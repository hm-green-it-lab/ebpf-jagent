#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <inttypes.h>
#include <getopt.h>

#include <curl/curl.h>
#include <bpf/libbpf.h>

#include "ebpf_jagent.skel.h"

#include "environment/env_loader.h"
#include "metrics/exporter/metrics_exporter.h"
#include "metrics/importer/process_cpu.h"
#include "model/event.h"

#define MAX_FILTER_LEN 64
#define DEFAULT_OUTPUT_FILE "method_trace.txt"

// simple logging helpers
#define LOG_INFO(fmt, ...)                                  \
    do                                                      \
    {                                                       \
        fprintf(stderr, "[INFO] " fmt "\n", ##__VA_ARGS__); \
    } while (0)
#define LOG_ERROR(fmt, ...)                                  \
    do                                                       \
    {                                                        \
        fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); \
    } while (0)

static volatile bool exiting = false;

// signal handler sets flag to break out of main loop
static void sig_handler(int sig)
{
    (void)sig;
    exiting = true;
}

// libbpf logging callback: forward to stderr
static int libbpf_print_fn(enum libbpf_print_level level,
                           const char *fmt, va_list args)
{
    (void)level;
    return vfprintf(stderr, fmt, args);
}

// initialize global CURL state used for OTLP exporter
static void init_otlp_http()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

// print usage/help message
static void print_usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s -p <java-pid> [-f <filter_substring>] [output_file] [--no-print]\n"
            "  -p, --pid <java-pid>        PID of Java process to trace (required)\n"
            "  -f, --filter <substring>    Optional substring to filter class/method names\n"
            "  output_file                Optional output file (default: %s)\n"
            "  --no-print                 Suppress startup banner/info prints\n"
            "  -h                         Show this help message and exit\n"
            "\n"
            "Note: JVM library path (libjvm.so) must be provided via JVM_LIB_PATH in .env. "
            "Program will not start without it.\n"
            "Use -h for options.\n",
            prog, DEFAULT_OUTPUT_FILE);
}

// core polling & processing loop: reads BPF maps, publishes metrics, writes events
static int run_tracing_loop(pid_t target_pid,
                            const char *filter,
                            struct ebpf_jagent_bpf *skel,
                            FILE *outf,
                            struct otlp_config *cfg,
                            const char *output_path,
                            bool no_print)
{
    struct bpf_map *map_cnt = skel->maps.event_cnt;
    struct bpf_map *map_ev = skel->maps.events_map;
    uint32_t event_cnt_key = 0;
    uint64_t last_id = 0;

    if (!no_print)
    {
        printf("\n\n === End of eBPF Logs === \n");
        printf("\n\n\n\n=============\n");
        printf("EBPF jAgent: Tracing pid %d. Filter `%s`. Output File: `%s` (ctrl-c to stop)\n", target_pid, filter, output_path);
        printf("=============\n");
    }

    while (!exiting)
    {
        uint64_t count = 0;

        uint64_t total_cpu_ns = 0;
        if (get_process_cpu_time_ns(target_pid, &total_cpu_ns) == 0)
        {
            publish_process_cpu(total_cpu_ns, cfg);
        }

        // lookup current event count; if successful, iterate new events
        if (bpf_map__lookup_elem(map_cnt, &event_cnt_key, sizeof(event_cnt_key),
                                 &count, sizeof(count), 0) == 0)
        {
            for (uint64_t id = last_id; id < count; id++)
            {
                struct event ev;
                if (bpf_map__lookup_elem(map_ev, &id, sizeof(id),
                                         &ev, sizeof(ev), 0) == 0)
                {
                    // write human-readable event summary
                    fprintf(outf,
                            "%s.%s — wall:%" PRIu64 " ns  cpu:%" PRIu64 " ns "
                            "tx:%" PRIu64 "  rx:%" PRIu64 "  io:%" PRIu64 "  alloc:%" PRIu64 "\n",
                            ev.class_name, ev.method_name,
                            ev.wdelta,
                            ev.cdelta,
                            ev.net_tx,
                            ev.net_rx,
                            ev.io,
                            ev.alloc);

                    publish_resource_demand_vector(&ev, cfg);

                    // remove processed event so map window can advance
                    bpf_map__delete_elem(map_ev, &id, sizeof(id), 0);
                }
            }
            last_id = count;
        }

        // responsive sleep: break into smaller chunks to respond quickly to SIGINT
        const int total_ms = 5000;
        const int step_ms = 200;
        int slept = 0;
        while (!exiting && slept < total_ms)
        {
            usleep(step_ms * 1000);
            slept += step_ms;
        }
    }

    return 0;
}

int main(int argc, char **argv)
{
    struct otlp_config cfg;
    int ret = 0;
    const char *filter = NULL;
    const char *output_path = DEFAULT_OUTPUT_FILE;
    bool no_print = false;
    pid_t target_pid = 0;

    // getopt_long setup: -p/--pid, -f/--filter, -h, --no-print
    static struct option long_opts[] = {
        {"pid", required_argument, NULL, 'p'},
        {"filter", required_argument, NULL, 'f'},
        {"no-print", no_argument, NULL, 0}, // handled via flag key 0
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0},
    };

    int opt;
    int long_index = 0;
    while ((opt = getopt_long(argc, argv, "p:f:h", long_opts, &long_index)) != -1)
    {
        switch (opt)
        {
        case 0:
            // long-only flags
            if (strcmp(long_opts[long_index].name, "no-print") == 0)
            {
                no_print = true;
            }
            break;
        case 'p':
        {
            // validate PID argument
            char *endptr = NULL;
            long pid_l = strtol(optarg, &endptr, 10);
            if (endptr == optarg || *endptr != '\0' || pid_l <= 0)
            {
                fprintf(stderr, "invalid java-pid: %s\n", optarg);
                return 1;
            }
            target_pid = (pid_t)pid_l;
            break;
        }
        case 'f':
            filter = optarg;
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            fprintf(stderr, "use -h for options.\n");
            return 1;
        }
    }

    // require PID
    if (target_pid == 0)
    {
        fprintf(stderr, "error: missing required -p/--pid argument; use -h for options.\n");
        return 1;
    }

    // positional leftover: [output_file]
    int remaining = argc - optind;
    if (remaining > 1)
    {
        fprintf(stderr, "use -h for options.\n");
        return 1;
    }
    if (remaining == 1)
    {
        output_path = argv[optind];
    }

    // load .env configuration (returns void)
    load_env_config(".env", &cfg);

    // ensure JVM_LIB_PATH is set in environment loaded from .env
    const char *jvm_lib_path = getenv("JVM_LIB_PATH");
    if (!jvm_lib_path || jvm_lib_path[0] == '\0')
    {
        LOG_ERROR("JVM_LIB_PATH not set in .env; cannot proceed");
        return 1;
    }

    struct ebpf_jagent_bpf *skel = NULL;
    FILE *outf = NULL;
    int err = 0;

    signal(SIGINT, sig_handler);
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    init_otlp_http();

    skel = ebpf_jagent_bpf__open();
    if (!skel)
    {
        LOG_ERROR("skeleton open failed");
        ret = 1;
        goto cleanup;
    }

    skel->rodata->target_pid = target_pid;

    // apply optional filter safely based on actual buffer size
    size_t buf_len = sizeof(skel->rodata->filter);
    if (filter)
    {
        size_t to_copy = strnlen(filter, (buf_len > 0 ? buf_len - 1 : 0));
        if (to_copy > 0)
        {
            memcpy((char *)skel->rodata->filter, filter, to_copy);
        }
        if (buf_len > 0)
            skel->rodata->filter[to_copy] = '\0';
    }
    else if (buf_len > 0)
    {
        skel->rodata->filter[0] = '\0';
    }

    err = ebpf_jagent_bpf__load(skel);
    if (err)
    {
        LOG_ERROR("load failed: %d", err);
        ret = 1;
        goto cleanup;
    }

    // attach required probes, abort if any attachment fails
    skel->links.method_entry =
        bpf_program__attach_usdt(skel->progs.method_entry, target_pid,
                                 jvm_lib_path,
                                 "hotspot", "method__entry", NULL);
    if (!skel->links.method_entry)
    {
        LOG_ERROR("failed to attach USDT method_entry");
        ret = 1;
        goto cleanup;
    }

    skel->links.method_return =
        bpf_program__attach_usdt(skel->progs.method_return, target_pid,
                                 jvm_lib_path,
                                 "hotspot", "method__return", NULL);
    if (!skel->links.method_return)
    {
        LOG_ERROR("failed to attach USDT method_return");
        ret = 1;
        goto cleanup;
    }

    skel->links.kprobe_sock_sendmsg =
    bpf_program__attach_kprobe(skel->progs.kprobe_sock_sendmsg, false, "sock_sendmsg");
    if (!skel->links.kprobe_sock_sendmsg)
    {
        LOG_ERROR("failed to attach tracepoint sock_sendmsg");
        ret = 1;
        goto cleanup;
    }

  skel->links.kretprobe_sock_recvmsg =
    bpf_program__attach_kprobe(skel->progs.kretprobe_sock_recvmsg, true, "sock_recvmsg");
 if (!skel->links.kretprobe_sock_recvmsg)
    {
        LOG_ERROR("failed to attach tracepoint sock_recvmsg");
        ret = 1;
        goto cleanup;
    }

    skel->links.trace_sys_enter_write =
        bpf_program__attach_tracepoint(skel->progs.trace_sys_enter_write, "syscalls", "sys_enter_write");
    if (!skel->links.trace_sys_enter_write)
    {
        LOG_ERROR("failed to attach tracepoint sys_enter_write");
        ret = 1;
        goto cleanup;
    }

    skel->links.object_alloc =
        bpf_program__attach_usdt(skel->progs.object_alloc, target_pid,
                                 jvm_lib_path,
                                 "hotspot", "object__alloc", NULL);
    if (!skel->links.object_alloc)
    {
        LOG_ERROR("failed to attach USDT object_alloc");
        ret = 1;
        goto cleanup;
    }

    outf = fopen(output_path, "w");
    if (!outf)
    {
        perror("fopen");
        ret = 1;
        goto cleanup;
    }
    setvbuf(outf, NULL, _IOLBF, 0); // line buffering so each event is flushed

    // run the main work loop (returns when exiting flag is set)
    run_tracing_loop(target_pid, filter, skel, outf, &cfg, output_path, no_print);

cleanup:
    ebpf_jagent_bpf__destroy(skel);
    if (outf)
        fclose(outf);
    curl_global_cleanup();
    free_all_metric_entries();
    free_env_config(&cfg);

    return ret < 0 ? -ret : ret;
}

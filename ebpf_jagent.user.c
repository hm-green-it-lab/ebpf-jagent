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
#include <errno.h>
#include <time.h>

#include <curl/curl.h>
#include <bpf/libbpf.h>

#include "ebpf_jagent.skel.h"

#include "environment/env_loader.h"
#include "metrics/exporter/metrics_exporter.h"
#include "metrics/importer/process_cpu.h"
#include "model/event.h"

#define MAX_FILTER_LEN 64
#define DEFAULT_OUTPUT_FILE "method_trace.txt"

// How long a ring-buffer poll waits before the loop checks the clock and the
// exit flag. Also bounds how quickly the agent reacts to SIGINT/SIGTERM.
#define POLL_TIMEOUT_MS 200

// How often process CPU is sampled and the queued datapoints are exported.
#define FLUSH_INTERVAL_MS 5000

// Flush early when a burst queues up between scheduled flushes, so a single
// OTLP request cannot grow unbounded.
#define MAX_PENDING_POINTS 2000

// Selectable resource dimensions.
//
// CPU and the transaction boundary both come from the method__entry/
// method__return USDT probes, so those are always attached; without them there
// is nothing to attribute anything to. Memory, network and storage each have
// their own probe and can be switched off, which matters when comparing
// against an agent that only collects a subset: probes that are attached cost
// their firing overhead whether or not the resulting values are used.
struct probe_selection
{
    bool memory;  // usdt object__alloc
    bool network; // kretprobe sock_sendmsg + kretprobe sock_recvmsg
    bool storage; // tracepoint sys_exit_write
};

// Parse a comma-separated dimension list such as "cpu,memory".
// Returns false on an unknown name.
static bool parse_probes(const char *spec, struct probe_selection *sel)
{
    if (strcmp(spec, "all") == 0)
    {
        sel->memory = sel->network = sel->storage = true;
        return true;
    }

    sel->memory = sel->network = sel->storage = false;

    char buffer[128];
    snprintf(buffer, sizeof(buffer), "%s", spec);

    for (char *token = strtok(buffer, ","); token; token = strtok(NULL, ","))
    {
        while (*token == ' ')
            token++;

        if (strcmp(token, "cpu") == 0)
            continue; // always on: it is the method probe itself
        else if (strcmp(token, "memory") == 0)
            sel->memory = true;
        else if (strcmp(token, "network") == 0)
            sel->network = true;
        else if (strcmp(token, "storage") == 0)
            sel->storage = true;
        else
        {
            fprintf(stderr, "unknown probe dimension: %s\n", token);
            return false;
        }
    }
    return true;
}

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
            "Usage: %s -p <java-pid> [-f <filter_substring>] [--probes <list>] [output_file] [--no-print]\n"
            "  -p, --pid <java-pid>        PID of Java process to trace (required)\n"
            "  -f, --filter <substring>    Optional substring to filter class/method names\n"
            "  --min-duration-us <n>      Only emit calls lasting at least n microseconds\n"
            "                              (default: 0, emit everything). Shorter calls are\n"
            "                              still measured and still propagate their resource\n"
            "                              use to the caller; they are just not reported.\n"
            "                              Raising this is the cheapest way to cut overhead\n"
            "                              on a method-heavy workload.\n"
            "  --probes <list>            Resource dimensions to collect, comma separated:\n"
            "                              cpu,memory,network,storage or all (default: all).\n"
            "                              cpu is always collected: it comes from the same\n"
            "                              method probes that delimit a transaction.\n"
            "                              Unselected dimensions are never attached, so their\n"
            "                              probes cost nothing.\n"
            "  output_file                Optional output file (default: %s).\n"
            "                              Use /dev/null to skip the per-transaction trace;\n"
            "                              the OTLP metrics carry the same values.\n"
            "  --no-print                 Suppress startup banner/info prints\n"
            "  -h                         Show this help message and exit\n"
            "\n"
            "Note: JVM library path (libjvm.so) must be provided via JVM_LIB_PATH in .env. "
            "Program will not start without it.\n"
            "Use -h for options.\n",
            prog, DEFAULT_OUTPUT_FILE);
}

// Context handed to the ring-buffer callback.
struct drain_ctx
{
    FILE *outf;
    struct otlp_config *cfg;
};

static uint64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

// Called once per event, directly on the ring buffer's memory.
//
// The kernel commits a record only once it is fully written, so a record is
// either visible and complete or not visible at all. That removes the
// reserved-but-unwritten gap the id-counter design had to wait out, along with
// the two syscalls per event needed to read and then delete each one.
static int handle_event(void *ctx, void *data, size_t size)
{
    struct drain_ctx *dc = ctx;
    const struct event *ev = data;

    if (size < sizeof(*ev))
    {
        LOG_ERROR("short event: %zu bytes, expected %zu", size, sizeof(*ev));
        return 0;
    }

    fprintf(dc->outf,
            "%s.%s — wall:%" PRIu64 " ns  cpu:%" PRIu64 " ns "
            "tx:%" PRIu64 "  rx:%" PRIu64 "  io:%" PRIu64 "  alloc:%" PRIu64 "\n",
            ev->class_name, ev->method_name,
            ev->wdelta, ev->cdelta, ev->net_tx, ev->net_rx, ev->io, ev->alloc);

    record_resource_demand(ev);

    // One request per batch rather than one per transaction: a per-event round
    // trip could not keep up with the service, so events piled up in the kernel
    // and were discarded. Flush early only when a burst would otherwise make a
    // single request unbounded.
    if (pending_resource_demand_count() >= MAX_PENDING_POINTS)
        flush_resource_demands(dc->cfg);

    return 0;
}

// core polling & processing loop: drains the ring buffer, publishes metrics
static int run_tracing_loop(pid_t target_pid,
                            const char *filter,
                            struct ebpf_jagent_bpf *skel,
                            FILE *outf,
                            struct otlp_config *cfg,
                            const char *output_path,
                            bool no_print)
{
    struct drain_ctx dc = {.outf = outf, .cfg = cfg};
    struct ring_buffer *rb = NULL;
    uint64_t last_flush_ms;
    int ret = 0;

    rb = ring_buffer__new(bpf_map__fd(skel->maps.events), handle_event, &dc, NULL);
    if (!rb)
    {
        LOG_ERROR("failed to create ring buffer");
        return -1;
    }

    if (!no_print)
    {
        printf("\n\n === End of eBPF Logs === \n");
        printf("\n\n\n\n=============\n");
        printf("EBPF jAgent: Tracing pid %d. Filter `%s`. Output File: `%s` (ctrl-c to stop)\n", target_pid, filter, output_path);
        printf("=============\n");
    }

    last_flush_ms = now_ms();

    while (!exiting)
    {
        int err = ring_buffer__poll(rb, POLL_TIMEOUT_MS);
        if (err < 0 && err != -EINTR)
        {
            LOG_ERROR("ring buffer poll failed: %d", err);
            ret = -1;
            break;
        }

        uint64_t now = now_ms();
        if (now - last_flush_ms >= FLUSH_INTERVAL_MS)
        {
            uint64_t total_cpu_ns = 0;
            if (get_process_cpu_time_ns(target_pid, &total_cpu_ns) == 0)
                publish_process_cpu(total_cpu_ns, cfg);

            flush_resource_demands(cfg);
            last_flush_ms = now;
        }
    }

    // Consume without polling: the signal arrives mid-interval, so whatever the
    // kernel committed since the last cycle would otherwise be dropped.
    ring_buffer__consume(rb);
    flush_resource_demands(cfg);
    ring_buffer__free(rb);

    return ret;
}

int main(int argc, char **argv)
{
    struct otlp_config cfg;
    int ret = 0;
    // Never NULL: it is printed in the startup banner.
    const char *filter = "";
    const char *output_path = DEFAULT_OUTPUT_FILE;
    bool no_print = false;
    pid_t target_pid = 0;
    uint64_t min_duration_ns = 0;
    // Default matches the historical behaviour: collect everything.
    struct probe_selection probes = {.memory = true, .network = true, .storage = true};

    // getopt_long setup: -p/--pid, -f/--filter, -h, --no-print
    static struct option long_opts[] = {
        {"pid", required_argument, NULL, 'p'},
        {"filter", required_argument, NULL, 'f'},
        {"no-print", no_argument, NULL, 0}, // handled via flag key 0
        {"probes", required_argument, NULL, 0},
        {"min-duration-us", required_argument, NULL, 0},
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
            else if (strcmp(long_opts[long_index].name, "probes") == 0)
            {
                if (!parse_probes(optarg, &probes))
                {
                    fprintf(stderr, "use -h for options.\n");
                    return 1;
                }
            }
            else if (strcmp(long_opts[long_index].name, "min-duration-us") == 0)
            {
                char *endptr = NULL;
                unsigned long long us = strtoull(optarg, &endptr, 10);
                if (endptr == optarg || *endptr != '\0')
                {
                    fprintf(stderr, "invalid min-duration-us: %s\n", optarg);
                    return 1;
                }
                min_duration_ns = (uint64_t)us * 1000u;
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
    // Without SIGTERM the container runtime kills the agent outright on
    // `docker stop`, losing every datapoint queued since the last flush.
    signal(SIGTERM, sig_handler);
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
    skel->rodata->min_duration_ns = min_duration_ns;

    // apply optional filter safely based on actual buffer size
    size_t buf_len = sizeof(skel->rodata->filter);
    size_t to_copy = strnlen(filter, buf_len - 1);
    if (strlen(filter) > to_copy)
        LOG_ERROR("filter truncated to %zu characters", to_copy);
    memcpy(skel->rodata->filter, filter, to_copy);
    skel->rodata->filter[to_copy] = '\0';
    // Precomputed so the BPF program does not rescan the filter on every return.
    skel->rodata->filter_len = (uint32_t)to_copy;

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

    // The network and storage probes hook kernel-wide functions, so unlike the
    // USDT probes they cannot be scoped to the target process. Leaving them
    // attached when their dimension is not collected would make every socket
    // operation and every write() on the machine trap for nothing.
    if (probes.network)
    {
        skel->links.kretprobe_sock_sendmsg =
            bpf_program__attach_kprobe(skel->progs.kretprobe_sock_sendmsg, true, "sock_sendmsg");
        if (!skel->links.kretprobe_sock_sendmsg)
        {
            LOG_ERROR("failed to attach kretprobe sock_sendmsg");
            ret = 1;
            goto cleanup;
        }

        skel->links.kretprobe_sock_recvmsg =
            bpf_program__attach_kprobe(skel->progs.kretprobe_sock_recvmsg, true, "sock_recvmsg");
        if (!skel->links.kretprobe_sock_recvmsg)
        {
            LOG_ERROR("failed to attach kretprobe sock_recvmsg");
            ret = 1;
            goto cleanup;
        }
    }

    if (probes.storage)
    {
        skel->links.trace_sys_exit_write =
            bpf_program__attach_tracepoint(skel->progs.trace_sys_exit_write, "syscalls", "sys_exit_write");
        if (!skel->links.trace_sys_exit_write)
        {
            LOG_ERROR("failed to attach tracepoint sys_exit_write");
            ret = 1;
            goto cleanup;
        }
    }

    if (probes.memory)
    {
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
    }

    if (!no_print)
    {
        LOG_INFO("collecting: cpu%s%s%s",
                 probes.memory ? ", memory" : "",
                 probes.network ? ", network" : "",
                 probes.storage ? ", storage" : "");
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
    // Before curl_global_cleanup(): this releases the reused easy handle.
    free_all_metric_entries();
    curl_global_cleanup();
    free_env_config(&cfg);

    return ret < 0 ? -ret : ret;
}

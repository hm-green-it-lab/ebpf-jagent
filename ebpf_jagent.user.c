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

// Drain cycles to wait for a reserved-but-unwritten event before giving up on
// it. One cycle is normally enough; the bound only exists so a genuinely lost
// event cannot stall the drain indefinitely.
#define MAX_STALL_CYCLES 3

// Grace period before the final drain, so events whose slot was reserved just
// as the interrupt arrived are written before the last read.
#define FINAL_DRAIN_SETTLE_MS 300

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
    bool network; // kprobe sock_sendmsg + kretprobe sock_recvmsg
    bool storage; // tracepoint sys_enter_write
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

// State carried between drain cycles.
struct drain_state
{
    struct bpf_map *map_cnt;
    struct bpf_map *map_ev;
    uint32_t cnt_key;
    uint64_t last_id;
    // An id whose slot is reserved but not yet readable, so the drain can wait
    // for it without blocking forever if it never appears.
    uint64_t stalled_id;
    unsigned stall_cycles;
    FILE *outf;
    struct otlp_config *cfg;
};

// Consume every event the kernel has published since the last call.
//
// Ids are reserved in order but written marginally later, so a gap means "not
// written yet", not "lost": the drain stops there and resumes on the next
// cycle. On the final pass no further writes are coming, so gaps are skipped
// rather than waited for.
//
// Returns the number of events consumed.
static uint64_t drain_events(struct drain_state *st, bool final_pass)
{
    uint64_t count = 0;
    uint64_t consumed = 0;

    if (bpf_map__lookup_elem(st->map_cnt, &st->cnt_key, sizeof(st->cnt_key),
                             &count, sizeof(count), 0) != 0)
        return 0;

    uint64_t id = st->last_id;
    while (id < count)
    {
        struct event ev;
        if (bpf_map__lookup_elem(st->map_ev, &id, sizeof(id), &ev, sizeof(ev), 0) != 0)
        {
            if (final_pass)
            {
                id++; // nothing more is coming; do not wait for it
                continue;
            }
            if (id == st->stalled_id && ++st->stall_cycles >= MAX_STALL_CYCLES)
            {
                LOG_ERROR("event %" PRIu64 " never materialised; skipping", id);
                st->stalled_id = UINT64_MAX;
                st->stall_cycles = 0;
                id++;
                continue;
            }
            if (id != st->stalled_id)
            {
                st->stalled_id = id;
                st->stall_cycles = 1;
            }
            break;
        }

        st->stalled_id = UINT64_MAX;
        st->stall_cycles = 0;

        fprintf(st->outf,
                "%s.%s — wall:%" PRIu64 " ns  cpu:%" PRIu64 " ns "
                "tx:%" PRIu64 "  rx:%" PRIu64 "  io:%" PRIu64 "  alloc:%" PRIu64 "\n",
                ev.class_name, ev.method_name,
                ev.wdelta, ev.cdelta, ev.net_tx, ev.net_rx, ev.io, ev.alloc);

        record_resource_demand(&ev);

        // remove processed event so map window can advance
        bpf_map__delete_elem(st->map_ev, &id, sizeof(id), 0);
        consumed++;
        id++;
    }

    // One request for the whole batch rather than one per transaction: the
    // per-event round trip could not keep up with the service, so events piled
    // up in the map and were discarded on shutdown.
    flush_resource_demands(st->cfg);

    // Resume from the first id not yet consumed, not from `count`.
    st->last_id = id;
    return consumed;
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
    struct drain_state st = {
        .map_cnt = skel->maps.event_cnt,
        .map_ev = skel->maps.events_map,
        .cnt_key = 0,
        .last_id = 0,
        .stalled_id = UINT64_MAX,
        .stall_cycles = 0,
        .outf = outf,
        .cfg = cfg,
    };

    if (!no_print)
    {
        printf("\n\n === End of eBPF Logs === \n");
        printf("\n\n\n\n=============\n");
        printf("EBPF jAgent: Tracing pid %d. Filter `%s`. Output File: `%s` (ctrl-c to stop)\n", target_pid, filter, output_path);
        printf("=============\n");
    }

    while (!exiting)
    {
        uint64_t total_cpu_ns = 0;
        if (get_process_cpu_time_ns(target_pid, &total_cpu_ns) == 0)
        {
            publish_process_cpu(total_cpu_ns, cfg);
        }

        drain_events(&st, false);

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

    // Final drain. The interrupt arrives between polls, so everything recorded
    // since the last cycle -- up to a full poll interval of transactions, plus
    // any export backlog -- would otherwise be discarded on shutdown. Settle
    // briefly first so events still in flight when the signal landed are
    // written before the last read.
    usleep(FINAL_DRAIN_SETTLE_MS * 1000);
    uint64_t remaining = drain_events(&st, true);
    if (remaining)
        LOG_INFO("drained %" PRIu64 " remaining event(s) on shutdown", remaining);

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
    // Default matches the historical behaviour: collect everything.
    struct probe_selection probes = {.memory = true, .network = true, .storage = true};

    // getopt_long setup: -p/--pid, -f/--filter, -h, --no-print
    static struct option long_opts[] = {
        {"pid", required_argument, NULL, 'p'},
        {"filter", required_argument, NULL, 'f'},
        {"no-print", no_argument, NULL, 0}, // handled via flag key 0
        {"probes", required_argument, NULL, 0},
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

    // The network and storage probes hook kernel-wide functions, so unlike the
    // USDT probes they cannot be scoped to the target process. Leaving them
    // attached when their dimension is not collected would make every socket
    // operation and every write() on the machine trap for nothing.
    if (probes.network)
    {
        skel->links.kprobe_sock_sendmsg =
            bpf_program__attach_kprobe(skel->progs.kprobe_sock_sendmsg, false, "sock_sendmsg");
        if (!skel->links.kprobe_sock_sendmsg)
        {
            LOG_ERROR("failed to attach kprobe sock_sendmsg");
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
        skel->links.trace_sys_enter_write =
            bpf_program__attach_tracepoint(skel->progs.trace_sys_enter_write, "syscalls", "sys_enter_write");
        if (!skel->links.trace_sys_enter_write)
        {
            LOG_ERROR("failed to attach tracepoint sys_enter_write");
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
    curl_global_cleanup();
    free_all_metric_entries();
    free_env_config(&cfg);

    return ret < 0 ? -ret : ret;
}

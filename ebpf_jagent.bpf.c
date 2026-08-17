#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

#define MAX_NAME_LEN 64
#define MAX_FILTER_LEN 64

// Frames deeper than this are still counted, so entry and return stay balanced,
// but they are not measured. Java stacks routinely nest far deeper than the
// frames anyone attributes resources to, and those deep frames dominate the
// probe firing count. Resources consumed below the cap roll up into the deepest
// tracked frame rather than being discarded -- see live_frame().
#define MAX_TRACE_DEPTH 32

// Power-of-two masks let the verifier prove every index stays in range.
#define NAME_MASK (MAX_NAME_LEN - 1)
#define FILTER_MASK (MAX_FILTER_LEN - 1)
#define DEPTH_MASK (MAX_TRACE_DEPTH - 1)

const volatile pid_t target_pid = 0;
// Precomputed by user space: rescanning filter on every return is pure waste.
const volatile __u32 filter_len = 0;
// Calls shorter than this are measured and propagated, but never emitted.
const volatile __u64 min_duration_ns = 0;
const volatile char filter[MAX_FILTER_LEN] = "";

// Per-call resource counters. One slot per stack frame.
struct frame
{
    __u64 wstart;
    __u64 cstart;
    __u64 net_tx;
    __u64 net_rx;
    __u64 io;
    __u64 alloc;
};

struct thread_state
{
    __u32 depth; // logical depth; may exceed MAX_TRACE_DEPTH
    struct frame frames[MAX_TRACE_DEPTH];
};

// Task-local storage rather than hash maps keyed by tid: it is a pointer chase
// off task_struct with no hashing and no bucket lock, and the kernel frees it
// when the thread exits -- so frames abandoned by a method__return that never
// fired (exception unwinding) cannot accumulate.
struct
{
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct thread_state);
} thread_states SEC(".maps");

// Event payload. Must match struct event in model/event.h.
struct event
{
    char class_name[MAX_NAME_LEN];
    char method_name[MAX_NAME_LEN];
    __u64 wdelta, cdelta, net_tx, net_rx, io, alloc;
    __u64 process_cpu_ns; // filled in by user space
};

// A ring buffer replaces the previous event-id counter plus hash map.
//
// That design had every CPU perform an atomic fetch-add on one shared counter
// value for every method return, so the counter's cache line ping-ponged
// between cores, and the map silently dropped events once full. Reserving the
// id non-atomically lost roughly a quarter of all events at 50 transactions/s;
// making it atomic fixed the loss but not the contention or the silent
// overflow. The ring buffer has neither: no shared counter, back-pressure
// instead of overwrites, a discard count when it does overflow, and user space
// drains it without a syscall per event.
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4 * 1024 * 1024);
} events SEC(".maps");

static __always_inline bool is_target(void)
{
    return (__u32)(bpf_get_current_pid_tgid() >> 32) == (__u32)target_pid;
}

// CPU time consumed by this task so far: the accounted total plus the slice it
// has been running since it was last scheduled in. exec_start lives in the
// sched_clock domain while bpf_ktime_get_ns() is CLOCK_MONOTONIC, so the two
// can disagree slightly; fall back to the accounted total rather than wrapping.
static __always_inline __u64 task_cpu_ns(struct task_struct *task, __u64 now)
{
    __u64 sum = BPF_CORE_READ(task, se.sum_exec_runtime);
    __u64 exec = BPF_CORE_READ(task, se.exec_start);

    return now > exec ? sum + (now - exec) : sum;
}

// The frame currently executing on this thread, for the resource probes.
// Returns NULL when this thread is not inside a traced method.
static __always_inline struct frame *live_frame(void)
{
    struct task_struct *task;
    struct thread_state *ts;
    __u32 d;

    if (!is_target())
        return NULL;

    task = bpf_get_current_task_btf();
    ts = bpf_task_storage_get(&thread_states, task, NULL, 0);
    if (!ts || ts->depth == 0)
        return NULL;

    d = ts->depth - 1;
    // Below the cap a call has no frame of its own, so attribute its resource
    // use to the deepest frame we do track instead of dropping it.
    if (d >= MAX_TRACE_DEPTH)
        d = MAX_TRACE_DEPTH - 1;

    return &ts->frames[d & DEPTH_MASK];
}

// Substring search over a name. Indices are masked rather than only compared,
// so the verifier can prove each access stays inside its buffer.
static __always_inline bool name_matches(const char *name, __u32 len)
{
    __u32 flen = filter_len;

    if (flen == 0)
        return true;
    if (flen > len)
        return false;

    for (__u32 i = 0; i + flen <= len && i < MAX_NAME_LEN; i++)
    {
        bool hit = true;

        for (__u32 j = 0; j < flen && j < MAX_FILTER_LEN; j++)
        {
            if (name[(i + j) & NAME_MASK] != filter[j & FILTER_MASK])
            {
                hit = false;
                break;
            }
        }
        if (hit)
            return true;
    }
    return false;
}

// Entry reads no USDT arguments and no strings at all: the class and method
// names are available again at return time, which is the only place they are
// used. This probe is half of all firings, so everything it does not do counts
// twice.
SEC("usdt/method_entry")
int method_entry(struct pt_regs *ctx)
{
    struct task_struct *task;
    struct thread_state *ts;
    struct frame *f;
    __u32 depth;
    __u64 now;

    if (!is_target())
        return 0;

    task = bpf_get_current_task_btf();
    ts = bpf_task_storage_get(&thread_states, task, NULL,
                              BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ts)
        return 0;

    depth = ts->depth;
    ts->depth = depth + 1;

    if (depth >= MAX_TRACE_DEPTH)
        return 0;

    f = &ts->frames[depth & DEPTH_MASK];
    now = bpf_ktime_get_ns();
    f->wstart = now;
    f->cstart = task_cpu_ns(task, now);
    f->net_tx = 0;
    f->net_rx = 0;
    f->io = 0;
    f->alloc = 0;

    return 0;
}

SEC("usdt/method_return")
int method_return(struct pt_regs *ctx)
{
    struct task_struct *task;
    struct thread_state *ts;
    struct frame *f;
    struct event ev = {};
    long cls_ptr, cls_len, mth_ptr, mth_len;
    __u32 depth, c1, c2;
    __u64 now, cpu_end;

    if (!is_target())
        return 0;

    task = bpf_get_current_task_btf();
    ts = bpf_task_storage_get(&thread_states, task, NULL, 0);
    if (!ts || ts->depth == 0)
        return 0;

    // Pop before anything that can fail: an early return that left the depth
    // skewed would make every later return on this thread pop the wrong frame.
    depth = ts->depth - 1;
    ts->depth = depth;

    if (depth >= MAX_TRACE_DEPTH)
        return 0;

    f = &ts->frames[depth & DEPTH_MASK];
    now = bpf_ktime_get_ns();
    ev.wdelta = now > f->wstart ? now - f->wstart : 0;
    ev.net_tx = f->net_tx;
    ev.net_rx = f->net_rx;
    ev.io = f->io;
    ev.alloc = f->alloc;

    // Propagate to the caller before any early exit: the parent's totals must
    // include this frame whether or not the event itself is emitted.
    if (depth > 0)
    {
        struct frame *pf = &ts->frames[(depth - 1) & DEPTH_MASK];

        pf->net_tx += ev.net_tx;
        pf->net_rx += ev.net_rx;
        pf->io += ev.io;
        pf->alloc += ev.alloc;
    }

    if (ev.wdelta < min_duration_ns)
        return 0;

    // Everything below runs only for events that can still be emitted, so the
    // four USDT argument reads, the two user-memory string reads and the
    // CPU-time reads are all skipped for calls dropped on duration.
    if (bpf_usdt_arg(ctx, 1, &cls_ptr) ||
        bpf_usdt_arg(ctx, 2, &cls_len) ||
        bpf_usdt_arg(ctx, 3, &mth_ptr) ||
        bpf_usdt_arg(ctx, 4, &mth_len))
        return 0;

    // Guard out negative or zero lengths, needed to ensure no crash.
    if (cls_len <= 0 || mth_len <= 0)
        return 0;

    c1 = cls_len < (MAX_NAME_LEN - 1) ? (__u32)cls_len : (MAX_NAME_LEN - 1);
    c2 = mth_len < (MAX_NAME_LEN - 1) ? (__u32)mth_len : (MAX_NAME_LEN - 1);

    // These are JVM pointers, so read them as user memory explicitly.
    if (bpf_probe_read_user_str(ev.class_name, c1 + 1, (void *)cls_ptr) < 0)
        return 0;
    if (bpf_probe_read_user_str(ev.method_name, c2 + 1, (void *)mth_ptr) < 0)
        return 0;

    if (!name_matches(ev.class_name, c1) && !name_matches(ev.method_name, c2))
        return 0;

    cpu_end = task_cpu_ns(task, now);
    ev.cdelta = cpu_end > f->cstart ? cpu_end - f->cstart : 0;
    // An unsigned subtraction that underflowed here would export ~1.8e19 ns.
    if (ev.cdelta > ev.wdelta)
        ev.cdelta = ev.wdelta;

    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);

    return 0;
}

// sock_sendmsg() has taken only (sock, msg) since Linux 4.2, so the third
// register held whatever happened to be in it rather than a length. The size
// has to come from the return value, which is the bytes actually sent anyway.
SEC("kretprobe/sock_sendmsg")
int BPF_KRETPROBE(kretprobe_sock_sendmsg, int ret)
{
    struct frame *f;

    if (ret <= 0)
        return 0;

    f = live_frame();
    if (f)
        f->net_tx += ret;

    return 0;
}

SEC("kretprobe/sock_recvmsg")
int BPF_KRETPROBE(kretprobe_sock_recvmsg, int ret)
{
    struct frame *f;

    if (ret <= 0)
        return 0;

    f = live_frame();
    if (f)
        f->net_rx += ret;

    return 0;
}

// sys_exit rather than sys_enter: the return value is the bytes actually
// written, where args[2] was only the count requested.
SEC("tracepoint/syscalls/sys_exit_write")
int trace_sys_exit_write(struct trace_event_raw_sys_exit *ctx)
{
    struct frame *f;
    long ret = ctx->ret;

    if (ret <= 0)
        return 0;

    f = live_frame();
    if (f)
        f->io += ret;

    return 0;
}

SEC("usdt/object_alloc")
int object_alloc(struct pt_regs *ctx)
{
    struct frame *f = live_frame();
    long size;

    // Resolve the frame first: when this thread is not inside a traced method
    // there is no reason to pay for the USDT argument read.
    if (!f)
        return 0;
    if (bpf_usdt_arg(ctx, 3, &size) || size <= 0)
        return 0;

    f->alloc += size;

    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

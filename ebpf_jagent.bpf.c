#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

const volatile pid_t target_pid = 0;
const volatile char filter[128] SEC(".rodata") = "";

#define MAX_ENTRIES 4096
#define MAX_NAME_LEN 64
#define FNV_OFFSET_32 2166136261u
#define FNV_PRIME_32 16777619u

// composite key: thread + method hash
struct key_t
{
    __u32 tid;
    __u32 hash;
};

// per-thread call-depth
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u32);
    __type(value, __u32);
} call_depth SEC(".maps");

// per-thread, per-depth method-hash stack
struct stack_key
{
    __u32 tid;
    __u32 depth;
};
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES * 4);
    __type(key, struct stack_key);
    __type(value, __u32);
} hash_stack SEC(".maps");

struct metrics
{
    __u64 wstart, cstart;
    __u64 net_tx, net_rx, io, alloc;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct key_t);
    __type(value, struct metrics);
} metrics_map SEC(".maps");

// single counter for event IDs
struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} event_cnt SEC(".maps");

// event payload
struct event
{
    char class_name[MAX_NAME_LEN];
    char method_name[MAX_NAME_LEN];
    __u64 wdelta, cdelta, net_tx, net_rx, io, alloc;
    uint64_t process_cpu_ns;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES * 10);
    __type(key, __u64);
    __type(value, struct event);
} events_map SEC(".maps");

static __always_inline __u32 fnv1a_hash(const char *buf, __u32 len)
{
    __u32 h = FNV_OFFSET_32;
    for (int i = 0; i < MAX_NAME_LEN && (u32)i < len; i++)
    {
        h ^= buf[i];
        h *= FNV_PRIME_32;
    }
    return h;
}

// Publish one completed method invocation to user space.
//
// The slot is reserved *before* the event is written. Reading the counter,
// writing at that key and then incrementing -- the previous order -- is not
// atomic as a whole: two threads returning from an instrumented method
// concurrently would read the same id, both write that key (one silently
// overwriting the other) and then both increment, consuming two ids for one
// stored event. That loses the overwritten event and leaves a hole at the
// skipped key. The loss scales with concurrency; at 50 transactions/s roughly
// a quarter of all events disappeared this way.
//
// __sync_fetch_and_add returns the value from before the addition, so every
// caller gets a distinct id. It compiles to a BPF atomic fetch-add, which
// needs a kernel >= 5.12.
static __always_inline void push_event(const struct event *ev)
{
    __u32 zero = 0;
    __u64 *counter = bpf_map_lookup_elem(&event_cnt, &zero);
    if (!counter)
        return;

    __u64 id = __sync_fetch_and_add(counter, 1);
    bpf_map_update_elem(&events_map, &id, ev, BPF_ANY);
}

SEC("usdt/method_entry")
int method_entry(struct pt_regs *ctx)
{
    long cls_ptr, cls_len, mth_ptr, mth_len;
    if (bpf_usdt_arg(ctx, 1, &cls_ptr) ||
        bpf_usdt_arg(ctx, 2, &cls_len) ||
        bpf_usdt_arg(ctx, 3, &mth_ptr) ||
        bpf_usdt_arg(ctx, 4, &mth_len))
        return 0;
    if (cls_len <= 0 || mth_len <= 0)
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();

    // bump depth
    __u32 depth = 0, *dp = bpf_map_lookup_elem(&call_depth, &tid);
    if (dp)
        depth = *dp;

    // clamp & read method name
    __u32 mlen = mth_len < (MAX_NAME_LEN - 1) ? (u32)mth_len : (MAX_NAME_LEN - 1);
    char mname[MAX_NAME_LEN];
    bpf_probe_read_str(mname, mlen + 1, (void *)mth_ptr);

    // compute hash & push to stack
    __u32 hash = fnv1a_hash(mname, mlen);

    struct stack_key sk = {.tid = tid, .depth = depth};
    bpf_map_update_elem(&hash_stack, &sk, &hash, BPF_ANY);

    // update depth
    depth++;
    bpf_map_update_elem(&call_depth, &tid, &depth, BPF_ANY);

    // init metrics
    struct key_t key = {.tid = tid, .hash = hash};
    struct metrics init = {};
    init.wstart = bpf_ktime_get_ns();
    {
        struct task_struct *task = (void *)bpf_get_current_task();
        __u64 sum = BPF_CORE_READ(task, se.sum_exec_runtime);
        __u64 exec = BPF_CORE_READ(task, se.exec_start);
        __u64 now2 = bpf_ktime_get_ns();
        init.cstart = sum + (now2 - exec);
    }
   
    bpf_map_update_elem(&metrics_map, &key, &init, BPF_NOEXIST);

    return 0;
}

SEC("usdt/method_return")
int method_return(struct pt_regs *ctx)
{
    long cls_ptr, cls_len, mth_ptr, mth_len;
    if (bpf_usdt_arg(ctx, 1, &cls_ptr) ||
        bpf_usdt_arg(ctx, 2, &cls_len) ||
        bpf_usdt_arg(ctx, 3, &mth_ptr) ||
        bpf_usdt_arg(ctx, 4, &mth_len))
        return 0;

    // guard out negative or zero lengths, needed to ensure no crash
    if (cls_len <= 0 || mth_len <= 0)
        return 0;

    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 *dp = bpf_map_lookup_elem(&call_depth, &tid);
    if (!dp || *dp == 0)
        return 0;
    __u32 depth = *dp - 1;

    struct stack_key sk = {.tid = tid, .depth = depth};
    __u32 *ph = bpf_map_lookup_elem(&hash_stack, &sk);
    if (!ph)
        return 0;
    __u32 hash = *ph;

    struct key_t key = {.tid = tid, .hash = hash};

    // clamp class/method lengths
    __u32 c1 = cls_len < (MAX_NAME_LEN - 1) ? (u32)cls_len : (MAX_NAME_LEN - 1);
    __u32 c2 = mth_len < (MAX_NAME_LEN - 1) ? (u32)mth_len : (MAX_NAME_LEN - 1);

    struct event ev = {};

    // read class_name with an explicit clamp
    __u32 class_size = c1 + 1;
    if (class_size > MAX_NAME_LEN)
        class_size = MAX_NAME_LEN;
    bpf_probe_read_str(ev.class_name, class_size, (void *)cls_ptr);

    // read method_name with an explicit clamp
    __u32 method_size = c2 + 1;
    if (method_size > MAX_NAME_LEN)
        method_size = MAX_NAME_LEN;
    bpf_probe_read_str(ev.method_name, method_size, (void *)mth_ptr);

    // lookup & compute metrics
    struct metrics *m = bpf_map_lookup_elem(&metrics_map, &key);
    if (m)
    {
        __u64 now = bpf_ktime_get_ns();
        ev.wdelta = now - m->wstart;
        {
            struct task_struct *task = (void *)bpf_get_current_task();
            __u64 sum2 = BPF_CORE_READ(task, se.sum_exec_runtime);
            __u64 exec2 = BPF_CORE_READ(task, se.exec_start);
            __u64 cpu_end = sum2 + (now - exec2);
            ev.cdelta = cpu_end - m->cstart;
        }
        ev.net_tx = m->net_tx;
        ev.net_rx = m->net_rx;
        ev.io = m->io;
        ev.alloc = m->alloc;

        if(m->alloc > 100)
        bpf_printk("Found mem! %s: %d, tid %d\n", ev.class_name, ev.method_name, depth, tid);
        if(m->net_tx > 0)
        bpf_printk("Found TX! %s: %d, tid %d\n", ev.class_name, ev.method_name, depth, tid);
        // propagate to parent
        if (depth > 0)
        {
            struct stack_key psk = {
                .tid = tid,
                .depth = depth - 1,
            };
            __u32 *ph_parent = bpf_map_lookup_elem(&hash_stack, &psk);
            if (ph_parent)
            {
                struct key_t parent_key = {
                    .tid = tid,
                    .hash = *ph_parent,
                };
                struct metrics *pm = bpf_map_lookup_elem(&metrics_map, &parent_key);
                if (pm)
                {
                    pm->net_tx += ev.net_tx;
                    pm->net_rx += ev.net_rx;
                    pm->io += ev.io;
                    pm->alloc += ev.alloc;
                }
            }
        }
    }

    // filtering for class or method name
    __u32 flen = 0;
#pragma unroll
    for (int i = 0; i < MAX_NAME_LEN; i++)
    {
        if (filter[i] == '\0')
            break;
        flen++;
    }
    if (flen)
    {
        bool found = false;
#pragma unroll
        for (u32 i = 0; i + flen <= c1; i++)
        {
#pragma unroll
            for (u32 j = 0; j < flen; j++)
            {
                if (ev.class_name[i + j] != filter[j])
                    break;
                if (j == flen - 1)
                    found = true;
            }
            if (found)
                break;
        }
        if (!found)
        {
#pragma unroll
            for (u32 i = 0; i + flen <= c2; i++)
            {
#pragma unroll
                for (u32 j = 0; j < flen; j++)
                {
                    if (ev.method_name[i + j] != filter[j])
                        break;
                    if (j == flen - 1)
                        found = true;
                }
                if (found)
                    break;
            }
        }
        if (!found)
            goto cleanup;
    }

    // emit event
    push_event(&ev);

cleanup:
    // cleanup maps / stack / depth
    bpf_map_delete_elem(&metrics_map, &key);
    bpf_map_delete_elem(&hash_stack, &sk);
    if (depth)
    {
        bpf_map_update_elem(&call_depth, &tid, &depth, BPF_ANY);
    }
    else
    {
        bpf_map_delete_elem(&call_depth, &tid);
    }
    return 0;
}

SEC("kprobe/sock_sendmsg")
int kprobe_sock_sendmsg(struct pt_regs *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 *dp = bpf_map_lookup_elem(&call_depth, &tid);
    if (!dp || *dp == 0)
        return 0;
    __u32 depth = *dp - 1;
    struct stack_key sk = {.tid = tid, .depth = depth};
    __u32 *ph = bpf_map_lookup_elem(&hash_stack, &sk);
    if (!ph)
        return 0;
    struct key_t key = {.tid = tid, .hash = *ph};

    size_t sz = PT_REGS_PARM3(ctx);
    struct metrics *m = bpf_map_lookup_elem(&metrics_map, &key);
    if (m)
        m->net_tx += sz;
    return 0;
}

SEC("kretprobe/sock_recvmsg")
int kretprobe_sock_recvmsg(struct pt_regs *ctx)
{
    int ret = (int)PT_REGS_RC(ctx);
    if (ret <= 0)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 *dp = bpf_map_lookup_elem(&call_depth, &tid);
    if (!dp || *dp == 0)
        return 0;
    __u32 depth = *dp - 1;
    struct stack_key sk = {.tid = tid, .depth = depth};
    __u32 *ph = bpf_map_lookup_elem(&hash_stack, &sk);
    if (!ph)
        return 0;
    struct key_t key = {.tid = tid, .hash = *ph};

    struct metrics *m = bpf_map_lookup_elem(&metrics_map, &key);
    if (m)
        m->net_rx += ret;
    return 0;
}


SEC("tracepoint/syscalls/sys_enter_write")
int trace_sys_enter_write(struct trace_event_raw_sys_enter *ctx)
{
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 *dp = bpf_map_lookup_elem(&call_depth, &tid);
    if (!dp || *dp == 0)
        return 0;
    __u32 depth = *dp - 1;
    struct stack_key sk = {.tid = tid, .depth = depth};
    __u32 *ph = bpf_map_lookup_elem(&hash_stack, &sk);
    if (!ph)
        return 0;
    struct key_t key = {.tid = tid, .hash = *ph};

    size_t cnt = ctx->args[2];
    struct metrics *m = bpf_map_lookup_elem(&metrics_map, &key);
    if (m)
        m->io += cnt;
    return 0;
}

SEC("usdt/object_alloc")
int object_alloc(struct pt_regs *ctx)
{
    long size = 0;
    if (bpf_usdt_arg(ctx, 3, &size) || size <= 0)
        return 0;
    __u32 tid = (__u32)bpf_get_current_pid_tgid();
    __u32 *dp = bpf_map_lookup_elem(&call_depth, &tid);
    if (!dp || *dp == 0)
        return 0;
    __u32 depth = *dp - 1;
    struct stack_key sk = {.tid = tid, .depth = depth};
    __u32 *ph = bpf_map_lookup_elem(&hash_stack, &sk);
    if (!ph)
        return 0;
    struct key_t key = {.tid = tid, .hash = *ph};

    struct metrics *m = bpf_map_lookup_elem(&metrics_map, &key);
    if (m)
        m->alloc += size;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
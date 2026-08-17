#ifndef EVENT_H
#define EVENT_H

#include <stdint.h>

/* must match the struct definition in the BPF program */
struct event {
    char     class_name[64];
    char     method_name[64];
    uint64_t wdelta;
    uint64_t cdelta;
    uint64_t net_tx;
    uint64_t net_rx;
    uint64_t io;
    uint64_t alloc;
    double process_cpu_ms; // doesnt need to match as it is not part of ebpfs event
};

#endif // EVENT_H

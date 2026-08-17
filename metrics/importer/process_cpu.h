#ifndef PROCESS_CPU_SIMPLE_H
#define PROCESS_CPU_SIMPLE_H

#include <stdint.h>
#include <sys/types.h>

/**
 * Get total CPU time (user + system across all threads) for the given process ID,
 * in ns. On success returns 0 and sets ms on failure returns -1.
 */
int get_process_cpu_time_ns(pid_t pid, uint64_t *out_ns);

#endif // PROCESS_CPU_SIMPLE_H

#ifndef METRICS_EXPORTER_H
#define METRICS_EXPORTER_H

#include <stdint.h>
#include <stdbool.h>
#include "model/event.h"
#include "environment/env_loader.h"

struct event;

/**
 * This updates (or creates) the metric entry for the given class+method in \p event,
 * accumulates CPU, I/O, memory, and network deltas, and sends a JSON payload
 * containing those per-method/resource metrics to the OTLP endpoint specified in the .env file.
 *
 * @param event Pointer to the event containing class_name, method_name, deltas, and process CPU.
 * Must not be NULL and must have valid class_name and method_name.
 * @param cfg   Pointer to a populated OTLP configuration (endpoint, auth, TLS, timeouts).
 * Must not be NULL. This function does not take ownership; caller retains ownership.
 */
void publish_resource_demand_vector(const struct event *event, const struct otlp_config *cfg);

/**
 * Sends a JSON payload containing the aggregate process CPU time (job-scoped) without
 * including per-method/resource breakdown. This function takes the raw CPU time in nanoseconds.
 *
 * @param process_cpu_ns Total process CPU time in **nanoseconds** (user + system across threads).
 * @param cfg            Pointer to a populated OTLP configuration (endpoint, auth, TLS, timeouts).
 *                       Must not be NULL. Caller retains ownership.
 */
void publish_process_cpu(uint64_t process_cpu_ns, const struct otlp_config *cfg);

/**
 * Should be called during shutdown to avoid leaking the linked list of metric_entry objects
 * that were created via send_otlp_metrics_without_process_cpu / publish_process_cpu.
 * After this call, internal state is reset and metrics will be re-created if new events arrive.
 */
void free_all_metric_entries(void);


#endif

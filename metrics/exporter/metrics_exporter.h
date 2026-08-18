#ifndef METRICS_EXPORTER_H
#define METRICS_EXPORTER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "model/event.h"
#include "environment/env_loader.h"

struct event;

/**
 * Restricts which resource dimensions are exported, to match the probes that
 * were actually attached.
 *
 * Without this the exporter emits all four series unconditionally, so a run
 * started with --probes cpu,memory publishes network and storage series that
 * are flat zero for their whole length. A consumer cannot tell that apart from
 * a genuine measurement of zero traffic, which is the more dangerous reading:
 * it looks like evidence that the transaction performed no I/O rather than an
 * absence of evidence. Publishing only what was measured makes the payload
 * self-describing.
 *
 * CPU is always exported: it comes from the method__entry/method__return probes
 * that delimit a transaction, so it cannot be switched off while anything is
 * being measured at all.
 *
 * Call once at start-up, before the first flush. Defaults to publishing
 * everything, which is what an agent started without --probes does.
 *
 * @param memory  Export ebpf.jagent.resource.demand.memory.bytes  (usdt object__alloc)
 * @param network Export ebpf.jagent.resource.demand.network.bytes (kretprobe sock_send/recvmsg)
 * @param storage Export ebpf.jagent.resource.demand.storage.bytes (tracepoint sys_exit_write)
 */
void configure_published_dimensions(bool memory, bool network, bool storage);

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
 * Accumulates one event into its class+method metric entry and queues a
 * datapoint for the next flush, without performing any network I/O.
 *
 * One datapoint is queued per event on purpose: differencing consecutive
 * datapoints is what recovers per-transaction demand, so a batch must not be
 * collapsed into a single value.
 *
 * @param event Pointer to the event. Must not be NULL.
 */
void record_resource_demand(const struct event *event);

/**
 * Sends every datapoint queued by record_resource_demand() as a single OTLP
 * request, then clears the queue. Sending one request per event instead makes
 * the drain loop wait on a full HTTP round trip per transaction, which cannot
 * keep up with a busy service and causes events to be discarded at shutdown.
 *
 * @param cfg Pointer to a populated OTLP configuration. Must not be NULL.
 */
void flush_resource_demands(const struct otlp_config *cfg);

/**
 * Number of datapoints queued by record_resource_demand() since the last flush.
 *
 * Lets the caller bound the size of a single OTLP request by flushing early
 * when a burst of events queues up between scheduled flushes.
 */
size_t pending_resource_demand_count(void);

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

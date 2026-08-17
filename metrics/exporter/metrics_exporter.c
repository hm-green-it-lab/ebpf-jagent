#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <curl/curl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <inttypes.h>

#include "metrics_exporter.h"

// error logging
#define ERROR(fmt, ...) \
    do { fprintf(stderr, "[ERROR] " fmt "\n", ##__VA_ARGS__); } while (0)

// JSON builder type
typedef struct {
    char *buffer;
    size_t length;
    size_t capacity;
} json_builder_t;

// metric entry linked list
typedef struct metric_entry {
    char *class_name;
    char *method_name;
    uint64_t cpu_ns;
    uint64_t io_bytes;
    uint64_t memory_bytes;
    uint64_t network_bytes;
    uint64_t start_time_ns;
    struct metric_entry *next;
} metric_entry_t;

// forward declarations
static bool json_builder_init(json_builder_t *jb, size_t initial_capacity);
static void json_builder_free(json_builder_t *jb);
static bool json_builder_reserve(json_builder_t *jb, size_t additional_needed);
static bool json_builder_appendf(json_builder_t *jb, const char *fmt, ...);
static bool json_builder_escape_and_append(json_builder_t *jb, const char *s);
static bool build_attributes_json(json_builder_t *jb, const char *class_name, const char *method_name);
static bool append_otlp_sum_metric(json_builder_t *jb, const char *name, const char *value_str,
                                   const char *attributes_json, uint64_t start_time_ns, uint64_t current_time_ns);
static void send_otlp_payload(const struct otlp_config *cfg, const char *json_payload);
static size_t _curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata);

// global head of metrics list
static metric_entry_t *g_metrics_head = NULL;

// safe strdup equivalent
static char *safe_strdup(const char *src)
{
    if (!src)
        return NULL;
    size_t len = strlen(src);
    char *dst = malloc(len + 1);
    if (dst)
        memcpy(dst, src, len + 1);
    return dst;
}

// current time in nanoseconds
static uint64_t get_current_time_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

// find or create metric entry
static metric_entry_t *find_or_create_metric(const char *class_name, const char *method_name)
{
    for (metric_entry_t *entry = g_metrics_head; entry; entry = entry->next)
    {
        if (strcmp(entry->class_name, class_name) == 0 &&
            strcmp(entry->method_name, method_name) == 0)
        {
            return entry;
        }
    }

    metric_entry_t *new_entry = calloc(1, sizeof(*new_entry));
    if (!new_entry)
        return NULL;

    new_entry->class_name = safe_strdup(class_name);
    new_entry->method_name = safe_strdup(method_name);
    new_entry->start_time_ns = get_current_time_ns();

    if (!new_entry->class_name || !new_entry->method_name || new_entry->start_time_ns == 0)
    {
        free(new_entry->class_name);
        free(new_entry->method_name);
        free(new_entry);
        return NULL;
    }

    new_entry->next = g_metrics_head;
    g_metrics_head = new_entry;
    return new_entry;
}

// free all metric entries
void free_all_metric_entries(void)
{
    metric_entry_t *current = g_metrics_head;
    while (current)
    {
        metric_entry_t *next = current->next;
        free(current->class_name);
        free(current->method_name);
        free(current);
        current = next;
    }
    g_metrics_head = NULL;
}

// JSON builder initialization
static bool json_builder_init(json_builder_t *jb, size_t initial_capacity)
{
    jb->capacity = initial_capacity > 0 ? initial_capacity : 2048;
    jb->length = 0;
    jb->buffer = malloc(jb->capacity);
    if (!jb->buffer)
        return false;
    jb->buffer[0] = '\0';
    return true;
}

// free builder
static void json_builder_free(json_builder_t *jb)
{
    free(jb->buffer);
    jb->buffer = NULL;
    jb->length = jb->capacity = 0;
}

// ensure capacity
static bool json_builder_reserve(json_builder_t *jb, size_t additional_needed)
{
    if (jb->length + additional_needed + 1 <= jb->capacity)
        return true;
    size_t new_capacity = jb->capacity;
    while (new_capacity < jb->length + additional_needed + 1)
        new_capacity *= 2;
    char *resized = realloc(jb->buffer, new_capacity);
    if (!resized)
        return false;
    jb->buffer = resized;
    jb->capacity = new_capacity;
    return true;
}

// append formatted data
static bool json_builder_appendf(json_builder_t *jb, const char *fmt, ...)
{
    va_list args1, args2;
    va_start(args1, fmt);
    va_copy(args2, args1);
    int needed = vsnprintf(NULL, 0, fmt, args1);
    va_end(args1);
    if (needed < 0)
    {
        va_end(args2);
        return false;
    }
    if (!json_builder_reserve(jb, (size_t)needed))
    {
        va_end(args2);
        return false;
    }
    vsnprintf(jb->buffer + jb->length, needed + 1, fmt, args2);
    jb->length += needed;
    va_end(args2);
    return true;
}

// escape string for JSON
static bool json_builder_escape_and_append(json_builder_t *jb, const char *s)
{
    if (!s)
        return json_builder_appendf(jb, "");

    for (const unsigned char *p = (const unsigned char *)s; *p; ++p)
    {
        switch (*p)
        {
        case '\"':
            if (!json_builder_appendf(jb, "\\\"")) return false;
            break;
        case '\\':
            if (!json_builder_appendf(jb, "\\\\")) return false;
            break;
        case '\b':
            if (!json_builder_appendf(jb, "\\b")) return false;
            break;
        case '\f':
            if (!json_builder_appendf(jb, "\\f")) return false;
            break;
        case '\n':
            if (!json_builder_appendf(jb, "\\n")) return false;
            break;
        case '\r':
            if (!json_builder_appendf(jb, "\\r")) return false;
            break;
        case '\t':
            if (!json_builder_appendf(jb, "\\t")) return false;
            break;
        default:
            if (*p < 0x20)
            {
                if (!json_builder_appendf(jb, "\\u%04x", *p)) return false;
            }
            else
            {
                if (!json_builder_appendf(jb, "%c", *p)) return false;
            }
        }
    }
    return true;
}

// build attributes array including job and optional class/method
static bool build_attributes_json(json_builder_t *jb, const char *class_name, const char *method_name)
{
    if (!json_builder_appendf(jb, "[")) return false;

    bool first = true;
    if (class_name)
    {
        if (!first && !json_builder_appendf(jb, ",")) return false;
        if (!json_builder_appendf(jb, "{\"key\":\"class.name\",\"value\":{\"stringValue\":\"")) return false;
        if (!json_builder_escape_and_append(jb, class_name)) return false;
        if (!json_builder_appendf(jb, "\"}}")) return false;
        first = false;
    }
    if (method_name)
    {
        if (!first && !json_builder_appendf(jb, ",")) return false;
        if (!json_builder_appendf(jb, "{\"key\":\"method.name\",\"value\":{\"stringValue\":\"")) return false;
        if (!json_builder_escape_and_append(jb, method_name)) return false;
        if (!json_builder_appendf(jb, "\"}}")) return false;
        first = false;
    }
    if (!first && !json_builder_appendf(jb, ",")) return false;
    if (!json_builder_appendf(jb, "{\"key\":\"job\",\"value\":{\"stringValue\":\"spring-app\"}}")) return false;

    if (!json_builder_appendf(jb, "]")) return false;
    return true;
}

// append sum metric
static bool append_otlp_sum_metric(json_builder_t *jb, const char *name, const char *value_str,
                                   const char *attributes_json, uint64_t start_time_ns, uint64_t current_time_ns)
{
    return json_builder_appendf(
        jb,
        "{"
        "\"name\":\"%s\","
        "\"sum\":{"
        "\"dataPoints\":[{"
        "\"attributes\":%s,"
        "\"asDouble\":%s,"
        "\"startTimeUnixNano\":\"%llu\","
        "\"timeUnixNano\":\"%llu\""
        "}],"
        "\"aggregationTemporality\":\"AGGREGATION_TEMPORALITY_CUMULATIVE\","
        "\"isMonotonic\":true"
        "}"
        "}",
        name, attributes_json, value_str,
        (unsigned long long)start_time_ns,
        (unsigned long long)current_time_ns);
}

// curl write callback for capturing response body
static size_t _curl_write_cb(char *ptr, size_t size, size_t nmemb, void *userdata)
{
    size_t total = size * nmemb;
    struct { char *buf; size_t len; size_t cap; } *resp = userdata;

    if (resp->len + total + 1 > resp->cap)
    {
        size_t newcap = resp->cap * 2;
        while (newcap < resp->len + total + 1)
            newcap *= 2;
        char *r = realloc(resp->buf, newcap);
        if (!r)
            return 0;
        resp->buf = r;
        resp->cap = newcap;
    }
    memcpy(resp->buf + resp->len, ptr, total);
    resp->len += total;
    resp->buf[resp->len] = '\0';
    return total;
}

// send JSON payload; only log on failure (curl error or non-2xx status)
static void send_otlp_payload(const struct otlp_config *cfg, const char *json_payload)
{
    if (!cfg || !cfg->endpoint || !json_payload)
        return;

    CURL *curl = curl_easy_init();
    if (!curl)
        return;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    if (cfg->bearer_token && cfg->bearer_token[0])
    {
        char auth_header[1024];
        snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", cfg->bearer_token);
        headers = curl_slist_append(headers, auth_header);
    }

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, cfg->endpoint);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 0L); // still want to inspect non-2xx

    if (cfg->insecure)
    {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    if (cfg->ca_cert)
        curl_easy_setopt(curl, CURLOPT_CAINFO, cfg->ca_cert);
    if (cfg->client_cert)
        curl_easy_setopt(curl, CURLOPT_SSLCERT, cfg->client_cert);
    if (cfg->client_key)
        curl_easy_setopt(curl, CURLOPT_SSLKEY, cfg->client_key);
    if (cfg->connect_timeout_secs > 0)
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, cfg->connect_timeout_secs);
    if (cfg->timeout_secs > 0)
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, cfg->timeout_secs);

    // prepare response capture
    struct {
        char *buf;
        size_t len;
        size_t cap;
    } resp = {NULL, 0, 1024};
    resp.buf = malloc(resp.cap);
    if (!resp.buf)
    {
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return;
    }
    resp.buf[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, _curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &resp);

    CURLcode res = curl_easy_perform(curl);
    long status = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status);

    if (res != CURLE_OK)
    {
        ERROR("OTLP export failed: %s", curl_easy_strerror(res));
    }
    else if (status < 200 || status >= 300)
    {
        ERROR("OTLP export HTTP %ld; body: %s", status, resp.buf);
    }

    free(resp.buf);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
}

// publish resource demand metrics for an event
void publish_resource_demand_vector(const struct event *event, const struct otlp_config *cfg)
{
    metric_entry_t *metric = find_or_create_metric(event->class_name, event->method_name);
    if (!metric)
        return;

    // accumulate metrics
    metric->cpu_ns += event->cdelta;
    metric->io_bytes += event->io;
    metric->memory_bytes += event->alloc;
    metric->network_bytes += event->net_tx + event->net_rx;

    uint64_t now_ns = get_current_time_ns();

    json_builder_t jb, jb_attr;
    if (!json_builder_init(&jb, 4096) || !json_builder_init(&jb_attr, 256))
    {
        ERROR("Failed to initialize JSON builder.");
        return;
    }

    if (!build_attributes_json(&jb_attr, event->class_name, event->method_name))
    {
        ERROR("Failed to build attributes JSON.");
        goto cleanup;
    }

    // start payload with required scope field
    json_builder_appendf(&jb,
                         "{"
                         "\"resourceMetrics\":[{"
                         "\"resource\":{\"attributes\":%s},"
                         "\"scopeMetrics\":[{"
                         "\"scope\":{},"
                         "\"metrics\":[",
                         jb_attr.buffer);

    const char *metric_names[] = {
        "ebpf.jagent.resource.demand.storage.bytes",
        "ebpf.jagent.resource.demand.memory.bytes",
        "ebpf.jagent.resource.demand.network.bytes",
        "ebpf.jagent.resource.demand.cpu.ms"};
    double metric_values[] = {
        (double)metric->io_bytes,
        (double)metric->memory_bytes,
        (double)metric->network_bytes,
        (double)metric->cpu_ns / 1e6};
    const char *metric_formats[] = {"%.0f", "%.0f", "%.0f", "%.3f"};

    for (int i = 0; i < 4; ++i)
    {
        char value_buf[64];
        snprintf(value_buf, sizeof(value_buf), metric_formats[i], metric_values[i]);

        if (!append_otlp_sum_metric(&jb, metric_names[i], value_buf, jb_attr.buffer, metric->start_time_ns, now_ns))
        {
            ERROR("Failed to append metric %s", metric_names[i]);
        }
        if (i < 3)
            json_builder_appendf(&jb, ",");
    }

    // close JSON
    json_builder_appendf(&jb, "]}]}]}");

    send_otlp_payload(cfg, jb.buffer);

cleanup:
    json_builder_free(&jb);
    json_builder_free(&jb_attr);
}

// publish process CPU usage metric
void publish_process_cpu(uint64_t process_cpu_ns, const struct otlp_config *cfg)
{
    if (!cfg)
        return;

    static uint64_t start_time_ns = 0;
    if (start_time_ns == 0)
        start_time_ns = get_current_time_ns();

    uint64_t now_ns = get_current_time_ns();
    double process_cpu_ms = (double)process_cpu_ns / 1e6;

    json_builder_t jb, jb_attr;
    if (!json_builder_init(&jb, 1024) || !json_builder_init(&jb_attr, 128))
    {
        ERROR("Failed to initialize JSON builder for process CPU.");
        return;
    }

    if (!build_attributes_json(&jb_attr, NULL, NULL))
    {
        ERROR("Failed to build attributes JSON for process CPU.");
        goto cleanup_cpu;
    }

    json_builder_appendf(&jb,
                         "{"
                         "\"resourceMetrics\":[{"
                         "\"resource\":{\"attributes\":%s},"
                         "\"scopeMetrics\":[{"
                         "\"scope\":{},"
                         "\"metrics\":[",
                         jb_attr.buffer);

    char value_buf[64];
    snprintf(value_buf, sizeof(value_buf), "%.3f", process_cpu_ms);
    append_otlp_sum_metric(&jb, "ebpf.jagent.resource.demand.process.cpu.ms", value_buf, jb_attr.buffer, start_time_ns, now_ns);

    json_builder_appendf(&jb, "]}]}]}");
    send_otlp_payload(cfg, jb.buffer);

cleanup_cpu:
    json_builder_free(&jb);
    json_builder_free(&jb_attr);
}

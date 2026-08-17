#ifndef ENV_LOADER_H
#define ENV_LOADER_H

#include <stdbool.h>

// Configuration struct for OTLP exporter
struct otlp_config {
    char *endpoint;
    char *bearer_token;
    char *ca_cert;
    char *client_cert;
    char *client_key;
    bool insecure;             // skip TLS verification
    int timeout_secs;          // overall timeout
    int connect_timeout_secs;  // connect timeout
};

// Load configuration: first from .env file at path (if non-NULL), then overlay with real env vars.
// If env_path is NULL, only environment variables are used.
void load_env_config(const char *env_path, struct otlp_config *cfg);

// Free any heap allocations inside cfg (but not cfg itself)
void free_env_config(struct otlp_config *cfg);

#endif // ENV_LOADER_H

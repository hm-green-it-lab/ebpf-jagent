#include "env_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdbool.h> // for bool

#define MAX_LINE 1024

// trim whitespace in place, return pointer to first non-space character
static char *trim(char *s) {
    if (!s) return s;
    while (*s && isspace((unsigned char)*s)) s++;
    char *end = s + strlen(s);
    while (end > s && isspace((unsigned char)*(end - 1))) end--;
    *end = '\0';
    return s;
}

// parse boolean-like strings ("1", "true", case-insensitive)
static bool parse_bool(const char *v) {
    if (!v) return false;
    if (strcmp(v, "1") == 0) return true;
    if (strcasecmp(v, "true") == 0) return true;
    return false;
}

// safe strdup equivalent, returns NULL if input is NULL or malloc fails
static char *strdup_or_null(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    char *d = malloc(len + 1);
    if (!d) return NULL;
    memcpy(d, s, len + 1);
    return d;
}

// helper: set *target to value if not already set
static void try_set_if_missing(char **target, const char *value) {
    if (value && value[0] && *target == NULL) {
        *target = strdup_or_null(value);
    }
}

// read .env-like file and populate parts of otlp_config, plus JVM_LIB_PATH into env if present
static void load_dotenv(const char *path, struct otlp_config *cfg) {
    if (!path) return;
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), f)) {
        char *p = trim(line);
        if (*p == '\0' || *p == '#' || *p == ';') // skip comments/blank
            continue;
        char *eq = strchr(p, '=');
        if (!eq)
            continue;
        *eq = '\0';
        char *key = trim(p);
        char *val = trim(eq + 1);

        // strip surrounding quotes if present (single or double)
        size_t vlen = strlen(val);
        if (vlen >= 2 && ((val[0] == '"' && val[vlen - 1] == '"') ||
                          (val[0] == '\'' && val[vlen - 1] == '\''))) {
            val[vlen - 1] = '\0';
            val++;
        }

        if (strcmp(key, "OTLP_ENDPOINT") == 0) {
            try_set_if_missing(&cfg->endpoint, val);
        } else if (strcmp(key, "OTLP_BEARER_TOKEN") == 0) {
            try_set_if_missing(&cfg->bearer_token, val);
        } else if (strcmp(key, "OTLP_CA_CERT") == 0) {
            try_set_if_missing(&cfg->ca_cert, val);
        } else if (strcmp(key, "OTLP_CLIENT_CERT") == 0) {
            try_set_if_missing(&cfg->client_cert, val);
        } else if (strcmp(key, "OTLP_CLIENT_KEY") == 0) {
            try_set_if_missing(&cfg->client_key, val);
        } else if (strcmp(key, "OTLP_INSECURE") == 0) {
            if (!cfg->insecure)
                cfg->insecure = parse_bool(val);
        } else if (strcmp(key, "OTLP_TIMEOUT_SECS") == 0) {
            if (cfg->timeout_secs == 0)
                cfg->timeout_secs = atoi(val);
        } else if (strcmp(key, "OTLP_CONNECT_TIMEOUT") == 0) {
            if (cfg->connect_timeout_secs == 0)
                cfg->connect_timeout_secs = atoi(val);
        } else if (strcmp(key, "JVM_LIB_PATH") == 0) {
            // persist JVM_LIB_PATH into environment so callers can retrieve it via getenv
            // but do not override if already set externally
            if (!getenv("JVM_LIB_PATH") && val[0]) {
                setenv("JVM_LIB_PATH", val, 0); // don't overwrite existing
            }
        }
    }
    fclose(f);
}

// overlay real environment variables (take precedence over .env values)
static void overlay_env_vars(struct otlp_config *cfg) {
    char *e;

    if ((e = getenv("OTLP_ENDPOINT"))) {
        free(cfg->endpoint);
        cfg->endpoint = strdup_or_null(e);
    }
    if ((e = getenv("OTLP_BEARER_TOKEN"))) {
        free(cfg->bearer_token);
        cfg->bearer_token = strdup_or_null(e);
    }
    if ((e = getenv("OTLP_CA_CERT"))) {
        free(cfg->ca_cert);
        cfg->ca_cert = strdup_or_null(e);
    }
    if ((e = getenv("OTLP_CLIENT_CERT"))) {
        free(cfg->client_cert);
        cfg->client_cert = strdup_or_null(e);
    }
    if ((e = getenv("OTLP_CLIENT_KEY"))) {
        free(cfg->client_key);
        cfg->client_key = strdup_or_null(e);
    }
    if ((e = getenv("OTLP_INSECURE"))) {
        cfg->insecure = parse_bool(e);
    }
    if ((e = getenv("OTLP_TIMEOUT_SECS"))) {
        cfg->timeout_secs = atoi(e);
    }
    if ((e = getenv("OTLP_CONNECT_TIMEOUT"))) {
        cfg->connect_timeout_secs = atoi(e);
    }
}

// public entry point: populate otlp_config and ensure required fields are present
void load_env_config(const char *env_path, struct otlp_config *cfg) {
    // zero everything and apply sane defaults
    memset(cfg, 0, sizeof(*cfg));
    cfg->insecure = false;
    cfg->timeout_secs = 5;
    cfg->connect_timeout_secs = 2;
    cfg->endpoint = NULL;
    cfg->bearer_token = NULL;
    cfg->ca_cert = NULL;
    cfg->client_cert = NULL;
    cfg->client_key = NULL;

    // load from .env file if provided
    if (env_path)
        load_dotenv(env_path, cfg);

    // overlay real env vars to take precedence
    overlay_env_vars(cfg);

    // endpoint is mandatory for OTLP exporter
    if (!cfg->endpoint) {
        fprintf(stderr, "OTLP endpoint not configured (missing OTLP_ENDPOINT in .env or environment)\n");
        exit(-1);
    }

    // JVM_LIB_PATH must also be present either via .env or environment
    const char *jvm_path = getenv("JVM_LIB_PATH");
    if (!jvm_path || jvm_path[0] == '\0') {
        fprintf(stderr, "JVM_LIB_PATH not configured in .env or environment; cannot proceed\n");
        exit(-1);
    }
}

// free any dynamically allocated strings inside otlp_config
void free_env_config(struct otlp_config *cfg) {
    if (!cfg) return;
    free(cfg->endpoint);
    free(cfg->bearer_token);
    free(cfg->ca_cert);
    free(cfg->client_cert);
    free(cfg->client_key);
    cfg->endpoint = NULL;
    cfg->bearer_token = NULL;
    cfg->ca_cert = NULL;
    cfg->client_cert = NULL;
    cfg->client_key = NULL;
}

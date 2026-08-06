/*
 * mali_iov_audit.c
 * 只读审计 /dev/mali0 的 ioctl 命令，寻找 canonical 内核地址泄漏
 * 编译：aarch64-linux-android35-clang -O2 -o mali_iov_audit mali_iov_audit.c
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>

/* Mali ioctl magic */
#define KBASE_IOCTL_TYPE 0x80

/* 已知的 mali_kbase ioctl 命令 */
#define KBASE_IOCTL_VERSION             _IOWR(KBASE_IOCTL_TYPE, 0, struct kbase_ioctl_version)
#define KBASE_IOCTL_MEM_ALLOC           _IOWR(KBASE_IOCTL_TYPE, 5, struct kbase_ioctl_mem_alloc)
#define KBASE_IOCTL_MEM_QUERY           _IOWR(KBASE_IOCTL_TYPE, 7, struct kbase_ioctl_mem_query)
struct kbase_ioctl_gpu_props_reg_dump {
    unsigned char data[4096];
};

#define KBASE_IOCTL_GPU_PROPS_REG_DUMP  _IOWR(KBASE_IOCTL_TYPE, 14, struct kbase_ioctl_gpu_props_reg_dump)
#define KBASE_IOCTL_GET_CONTEXT_ID      _IOWR(KBASE_IOCTL_TYPE, 3, struct kbase_ioctl_get_context_id)

struct kbase_ioctl_version {
    int major;
    int minor;
};

struct kbase_ioctl_get_context_id {
    unsigned long long id;
};

/* 通用 ioctl 测试 */
static void try_ioctl_raw(int fd, unsigned int cmd, const char *name) {
    unsigned char buf[4096];
    memset(buf, 0x41, sizeof(buf));  /* 填充可识别模式 */

    int ret = ioctl(fd, cmd, buf);
    if (ret < 0) {
        if (errno != ENOTTY && errno != EINVAL) {
            printf("[IOCTL] %s (0x%x): ret=%d errno=%d (%s)\n",
                   name, cmd, ret, errno, strerror(errno));
        }
        return;
    }

    printf("[IOCTL] %s (0x%x): ret=%d\n", name, cmd, ret);

    /* 检查返回数据中是否有 canonical 内核地址 */
    for (int i = 0; i < sizeof(buf) - 7; i += 8) {
        unsigned long long val;
        memcpy(&val, buf + i, sizeof(val));
        /* canonical kernel address: 0xffffffd3... */
        if ((val >> 32) == 0xffffffd3 || (val >> 32) == 0xffffffc0) {
            printf("  [LEAK] offset=0x%x val=0x%016llx\n", i, val);
        }
    }
}

int main(void) {
    int fd = open("/dev/mali0", O_RDWR);
    if (fd < 0) {
        perror("open /dev/mali0");
        return 1;
    }

    printf("=== Mali ioctl audit ===\n");

    /* 测试已知 ioctl 命令 */
    try_ioctl_raw(fd, KBASE_IOCTL_VERSION, "VERSION");
    try_ioctl_raw(fd, KBASE_IOCTL_GET_CONTEXT_ID, "GET_CONTEXT_ID");
    try_ioctl_raw(fd, KBASE_IOCTL_GPU_PROPS_REG_DUMP, "GPU_PROPS_REG_DUMP");

    /* 扫描所有可能的 ioctl 命令 */
    for (int cmd_idx = 0; cmd_idx < 256; cmd_idx++) {
        unsigned int cmd = _IOWR(KBASE_IOCTL_TYPE, cmd_idx, unsigned char[256]);
        try_ioctl_raw(fd, cmd, "SCAN");
    }

    close(fd);
    printf("=== Done ===\n");
    return 0;
}

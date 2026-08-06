/*
 * Minimal read-only ABI check for Violin's public /dev/hpc-cdev.
 * The exact OTA module hpc_cdev.ko accepts 0xc0085802, copies an 8-byte
 * {tsens_id, temperature} record, calls xr_tsens_read_temp(), and copies the
 * record back.  No allocation, mapping, control operation, or write command
 * is sent.
 */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct hpc_tsens_info {
  int32_t tsens_id;
  int32_t temperature;
};

#define HPC_IOCTL_GET_TSENS_INFO _IOWR('X', 2, struct hpc_tsens_info)

int main(void) {
  struct hpc_tsens_info info = { .tsens_id = 0, .temperature = 0 };
  int fd = open("/dev/hpc-cdev", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    printf("HPC_OPEN_FAIL errno=%d (%s)\n", errno, strerror(errno));
    return 1;
  }
  errno = 0;
  int ret = ioctl(fd, HPC_IOCTL_GET_TSENS_INFO, &info);
  int saved_errno = errno;
  printf("HPC_TSENS cmd=0x%08lx ret=%d errno=%d (%s) id=%d temp=%d\n",
         (unsigned long)HPC_IOCTL_GET_TSENS_INFO, ret, saved_errno,
         strerror(saved_errno), info.tsens_id, info.temperature);
  close(fd);
  return ret == 0 ? 0 : 2;
}

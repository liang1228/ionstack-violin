/* Read-only ABI probe for /dev/mali0. It only opens the device and submits
 * the documented version-negotiation ioctl; no memory allocation or GPU job
 * submission is performed. */
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

struct mali_version_check {
  uint16_t major;
  uint16_t minor;
};

#define MALI_IOCTL_VERSION_CHECK _IOWR(0x80, 0x00, struct mali_version_check)

int main(void) {
  struct mali_version_check version = {1, 0};
  int fd = open("/dev/mali0", O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    printf("MALI_OPEN_FAIL errno=%d (%s)\n", errno, strerror(errno));
    return 1;
  }
  int ret = ioctl(fd, MALI_IOCTL_VERSION_CHECK, &version);
  int saved_errno = errno;
  printf("MALI_VERSION_CHECK cmd=0x%08lx ret=%d errno=%d (%s) major=%u minor=%u\n",
         (unsigned long)MALI_IOCTL_VERSION_CHECK, ret, saved_errno, strerror(saved_errno),
         version.major, version.minor);
  close(fd);
  return ret == 0 ? 0 : 2;
}

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

/* xr_timestamp.ts_ioctl: _IOR('k', 0/1, __u64), no input payload. */
#define XR_TIMESTAMP_GETCOUNT _IOR('k', 0, unsigned long long)
#define XR_TIMESTAMP_GETTIME  _IOR('k', 1, unsigned long long)

static int read_scalar(int fd, unsigned long command, const char *name) {
    unsigned long long value = 0;
    int ret = ioctl(fd, command, &value);
    int saved_errno = errno;
    printf("%s cmd=0x%08lx ret=%d errno=%d (%s) value=%llu\n",
           name, command, ret, saved_errno, strerror(saved_errno), value);
    return ret;
}

int main(void) {
    int fd = open("/dev/timestamp", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        printf("open errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    int a = read_scalar(fd, XR_TIMESTAMP_GETCOUNT, "GETCOUNT");
    int b = read_scalar(fd, XR_TIMESTAMP_GETTIME, "GETTIME");
    if (close(fd) != 0) {
        printf("close errno=%d (%s)\n", errno, strerror(errno));
        return 1;
    }
    return (a == 0 && b == 0) ? 0 : 1;
}

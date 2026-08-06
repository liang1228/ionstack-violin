#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "Usage: %s <ko>\n", argv[0]); return 1; }
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) { fprintf(stderr, "open: %s\n", strerror(errno)); return 1; }
    long sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    void *buf = malloc(sz);
    read(fd, buf, sz);
    close(fd);
    fprintf(stderr, "Loading %s (%ld bytes)\n", argv[1], sz);
    
    // Try finit_module with IGNORE_VERMAGIC (2)
    fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    int ret = syscall(SYS_finit_module, fd, "", 2);
    fprintf(stderr, "finit(VERMAGIC): ret=%d errno=%d %s\n", ret, errno, strerror(errno));
    close(fd);
    
    if (ret != 0) {
        // Try with IGNORE_MODVERSIONS (1)
        fd = open(argv[1], O_RDONLY | O_CLOEXEC);
        ret = syscall(SYS_finit_module, fd, "", 1);
        fprintf(stderr, "finit(MODVERSIONS): ret=%d errno=%d %s\n", ret, errno, strerror(errno));
        close(fd);
    }
    
    if (ret != 0) {
        // Try with IGNORE_BOTH (3)
        fd = open(argv[1], O_RDONLY | O_CLOEXEC);
        ret = syscall(SYS_finit_module, fd, "", 3);
        fprintf(stderr, "finit(BOTH): ret=%d errno=%d %s\n", ret, errno, strerror(errno));
        close(fd);
    }
    
    if (ret != 0) {
        // Try init_module (load from memory)
        ret = syscall(SYS_init_module, buf, sz, "");
        fprintf(stderr, "init_module: ret=%d errno=%d %s\n", ret, errno, strerror(errno));
    }
    
    free(buf);
    return ret ? 1 : 0;
}

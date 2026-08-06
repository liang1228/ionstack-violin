#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>

// init_module(module_image, len, param_values)
// flags: MODULE_INIT_IGNORE_MODVERSIONS=1, MODULE_INIT_IGNORE_VERMAGIC=2

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <ko_file> [params]\n", argv[0]);
        return 1;
    }
    
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        fprintf(stderr, "open failed: %s\n", strerror(errno));
        return 1;
    }
    
    long sz = lseek(fd, 0, SEEK_END);
    lseek(fd, 0, SEEK_SET);
    
    void *buf = malloc(sz);
    read(fd, buf, sz);
    close(fd);
    
    fprintf(stderr, "Loading %s (%ld bytes)...\n", argv[1], sz);
    
    // Try with ignore vermagic
    const char *params = argc > 2 ? argv[2] : "";
    int ret = syscall(SYS_init_module, buf, sz, params);
    if (ret == 0) {
        fprintf(stderr, "SUCCESS!\n");
        free(buf);
        return 0;
    }
    
    fprintf(stderr, "init_module failed: %s (errno=%d)\n", strerror(errno), errno);
    
    // Try with finit_module + flags
    fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        // finit_module(fd, params, flags)
        // MODULE_INIT_IGNORE_MODVERSIONS = 1
        // MODULE_INIT_IGNORE_VERMAGIC = 2
        ret = syscall(SYS_finit_module, fd, params, 2);  // IGNORE_VERMAGIC
        fprintf(stderr, "finit_module(IGNORE_VERMAGIC): ret=%d errno=%d %s\n", 
                ret, errno, strerror(errno));
        
        if (ret != 0) {
            ret = syscall(SYS_finit_module, fd, params, 3);  // IGNORE_BOTH
            fprintf(stderr, "finit_module(IGNORE_BOTH): ret=%d errno=%d %s\n",
                    ret, errno, strerror(errno));
        }
        close(fd);
    }
    
    free(buf);
    return ret;
}

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <errno.h>

#define MODULE_INIT_IGNORE_VERMAGIC 0x0002
#define MODULE_INIT_IGNORE_MODVERSIONS 0x0001

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <ko> [args]\n", argv[0]); return 1; }
    int fd = open(argv[1], O_RDONLY|O_CLOEXEC);
    if (fd<0) { perror("open"); return 1; }
    struct stat st;
    fstat(fd, &st);
    void *img = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    if (img == MAP_FAILED) { perror("mmap"); close(fd); return 1; }
    char params[4096]={0};
    int off=0;
    for (int i=2;i<argc&&off<(int)sizeof(params)-128;i++) {
        if(i>2) params[off++]=' ';
        off += snprintf(params+off, sizeof(params)-off, "%s", argv[i]);
    }
    /* Try init_module first (from memory) */
    long ret = syscall(SYS_init_module, img, (unsigned long)st.st_size, params);
    if (ret == 0) {
        printf("init_module: loaded ok\n");
        munmap(img, st.st_size);
        close(fd);
        return 0;
    }
    int e1 = errno;
    fprintf(stderr, "init_module: %s (errno=%d)\n", strerror(e1), e1);
    /* Try finit_module with flags */
    lseek(fd, 0, SEEK_SET);
    ret = syscall(SYS_finit_module, fd, params, MODULE_INIT_IGNORE_VERMAGIC|MODULE_INIT_IGNORE_MODVERSIONS);
    if (ret == 0) {
        printf("finit_module: loaded ok\n");
        munmap(img, st.st_size);
        close(fd);
        return 0;
    }
    int e2 = errno;
    fprintf(stderr, "finit_module: %s (errno=%d)\n", strerror(e2), e2);
    /* Try finit_module with only IGNORE_VERMAGIC */
    lseek(fd, 0, SEEK_SET);
    ret = syscall(SYS_finit_module, fd, params, MODULE_INIT_IGNORE_VERMAGIC);
    if (ret == 0) {
        printf("finit_module(ignore_vermagic): loaded ok\n");
        munmap(img, st.st_size);
        close(fd);
        return 0;
    }
    int e3 = errno;
    fprintf(stderr, "finit_module(ignore_vermagic): %s (errno=%d)\n", strerror(e3), e3);
    /* Try finit_module with only IGNORE_MODVERSIONS */
    lseek(fd, 0, SEEK_SET);
    ret = syscall(SYS_finit_module, fd, params, MODULE_INIT_IGNORE_MODVERSIONS);
    if (ret == 0) {
        printf("finit_module(ignore_modversions): loaded ok\n");
        munmap(img, st.st_size);
        close(fd);
        return 0;
    }
    int e4 = errno;
    fprintf(stderr, "finit_module(ignore_modversions): %s (errno=%d)\n", strerror(e4), e4);
    /* Try finit_module with no flags */
    lseek(fd, 0, SEEK_SET);
    ret = syscall(SYS_finit_module, fd, params, 0);
    if (ret == 0) {
        printf("finit_module(no flags): loaded ok\n");
        munmap(img, st.st_size);
        close(fd);
        return 0;
    }
    int e5 = errno;
    fprintf(stderr, "finit_module(no flags): %s (errno=%d)\n", strerror(e5), e5);
    munmap(img, st.st_size);
    close(fd);
    return 1;
}

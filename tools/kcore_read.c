/*
 * kcore_read.c — 从 /proc/kcore 读取内核虚拟地址内容
 * 编译: aarch64-linux-android35-clang -O2 -static -o kcore_read kcore_read.c
 * 用法: kcore_read <vaddr_hex> <len> <outfile>
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <string.h>
#include <elf.h>

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <vaddr_hex> <len> <outfile>\n", argv[0]);
        return 1;
    }
    uint64_t vaddr = strtoull(argv[1], NULL, 0);
    size_t len = atoi(argv[2]);
    const char *outfile = argv[3];

    int fd = open("/proc/kcore", O_RDONLY);
    if (fd < 0) { perror("/proc/kcore"); return 1; }

    Elf64_Ehdr ehdr;
    read(fd, &ehdr, sizeof(ehdr));
    if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) {
        fprintf(stderr, "Not ELF\n"); return 1;
    }

    for (int i = 0; i < ehdr.e_phnum; i++) {
        Elf64_Phdr phdr;
        lseek(fd, ehdr.e_phoff + i * ehdr.e_phentsize, SEEK_SET);
        read(fd, &phdr, sizeof(phdr));
        if (phdr.p_type != PT_LOAD) continue;
        if (vaddr >= phdr.p_vaddr && vaddr < phdr.p_vaddr + phdr.p_filesz) {
            uint64_t off = phdr.p_offset + (vaddr - phdr.p_vaddr);
            lseek(fd, off, SEEK_SET);
            unsigned char *buf = malloc(len);
            ssize_t n = read(fd, buf, len);
            if (n > 0) {
                int ofd = open(outfile, O_WRONLY|O_CREAT|O_TRUNC, 0644);
                write(ofd, buf, n);
                close(ofd);
                fprintf(stderr, "OK: %zd bytes from 0x%lx -> %s\n",
                        n, (unsigned long)vaddr, outfile);
            }
            free(buf);
            close(fd);
            return 0;
        }
    }
    fprintf(stderr, "0x%lx not in kcore\n", (unsigned long)vaddr);
    return 1;
}

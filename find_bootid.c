#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>

int main() {
    // sysctl_bootid address from kallsyms
    uint64_t addr = 0xffffffd368136f58ULL;
    int fd = open("/proc/1/mem", O_RDONLY);
    if (fd < 0) { perror("open"); return 1; }
    uint64_t ptr = 0;
    pread(fd, &ptr, 8, (off_t)addr);
    close(fd);
    printf("random_boot_id = 0x%016llx\n", (unsigned long long)ptr);
    return 0;
}

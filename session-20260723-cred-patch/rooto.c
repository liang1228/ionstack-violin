#include <unistd.h>
int main(void) {
    setuid(0);
    setgid(0);
    execl("/system/bin/sh", "sh", NULL);
    return 1;
}

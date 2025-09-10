#include <stdio.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <fcntl.h>

int main() {
    printf("Testing syscall %d (openat)\n", __NR_openat);
    
    // Try to open a file to trigger openat syscall
    int fd = open("/dev/null", O_RDONLY);
    if (fd >= 0) {
        printf("Successfully opened /dev/null, fd=%d\n", fd);
        close(fd);
    } else {
        printf("Failed to open /dev/null\n");
    }
    
    return 0;
}

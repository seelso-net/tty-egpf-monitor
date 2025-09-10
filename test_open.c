#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s <device>\n", argv[0]);
        return 1;
    }
    
    printf("Opening %s...\n", argv[1]);
    int fd = open(argv[1], O_RDWR);
    if (fd < 0) {
        perror("open failed");
        return 1;
    }
    
    printf("Successfully opened %s, fd=%d\n", argv[1], fd);
    printf("Sleeping for 2 seconds...\n");
    sleep(2);
    
    printf("Closing %s...\n", argv[1]);
    close(fd);
    printf("Done.\n");
    
    return 0;
}

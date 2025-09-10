#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <termios.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <tty_device>\n", argv[0]);
        return 1;
    }

    const char *tty_device = argv[1];
    int fd;

    printf("Opening %s...\n", tty_device);
    fd = open(tty_device, O_RDWR | O_NOCTTY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open %s: %s\n", tty_device, strerror(errno));
        return 1;
    }
    printf("Successfully opened %s, fd=%d\n", tty_device, fd);

    // Configure the serial port
    struct termios tty;
    if (tcgetattr(fd, &tty) != 0) {
        fprintf(stderr, "Error getting termios: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    // Set baud rate to 115200
    cfsetospeed(&tty, B115200);
    cfsetispeed(&tty, B115200);

    // Configure 8N1
    tty.c_cflag &= ~PARENB; // No parity
    tty.c_cflag &= ~CSTOPB; // One stop bit
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;     // 8 data bits
    tty.c_cflag &= ~CRTSCTS; // No hardware flow control
    tty.c_cflag |= CREAD | CLOCAL; // Enable reading and ignore modem control lines

    // Make raw
    cfmakeraw(&tty);

    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        fprintf(stderr, "Error setting termios: %s\n", strerror(errno));
        close(fd);
        return 1;
    }

    printf("Serial port configured\n");

    // Try to write some data
    const char *test_data = "Hello TTY!\n";
    ssize_t written = write(fd, test_data, strlen(test_data));
    if (written < 0) {
        fprintf(stderr, "Write failed: %s\n", strerror(errno));
    } else {
        printf("Wrote %zd bytes: %s", written, test_data);
    }

    // Try to read some data (non-blocking)
    char buffer[256];
    ssize_t bytes_read = read(fd, buffer, sizeof(buffer) - 1);
    if (bytes_read < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            printf("No data available to read (expected)\n");
        } else {
            fprintf(stderr, "Read failed: %s\n", strerror(errno));
        }
    } else if (bytes_read > 0) {
        buffer[bytes_read] = '\0';
        printf("Read %zd bytes: %s", bytes_read, buffer);
    } else {
        printf("No data read\n");
    }

    printf("Sleeping for 2 seconds...\n");
    sleep(2);

    printf("Closing %s...\n", tty_device);
    close(fd);
    printf("Done.\n");

    return 0;
}


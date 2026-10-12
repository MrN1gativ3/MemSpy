#define _GNU_SOURCE

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(void)
{
    int ready[2];
    int release[2];
    pid_t child;
    uintptr_t address;
    char path[64];
    char value = 0x2a;
    int descriptor;
    int status;

    if (pipe(ready) != 0 || pipe(release) != 0)
        return 1;
    child = fork();
    if (child == 0) {
        char *page = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        close(ready[0]);
        close(release[1]);
        if (page == MAP_FAILED)
            _exit(2);
        address = (uintptr_t)page;
        if (write(ready[1], &address, sizeof address) != (ssize_t)sizeof address)
            _exit(3);
        if (read(release[0], &value, 1) != 1)
            _exit(4);
        _exit(page[0] == 0x2a ? 0 : 5);
    }
    close(ready[1]);
    close(release[0]);
    if (child < 0 || read(ready[0], &address, sizeof address) != (ssize_t)sizeof address)
        return 1;
    snprintf(path, sizeof path, "/proc/%d/mem", child);
    descriptor = open(path, O_RDWR | O_CLOEXEC);
    if (descriptor < 0 || pwrite(descriptor, &value, 1, (off_t)address) != 1)
        return 1;
    usleep(250000);
    close(descriptor);
    if (write(release[1], &value, 1) != 1)
        return 1;
    waitpid(child, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : 1;
}

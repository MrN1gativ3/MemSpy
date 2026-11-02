#define _GNU_SOURCE

#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static int
exec_from_memfd(char **argv)
{
    char buffer[8192];
    ssize_t count;
    int source = open("/proc/self/exe", O_RDONLY);
    int memory = (int)syscall(SYS_memfd_create, "memspy-chain-fixture", 0);

    if (source < 0 || memory < 0)
        return 1;
    while ((count = read(source, buffer, sizeof buffer)) > 0) {
        if (write(memory, buffer, (size_t)count) != count)
            return 1;
    }
    if (count < 0 || fchmod(memory, 0700) != 0 || lseek(memory, 0, SEEK_SET) < 0)
        return 1;
    setenv("MEMSPY_CHAIN_CHILD", "1", 1);
    syscall(SYS_execveat, memory, "", argv, environ, AT_EMPTY_PATH);
    return 1;
}

int
main(int argc, char **argv)
{
    int ready[2];
    int proceed[2];
    pid_t child;
    uintptr_t address;
    int replacement = 42;
    int status = 0;
    char signal_byte = 1;
    struct iovec local = {.iov_base = &replacement, .iov_len = sizeof replacement};
    struct iovec remote;
    bool write_succeeded;

    (void)argc;
    if (getenv("MEMSPY_CHAIN_CHILD") != NULL)
        return 0;
    if (pipe(ready) != 0 || pipe(proceed) != 0)
        return 1;
    child = fork();
    if (child == 0) {
        volatile int target = 0;
        address = (uintptr_t)&target;
        close(ready[0]);
        close(proceed[1]);
        if (write(ready[1], &address, sizeof address) != sizeof address ||
            read(proceed[0], &signal_byte, 1) != 1)
            _exit(1);
        /* The same child receives the write and executes the memfd image. */
        _exit(exec_from_memfd(argv));
    }
    if (child < 0)
        return 1;
    close(ready[1]);
    close(proceed[0]);
    if (read(ready[0], &address, sizeof address) != sizeof address)
        return 1;
    remote = (struct iovec){.iov_base = (void *)address, .iov_len = sizeof replacement};
    write_succeeded = process_vm_writev(child, &local, 1, &remote, 1, 0) ==
                      sizeof replacement;
    usleep(250000);
    if (write(proceed[1], &signal_byte, 1) != 1 || waitpid(child, &status, 0) != child)
        return 1;
    return write_succeeded && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

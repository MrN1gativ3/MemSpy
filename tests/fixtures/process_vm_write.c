#define _GNU_SOURCE
#include <signal.h>
#include <stdint.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <unistd.h>

int
main(void)
{
    int pipefd[2];
    pid_t child;
    uintptr_t remote_address;
    int replacement = 42;

    if (pipe(pipefd) != 0)
        return 1;
    child = fork();
    if (child == 0) {
        volatile int target = 0;
        uintptr_t address = (uintptr_t)&target;
        close(pipefd[0]);
        if (write(pipefd[1], &address, sizeof address) != sizeof address)
            _exit(1);
        sleep(1);
        _exit(target == replacement ? 0 : 1);
    }
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 1;
    }
    close(pipefd[1]);
    if (read(pipefd[0], &remote_address, sizeof remote_address) != sizeof remote_address) {
        close(pipefd[0]);
        return 1;
    }
    close(pipefd[0]);
    struct iovec local = {.iov_base = &replacement, .iov_len = sizeof replacement};
    struct iovec remote = {.iov_base = (void *)remote_address, .iov_len = sizeof replacement};
    if (process_vm_writev(child, &local, 1, &remote, 1, 0) != sizeof replacement) {
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    waitpid(child, NULL, 0);
    return 0;
}

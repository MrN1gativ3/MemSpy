#define _POSIX_C_SOURCE 200809L
#include <signal.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

int
main(void)
{
    int pipefd[2];
    pid_t child;
    int status;
    uintptr_t remote_address;

    if (pipe(pipefd) != 0)
        return 1;
    child = fork();

    if (child == 0) {
        volatile long target = 0;
        uintptr_t address = (uintptr_t)&target;
        close(pipefd[0]);
        if (write(pipefd[1], &address, sizeof address) != sizeof address)
            _exit(1);
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) != 0)
            _exit(1);
        raise(SIGSTOP);
        _exit(target == 42 ? 0 : 1);
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
    if (waitpid(child, &status, 0) < 0 || !WIFSTOPPED(status))
        return 1;
    if (ptrace(PTRACE_POKEDATA, child, (void *)remote_address, (void *)42L) != 0) {
        ptrace(PTRACE_DETACH, child, NULL, NULL);
        kill(child, SIGKILL);
        waitpid(child, NULL, 0);
        return 1;
    }
    ptrace(PTRACE_DETACH, child, NULL, NULL);
    waitpid(child, &status, 0);
    return WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : 1;
}

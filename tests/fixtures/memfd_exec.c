#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

int
main(int argc, char **argv)
{
    char buffer[8192];
    ssize_t count;
    int source;
    int memory;

    (void)argc;
    if (getenv("FILELESS_FIXTURE_CHILD") != NULL) {
        usleep(300000);
        return 0;
    }
    source = open("/proc/self/exe", O_RDONLY);
    memory = (int)syscall(SYS_memfd_create, "fileless-fixture", 0);
    if (source < 0 || memory < 0)
        return 1;
    while ((count = read(source, buffer, sizeof buffer)) > 0) {
        if (write(memory, buffer, (size_t)count) != count)
            return 1;
    }
    if (count < 0 || fchmod(memory, 0700) != 0 || lseek(memory, 0, SEEK_SET) < 0)
        return 1;
    setenv("FILELESS_FIXTURE_CHILD", "1", 1);
    syscall(SYS_execveat, memory, "", argv, environ, AT_EMPTY_PATH);
    return 1;
}

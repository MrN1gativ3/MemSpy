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
    char path[] = "/tmp/memspy-deleted-XXXXXX";
    char buffer[8192];
    ssize_t count;
    int source;
    int target;

    (void)argc;
    if (getenv("MEMSPY_FIXTURE_CHILD") != NULL) {
        usleep(300000);
        return 0;
    }
    source = open("/proc/self/exe", O_RDONLY);
    target = mkstemp(path);
    if (source < 0 || target < 0)
        return 1;
    while ((count = read(source, buffer, sizeof buffer)) > 0) {
        if (write(target, buffer, (size_t)count) != count)
            return 1;
    }
    if (count < 0 || fchmod(target, 0700) != 0 || unlink(path) != 0 || lseek(target, 0, SEEK_SET) < 0)
        return 1;
    setenv("MEMSPY_FIXTURE_CHILD", "1", 1);
    syscall(SYS_execveat, target, "", argv, environ, AT_EMPTY_PATH);
    return 1;
}

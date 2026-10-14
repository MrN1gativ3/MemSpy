#define _GNU_SOURCE
#include <fcntl.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <unistd.h>

int
main(void)
{
    /* Negative control: even many write variants must not look like a
     * cross-process write when the fd is only a regular temporary file. */
    char byte = 0;
    char path[] = "/tmp/memspy-write-XXXXXX";
    struct iovec vector = {.iov_base = &byte, .iov_len = sizeof byte};
    int descriptor = mkstemp(path);

    if (descriptor < 0)
        return 1;
    unlink(path);
    for (unsigned int index = 0; index < 20000U; ++index) {
        if (write(descriptor, &byte, sizeof byte) != (ssize_t)sizeof byte ||
            pwrite(descriptor, &byte, sizeof byte, 0) != (ssize_t)sizeof byte ||
            writev(descriptor, &vector, 1) != (ssize_t)sizeof byte ||
            pwritev(descriptor, &vector, 1, 0) != (ssize_t)sizeof byte ||
            pwritev2(descriptor, &vector, 1, 0, 0) != (ssize_t)sizeof byte)
            return 1;
    }
    return close(descriptor) == 0 ? 0 : 1;
}

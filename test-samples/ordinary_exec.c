#include <unistd.h>

int
main(void)
{
    execl("/usr/bin/true", "true", NULL);
    return 1;
}

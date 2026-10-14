#include <unistd.h>

int
main(void)
{
    /* Negative control: an ordinary on-disk exec should not alert. */
    execl("/usr/bin/true", "true", NULL);
    return 1;
}

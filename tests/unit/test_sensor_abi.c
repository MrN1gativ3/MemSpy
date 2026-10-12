#include <stdint.h>

#include "memspy_shared.h"

_Static_assert(MS_KERNEL_EVENT_ABI == 2, "kernel event ABI version changed unexpectedly");
_Static_assert(sizeof(struct ms_kernel_event) == 64, "kernel event ABI must remain 64 bytes");
_Static_assert(sizeof(((struct ms_kernel_event *)0)->comm) == 16, "kernel comm bound changed");

int
main(void)
{
    if (!ms_ptrace_request_modifies(5) || !ms_ptrace_request_modifies(6) ||
        !ms_ptrace_request_modifies(0x4205) || ms_ptrace_request_modifies(18) ||
        ms_ptrace_request_modifies(0x4204))
        return 1;
    return 0;
}

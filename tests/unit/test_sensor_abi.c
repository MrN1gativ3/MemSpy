#include <stdint.h>

#include "fileless_shared.h"

_Static_assert(FL_KERNEL_EVENT_ABI == 1, "kernel event ABI must start at version 1");
_Static_assert(sizeof(struct fl_kernel_event) == 64, "kernel event ABI must remain 64 bytes");
_Static_assert(sizeof(((struct fl_kernel_event *)0)->comm) == 16, "kernel comm bound changed");

int
main(void)
{
    if (!fl_ptrace_request_modifies(5) || !fl_ptrace_request_modifies(6) ||
        !fl_ptrace_request_modifies(0x4205) || fl_ptrace_request_modifies(18) ||
        fl_ptrace_request_modifies(0x4204))
        return 1;
    return 0;
}

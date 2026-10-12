#include <stdint.h>

#include "memspy_shared.h"

_Static_assert(MS_KERNEL_EVENT_ABI == 2, "kernel event ABI version changed unexpectedly");
_Static_assert(sizeof(struct ms_kernel_event) == 64, "kernel event ABI must remain 64 bytes");
_Static_assert(sizeof(((struct ms_kernel_event *)0)->comm) == 16, "kernel comm bound changed");

int
main(void)
{
    static const char proc_mem[] = "mem";
    static const char proc_maps[] = "maps";

    if (!ms_ptrace_request_modifies(5) || !ms_ptrace_request_modifies(6) ||
        !ms_ptrace_request_modifies(0x4205) || ms_ptrace_request_modifies(18) ||
        ms_ptrace_request_modifies(0x4204))
        return 1;
    if (!ms_is_proc_mem_file(MS_PROC_SUPER_MAGIC, proc_mem) ||
        ms_is_proc_mem_file(MS_PROC_SUPER_MAGIC, proc_maps) ||
        ms_is_proc_mem_file(0x01021994U, proc_mem))
        return 1;
    if (ms_parse_proc_pid("12345") != 12345U || ms_parse_proc_pid("0") != 0 ||
        ms_parse_proc_pid("self") != 0 || ms_parse_proc_pid("12x") != 0)
        return 1;
    return 0;
}

# MemSpy test samples

These benign programs intentionally reproduce the syscall patterns detected by MemSpy. They contain no payload, persistence, networking, privilege escalation, evasion, or arbitrary process targeting.

| Sample | Expected result |
| --- | --- |
| `memfd_exec.c` | `MEMFD_EXEC` |
| `deleted_exec.c` | `DELETED_EXEC` |
| `process_vm_write.c` | `PROCESS_VM_WRITE` against its own child |
| `ptrace_write.c` | `PTRACE_WRITE` against its own traced child |
| `proc_mem_write.c` | `PROC_MEM_WRITE` against its own child |
| `injection_chain.c` | `PROCESS_VM_WRITE` followed by `INJECTION_CHAIN` in the same child |
| `ordinary_exec.c` | No alert |
| `ordinary_write.c` | No alert |

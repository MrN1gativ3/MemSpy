# MemSpy test samples

These benign programs intentionally reproduce the syscall patterns detected by MemSpy. They contain no payload, persistence, networking, privilege escalation, evasion, or arbitrary process targeting.

| Sample | Expected result |
| --- | --- |
| `memfd_exec.c` | `MEMFD_EXEC` |
| `deleted_exec.c` | `DELETED_EXEC` |
| `process_vm_write.c` | `PROCESS_VM_WRITE` against its own child |
| `ptrace_write.c` | `PTRACE_WRITE` against its own traced child |
| `ordinary_exec.c` | No alert |

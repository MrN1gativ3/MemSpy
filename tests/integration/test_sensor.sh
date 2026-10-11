#!/bin/sh
set -eu

build_dir=$1

"$build_dir/sensor-harness" "$build_dir/memfd_exec" MEMFD_EXEC
"$build_dir/sensor-harness" "$build_dir/deleted_exec" DELETED_EXEC
"$build_dir/sensor-harness" "$build_dir/process_vm_write" PROCESS_VM_WRITE
"$build_dir/sensor-harness" "$build_dir/ptrace_write" PTRACE_WRITE
"$build_dir/sensor-harness" "$build_dir/ordinary_exec" NONE

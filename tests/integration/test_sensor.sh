#!/bin/sh
set -eu

build_dir=$1

"$build_dir/sensor-harness" "$build_dir/memfd_exec" FL-MEMFD-EXEC
"$build_dir/sensor-harness" "$build_dir/deleted_exec" FL-DELETED-EXEC
"$build_dir/sensor-harness" "$build_dir/process_vm_write" FL-PROCESS-VM-WRITE
"$build_dir/sensor-harness" "$build_dir/ptrace_write" FL-PTRACE-WRITE
"$build_dir/sensor-harness" "$build_dir/ordinary_exec" NONE

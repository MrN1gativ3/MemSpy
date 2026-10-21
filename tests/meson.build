alert_json_test = executable(
  'test-alert-json',
  'unit/test_alert_json.c',
  '../src/common/alert_json.c',
  include_directories: inc,
  dependencies: [glib_dep, json_c_dep],
)

test('alert-json', alert_json_test)

daemon_inc = include_directories('../src/daemon')

policy_test = executable(
  'test-policy',
  'unit/test_policy.c',
  '../src/daemon/policy.c',
  include_directories: [inc, daemon_inc],
  dependencies: [glib_dep],
)

test('policy', policy_test)

allowlist_test = executable(
  'test-allowlist',
  'unit/test_allowlist.c',
  '../src/daemon/allowlist.c',
  include_directories: [inc, daemon_inc],
  dependencies: [glib_dep],
)

test('allowlist', allowlist_test)

response_config_test = executable(
  'test-response-config',
  'unit/test_response_config.c',
  '../src/daemon/response_config.c',
  include_directories: [inc, daemon_inc, include_directories('../src/bpf')],
  dependencies: [glib_dep],
)

test('response-config', response_config_test)

store_test = executable(
  'test-store',
  'unit/test_store.c',
  '../src/daemon/store.c',
  include_directories: [inc, daemon_inc],
  dependencies: [glib_dep, sqlite_dep],
)

test('store', store_test)

api_test = executable(
  'test-api',
  'unit/test_api.c',
  '../src/common/alert_json.c',
  '../src/daemon/api.c',
  '../src/daemon/authorizer.c',
  '../src/daemon/store.c',
  '../src/common/client.c',
  include_directories: [inc, daemon_inc, include_directories('../src/common')],
  dependencies: [glib_dep, gio_dep, json_c_dep, sqlite_dep],
)

test('api', api_test, timeout: 15)

cli_output_test = executable(
  'test-cli-output',
  'unit/test_cli_output.c',
  '../src/cli/output.c',
  '../src/common/alert_json.c',
  include_directories: [inc, include_directories('../src/cli'), include_directories('../src/common'), daemon_inc],
  dependencies: [glib_dep, json_c_dep],
)

test('cli-output', cli_output_test)
test('cli-integration', find_program('sh'),
     args: [meson.current_source_dir() / 'integration/test_cli.sh', memspyctl])

sensor_abi_test = executable(
  'test-sensor-abi',
  'unit/test_sensor_abi.c',
  include_directories: [inc, include_directories('../src/bpf')],
)

test('sensor-abi', sensor_abi_test)

enforce_abi_test = executable(
  'test-enforce-abi',
  'unit/test_enforce_abi.c',
  include_directories: [inc, include_directories('../src/bpf')],
  dependencies: [glib_dep],
)

test('enforce-abi', enforce_abi_test)

enforcer_test = executable(
  'test-enforcer',
  'unit/test_enforcer.c',
  '../src/daemon/enforcer.c',
  '../src/daemon/process_evidence.c',
  enforce_bpf_skeleton,
  include_directories: [inc, daemon_inc, include_directories('../src/bpf'), include_directories('..')],
  dependencies: [glib_dep, libbpf_dep],
  c_args: ['-Wno-overlength-strings'],
)

test('enforcer', enforcer_test)

sensor_test = executable(
  'test-sensor',
  'unit/test_sensor.c',
  '../src/daemon/sensor.c',
  '../src/daemon/process_evidence.c',
  bpf_skeleton,
  include_directories: [inc, daemon_inc, include_directories('../src/bpf'), include_directories('..')],
  dependencies: [glib_dep, libbpf_dep],
  c_args: ['-Wno-overlength-strings'],
)

test('sensor', sensor_test)

process_evidence_test = executable(
  'test-process-evidence',
  'unit/test_process_evidence.c',
  '../src/daemon/process_evidence.c',
  include_directories: [inc, daemon_inc],
  dependencies: [glib_dep],
)

test('process-evidence', process_evidence_test)

ptrace_barrier_test = executable(
  'test-ptrace-barrier',
  'unit/test_ptrace_barrier.c',
  '../src/daemon/ptrace_barrier.c',
  include_directories: [inc, daemon_inc, include_directories('../src/bpf')],
  dependencies: [glib_dep],
)

test('ptrace-barrier', ptrace_barrier_test)

daemon_test = executable(
  'test-daemon',
  'unit/test_daemon.c',
  '../src/daemon/app.c',
  '../src/daemon/health.c',
  '../src/daemon/policy.c',
  '../src/daemon/allowlist.c',
  '../src/daemon/store.c',
  '../src/daemon/api.c',
  '../src/daemon/sensor.c',
  '../src/daemon/enforcer.c',
  '../src/daemon/process_evidence.c',
  '../src/daemon/ptrace_barrier.c',
  '../src/daemon/response_config.c',
  '../src/daemon/authorizer.c',
  '../src/daemon/journal.c',
  '../src/common/alert_json.c',
  bpf_skeleton,
  enforce_bpf_skeleton,
  include_directories: [inc, daemon_inc, include_directories('../src/bpf'), include_directories('..')],
  dependencies: [glib_dep, gio_dep, json_c_dep, sqlite_dep, libbpf_dep, systemd_dep],
  c_args: ['-Wno-overlength-strings'],
)

test('daemon', daemon_test)

journal_test = executable(
  'test-journal',
  'unit/test_journal.c',
  '../src/daemon/journal.c',
  '../src/common/alert_json.c',
  include_directories: [inc, daemon_inc],
  dependencies: [json_c_dep, glib_dep, systemd_dep],
)

test('journal', journal_test)

test('daemon-integration', find_program('sh'),
     args: [meson.current_source_dir() / 'integration/test_daemon.sh', memspyd])

test('installer', find_program('sh'),
     args: [meson.current_source_dir() / 'package/test_ubuntu_installer.sh',
            meson.project_source_root() / 'install.sh',
            meson.project_source_root() / 'packaging/ubuntu/install-test-vm.sh'])

test('uninstall-state', find_program('sh'),
     args: [meson.current_source_dir() / 'package/test_uninstall_state.sh',
            meson.project_source_root() / 'packaging/common/remove-state.sh'])

test('bpf-lsm-boot', find_program('sh'),
     args: [meson.current_source_dir() / 'package/test_bpf_lsm_boot.sh',
            meson.project_source_root() / 'packaging/common/enable-bpf-lsm.sh'])

test('ci-dependencies', find_program('sh'),
     args: [meson.current_source_dir() / 'package/test_ci_dependencies.sh',
            meson.project_source_root() / '.github/workflows/ci.yml'])

test('build-portability', find_program('sh'),
     args: [meson.current_source_dir() / 'package/test_build_portability.sh',
            meson.project_source_root() / 'meson.build',
            meson.project_source_root() / 'src/daemon/store.c',
            meson.project_source_root() / 'src/bpf/memspy_enforce.bpf.c',
            meson.project_source_root() / 'src/daemon/enforcer.c',
            meson.project_source_root() / 'src/daemon/main.c'])

test('lab-runner', find_program('python3'),
     args: [meson.project_source_root() / 'tests/package/test_lab_runner.py'])

if desktop_enabled
ui_state_test = executable(
  'test-ui-state',
  'unit/test_ui_state.c',
  '../src/ui/state.c',
  include_directories: [inc, include_directories('../src/ui')],
  dependencies: [glib_dep],
)

test('ui-state', ui_state_test)

ui_test = executable(
  'test-ui',
  'ui/test_ui.c',
  '../src/ui/indicator.c',
  '../src/ui/window.c',
  '../src/ui/state.c',
  include_directories: [inc, include_directories('../src/ui')],
  dependencies: [glib_dep, gtk_dep, appindicator_dep],
)

test('ui', ui_test)
test('ui-activation', find_program('sh'),
     args: [meson.current_source_dir() / 'ui/test_activation.sh', memspy_ui],
     timeout: 30)
endif

foreach fixture : ['memfd_exec', 'deleted_exec', 'process_vm_write', 'ptrace_write', 'proc_mem_write', 'ordinary_exec', 'ordinary_write']
  executable(fixture, '../test-samples/' + fixture + '.c', install: false)
endforeach

sensor_harness = executable(
  'sensor-harness',
  'integration/sensor_harness.c',
  '../src/daemon/sensor.c',
  '../src/daemon/process_evidence.c',
  '../src/daemon/policy.c',
  bpf_skeleton,
  include_directories: [inc, daemon_inc, include_directories('../src/bpf'), include_directories('..')],
  dependencies: [glib_dep, libbpf_dep],
  c_args: ['-Wno-overlength-strings'],
)

if get_option('integration_tests')
  test('sensor-integration', find_program('sh'),
       args: [meson.current_source_dir() / 'integration/test_sensor.sh', meson.current_build_dir()],
       timeout: 60, suite: 'privileged')
endif

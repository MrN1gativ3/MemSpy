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
  '../src/daemon/store.c',
  '../src/ui/client.c',
  include_directories: [inc, daemon_inc, include_directories('../src/ui')],
  dependencies: [glib_dep, gio_dep, json_c_dep, sqlite_dep],
)

test('api', api_test, timeout: 15)

sensor_abi_test = executable(
  'test-sensor-abi',
  'unit/test_sensor_abi.c',
  include_directories: [inc, include_directories('../src/bpf')],
)

test('sensor-abi', sensor_abi_test)

sensor_test = executable(
  'test-sensor',
  'unit/test_sensor.c',
  '../src/daemon/sensor.c',
  bpf_skeleton,
  include_directories: [inc, daemon_inc, include_directories('../src/bpf'), include_directories('..')],
  dependencies: [glib_dep, libbpf_dep],
  c_args: ['-Wno-overlength-strings'],
)

test('sensor', sensor_test)

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
  '../src/common/alert_json.c',
  bpf_skeleton,
  include_directories: [inc, daemon_inc, include_directories('../src/bpf'), include_directories('..')],
  dependencies: [glib_dep, gio_dep, json_c_dep, sqlite_dep, libbpf_dep],
  c_args: ['-Wno-overlength-strings'],
)

test('daemon', daemon_test)

test('daemon-integration', find_program('sh'),
     args: [meson.current_source_dir() / 'integration/test_daemon.sh', memspyd])

test('installer', find_program('sh'),
     args: [meson.current_source_dir() / 'package/test_ubuntu_installer.sh',
            meson.project_source_root() / 'install.sh',
            meson.project_source_root() / 'packaging/ubuntu/install-test-vm.sh'])

test('migration', find_program('sh'),
     args: [meson.current_source_dir() / 'package/test_migration.sh',
            meson.project_source_root() / 'packaging/common/migrate-legacy.sh'])

test('ci-dependencies', find_program('sh'),
     args: [meson.current_source_dir() / 'package/test_ci_dependencies.sh',
            meson.project_source_root() / '.github/workflows/ci.yml'])

test('build-portability', find_program('sh'),
     args: [meson.current_source_dir() / 'package/test_build_portability.sh',
            meson.project_source_root() / 'meson.build',
            meson.project_source_root() / 'src/daemon/store.c'])

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

foreach fixture : ['memfd_exec', 'deleted_exec', 'process_vm_write', 'ptrace_write', 'ordinary_exec']
  executable(fixture, '../test-samples/' + fixture + '.c', install: false)
endforeach

sensor_harness = executable(
  'sensor-harness',
  'integration/sensor_harness.c',
  '../src/daemon/sensor.c',
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

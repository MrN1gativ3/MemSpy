project(
  'memspy',
  'c',
  version: '0.1.0',
  default_options: ['c_std=c17', 'warning_level=3', 'werror=true', 'b_pie=true'],
)

add_project_arguments('-fstack-protector-strong', language: 'c')
add_project_link_arguments('-Wl,-z,relro,-z,now', language: 'c')
if get_option('optimization') != '0'
  add_project_arguments('-D_FORTIFY_SOURCE=3', language: 'c')
endif

json_c_dep = dependency('json-c')
glib_dep = dependency('glib-2.0')
sqlite_dep = dependency('sqlite3')
gio_dep = dependency('gio-2.0')
libbpf_dep = dependency('libbpf')
gtk_dep = dependency('gtk+-3.0')
appindicator_dep = dependency('ayatana-appindicator3-0.1')
libnotify_dep = dependency('libnotify')

clang = find_program('clang')
bpftool = find_program('bpftool')

bpf_object = custom_target(
  'memspy-bpf',
  input: 'src/bpf/memspy.bpf.c',
  output: 'memspy.bpf.o',
  command: [clang, '-g', '-O2', '-target', 'bpf', '-D__TARGET_ARCH_x86',
            '-I/usr/include/' + host_machine.cpu_family() + '-linux-gnu',
            '-I' + meson.current_source_dir() / 'src/bpf', '-c', '@INPUT@', '-o', '@OUTPUT@'],
  install: true,
  install_dir: get_option('libexecdir') / 'memspy',
)

bpf_skeleton = custom_target(
  'memspy-bpf-skeleton',
  input: bpf_object,
  output: 'memspy.skel.h',
  command: [bpftool, 'gen', 'skeleton', '@INPUT@'],
  capture: true,
)

vmlinux_header = custom_target(
  'vmlinux-header',
  output: 'vmlinux.h',
  command: [bpftool, 'btf', 'dump', 'file', '/sys/kernel/btf/vmlinux', 'format', 'c'],
  capture: true,
)

enforce_bpf_object = custom_target(
  'memspy-enforce-bpf',
  input: ['src/bpf/memspy_enforce.bpf.c', vmlinux_header],
  output: 'memspy_enforce.bpf.o',
  command: [clang, '-g', '-O2', '-target', 'bpf', '-D__TARGET_ARCH_x86',
            '-I' + meson.current_build_dir(),
            '-I' + meson.current_source_dir() / 'src/bpf',
            '-c', '@INPUT0@', '-o', '@OUTPUT@'],
  install: true,
  install_dir: get_option('libexecdir') / 'memspy',
)

enforce_bpf_skeleton = custom_target(
  'memspy-enforce-bpf-skeleton',
  input: enforce_bpf_object,
  output: 'memspy_enforce.skel.h',
  command: [bpftool, 'gen', 'skeleton', '@INPUT@'],
  capture: true,
)

inc = include_directories('include')

daemon_sources = [
  'src/daemon/main.c',
  'src/daemon/app.c',
  'src/daemon/health.c',
  'src/daemon/policy.c',
  'src/daemon/allowlist.c',
  'src/daemon/store.c',
  'src/daemon/api.c',
  'src/daemon/sensor.c',
  'src/daemon/enforcer.c',
  'src/daemon/response_config.c',
  'src/daemon/authorizer.c',
  'src/common/alert_json.c',
]

memspyd = executable(
  'memspyd',
  daemon_sources,
  bpf_skeleton,
  enforce_bpf_skeleton,
  include_directories: [inc, include_directories('src/daemon'), include_directories('src/bpf'), include_directories('.')],
  dependencies: [glib_dep, gio_dep, json_c_dep, sqlite_dep, libbpf_dep],
  c_args: ['-Wno-overlength-strings'],
  pie: true,
  install: true,
)

memspy_ui = executable(
  'memspy-ui',
  'src/ui/main.c',
  'src/ui/state.c',
  'src/ui/client.c',
  'src/ui/window.c',
  'src/ui/indicator.c',
  'src/ui/notifications.c',
  'src/daemon/store.c',
  'src/common/alert_json.c',
  include_directories: [inc, include_directories('src/ui'), include_directories('src/daemon')],
  dependencies: [glib_dep, gio_dep, json_c_dep, sqlite_dep, gtk_dep, appindicator_dep, libnotify_dep],
  pie: true,
  install: true,
)

install_data('config/allowlist.conf', install_dir: get_option('sysconfdir') / 'memspy')
install_data('config/response-allowlist.conf',
             install_dir: get_option('sysconfdir') / 'memspy')
install_data('packaging/common/migrate-legacy.sh',
             install_dir: get_option('libexecdir') / 'memspy',
             install_mode: 'rwxr-xr-x',
             rename: 'migrate-legacy')
install_data('packaging/common/cleanup-bpf.sh',
             install_dir: get_option('libexecdir') / 'memspy',
             install_mode: 'rwxr-xr-x',
             rename: 'cleanup-bpf')
install_data('data/memspy-ui.css', install_dir: get_option('datadir') / 'memspy')
install_data('packaging/common/memspyd.service',
             install_dir: get_option('prefix') / 'lib/systemd/system')
install_data('packaging/common/memspyd.tmpfiles',
             install_dir: get_option('prefix') / 'lib/tmpfiles.d',
             rename: 'memspyd.conf')
install_data('packaging/common/memspyd.sysusers',
             install_dir: get_option('prefix') / 'lib/sysusers.d',
             rename: 'memspyd.conf')
install_data('packaging/common/org.memspy.response.policy',
             install_dir: get_option('datadir') / 'polkit-1/actions')
install_data('packaging/common/org.memspy.MemSpyUI.desktop',
             install_dir: get_option('datadir') / 'applications')
install_data('packaging/common/org.memspy.MemSpyUI-autostart.desktop',
             install_dir: get_option('sysconfdir') / 'xdg/autostart',
             rename: 'org.memspy.MemSpyUI.desktop')
install_data(
  'data/icons/memspy-healthy-symbolic.svg',
  'data/icons/memspy-medium-symbolic.svg',
  'data/icons/memspy-high-symbolic.svg',
  'data/icons/memspy-offline-symbolic.svg',
  install_dir: get_option('datadir') / 'icons/hicolor/scalable/status',
)
install_man('docs/memspyd.8', 'docs/memspy-ui.1')

subdir('tests')

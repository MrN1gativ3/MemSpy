Name:           memspyd
Version:        0.1.0
Release:        1%{?dist}
Summary:        Local eBPF fileless malware detector for GNOME and KDE
License:        LicenseRef-Not-Specified
URL:            https://example.invalid/memspyd
Source0:        %{name}-%{version}.tar.gz

ExclusiveArch:  x86_64
BuildRequires:  meson
BuildRequires:  ninja-build
BuildRequires:  clang
BuildRequires:  bpftool
BuildRequires:  pkgconfig(libbpf)
BuildRequires:  pkgconfig(glib-2.0)
BuildRequires:  pkgconfig(json-c)
BuildRequires:  pkgconfig(sqlite3)
BuildRequires:  pkgconfig(gtk+-3.0)
BuildRequires:  pkgconfig(ayatana-appindicator3-0.1)
BuildRequires:  pkgconfig(libnotify)
Requires:       systemd
Conflicts:      filelessd
Obsoletes:      filelessd < 0.1.0-2
Suggests:       gnome-shell-extension-appindicator

%description
A detection-only eBPF daemon and unprivileged desktop alert indicator for
high-confidence fileless execution and injection behavior.

%prep
%autosetup

%build
%meson -Dintegration_tests=false
%meson_build

%install
%meson_install

%pre
%sysusers_create_compat %{_sysusersdir}/memspyd.conf

%post
/usr/libexec/memspy/migrate-legacy
%systemd_post memspyd.service
systemd-tmpfiles --create %{_tmpfilesdir}/memspyd.conf || :

%preun
%systemd_preun memspyd.service

%postun
%systemd_postun_with_restart memspyd.service

%files
%config(noreplace) %{_sysconfdir}/memspy/allowlist.conf
%{_bindir}/memspyd
%{_bindir}/memspy-ui
%{_libexecdir}/memspy/memspy.bpf.o
%{_libexecdir}/memspy/migrate-legacy
%{_unitdir}/memspyd.service
%{_tmpfilesdir}/memspyd.conf
%{_sysusersdir}/memspyd.conf
%{_datadir}/applications/org.memspy.MemSpyUI.desktop
%{_sysconfdir}/xdg/autostart/org.memspy.MemSpyUI.desktop
%{_datadir}/memspy/memspy-ui.css
%{_datadir}/icons/hicolor/scalable/status/memspy-*-symbolic.svg
%{_mandir}/man1/memspy-ui.1*
%{_mandir}/man8/memspyd.8*

%changelog
* Sun Oct 11 2026 MemSpy maintainers <maintainers@invalid.example> - 0.1.0-1
- Initial package

Name:           filelessd
Version:        0.1.0
Release:        1%{?dist}
Summary:        Local eBPF fileless malware detector for GNOME and KDE
License:        LicenseRef-Not-Specified
URL:            https://example.invalid/filelessd
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
%sysusers_create_compat %{_sysusersdir}/filelessd.conf

%post
%systemd_post filelessd.service
systemd-tmpfiles --create %{_tmpfilesdir}/filelessd.conf || :

%preun
%systemd_preun filelessd.service

%postun
%systemd_postun_with_restart filelessd.service

%files
%config(noreplace) %{_sysconfdir}/filelessd/allowlist.conf
%{_bindir}/filelessd
%{_bindir}/fileless-ui
%{_libexecdir}/filelessd/fileless.bpf.o
%{_unitdir}/filelessd.service
%{_tmpfilesdir}/filelessd.conf
%{_sysusersdir}/filelessd.conf
%{_datadir}/applications/org.fileless.DetectorUI.desktop
%{_sysconfdir}/xdg/autostart/org.fileless.DetectorUI.desktop
%{_datadir}/fileless-detector/fileless-ui.css
%{_datadir}/icons/hicolor/scalable/status/fileless-*-symbolic.svg
%{_mandir}/man1/fileless-ui.1*
%{_mandir}/man8/filelessd.8*

%changelog
* Sun Oct 11 2026 Fileless Detector maintainers <maintainers@invalid.example> - 0.1.0-1
- Initial package

%global _missing_build_ids_terminate_build 0
%global _build_id_links none
# Keep the prebuilt Go binary and BPF object byte-for-byte. strip cannot parse BPF objects.
%global __strip /bin/true

Name:           net-scouter
Version:        %{ns_version}
Release:        %{ns_release}
Summary:        Low-overhead IPv4/IPv6 TCP and UDP flow discovery agent
License:        GPL-2.0-only
URL:            https://nexus.manty.co.kr/repository/yum-hosted/net-scouter/
BuildArch:      %{ns_arch}
AutoReqProv:    no

%description
Observes directional IPv4/IPv6 TCP and UDP flows on a Linux host and keeps
packet, byte, and local TCP connection counters in a bounded kernel map.
The package does not enable or start the service. Edit
/etc/net-scouter/net-scouter.yaml, then start net-scouter.service.

%install
rm -rf %{buildroot}
install -d %{buildroot}/usr/bin
install -d %{buildroot}/usr/lib/net-scouter
install -d %{buildroot}/etc/net-scouter
install -d %{buildroot}/usr/lib/systemd/system
install -m 0755 %{_sourcedir}/net-scouter %{buildroot}/usr/bin/net-scouter
install -m 0644 %{_sourcedir}/flow.bpf.o %{buildroot}/usr/lib/net-scouter/flow.bpf.o
install -m 0644 %{_sourcedir}/net-scouter.yaml %{buildroot}/etc/net-scouter/net-scouter.yaml
install -m 0644 %{_sourcedir}/net-scouter.service %{buildroot}/usr/lib/systemd/system/net-scouter.service

%files
%dir /usr/lib/net-scouter
%dir /etc/net-scouter
/usr/bin/net-scouter
/usr/lib/net-scouter/flow.bpf.o
%config(noreplace) /etc/net-scouter/net-scouter.yaml
/usr/lib/systemd/system/net-scouter.service

%post
if [ "$1" -eq 1 ]; then
    systemctl daemon-reload >/dev/null 2>&1 || :
fi

%preun
if [ "$1" -eq 0 ]; then
    systemctl --no-reload disable --now net-scouter.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge 1 ]; then
    systemctl try-restart net-scouter.service >/dev/null 2>&1 || :
fi

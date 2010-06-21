Summary: Sendmail milter for SpamAssassin to Spam Confidence Level conversion
Name: sa2scl-milter
Version: 0.1
Release: 1
License: GPL
Group: System Environment/Daemons
URL: http://emsearcy.org/

Source: https://scm.insightsnow.com/hg/sa2scl-milter/sa2scl-milter-0.1-src.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root

BuildRequires: sendmail-devel, gcc
Requires: /usr/sbin/sendmail

%description
A Sendmail milter (mail filter) daemon that adds X-MS-Exchange-Organization-SCL
headers based on SpamAssassin headers.

%prep
%setup

%{__cat} <<EOF >sa2scl-milter.sysconfig
#SOCKET=/var/run/sa2scl.sock
#EXTRA_FLAGS="-d"
EOF

%build
%{__make} %{?_smp_mflags}

%install
%{__rm} -rf %{buildroot}
%makeinstall
%{__install} -Dp -m0755 sa2scl-milter.init %{buildroot}%{_initrddir}/sa2scl-milter
%{__install} -Dp -m0644 sa2scl-milter.sysconfig %{buildroot}%{_sysconfdir}/sysconfig/sa2scl-milter

%post
/sbin/chkconfig --add sa2scl-milter
/usr/bin/getent group sclmilt >/dev/null || /usr/sbin/groupadd -r sclmilt
/usr/bin/getent passwd sclmilt >/dev/null || /usr/sbin/useradd -r -g sclmilt \
-d /var/lib/sa2scl-milter -s /sbin/nologin -c "Daemon account for sa2scl-milter" sclmilt

%preun
if [ $1 -eq 0 ]; then
    /sbin/service sa2scl-milter stop &>/dev/null || :
    /sbin/chkconfig --del sa2scl-milter
fi

%postun
/sbin/service sa2scl-milter condrestart &>/dev/null || :

%clean
%{__rm} -rf %{buildroot}

%files
%defattr(-, root, root, 0755)
%config(noreplace) %{_sysconfdir}/sysconfig/sa2scl-milter
%config %{_initrddir}/sa2scl-milter
%{_sbindir}/sa2scl-milter

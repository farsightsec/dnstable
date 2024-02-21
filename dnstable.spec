Name:           dnstable
Version:        0.14.0
Release:        1%{?dist}
Summary:        passive DNS encoding format utilities

License:        Apache-2.0
URL:            https://github.com/farsightsec/%{name}
Source0:        https://dl.farsightsecurity.com/dist/%{name}/%{name}-%{version}.tar.gz

BuildRequires:  mtbl-devel >= 1.5.0 wdns-devel >= 0.11.0
Requires:       mtbl wdns

%description
dnstable implements an encoding format for passive DNS data.  It stores
key-value records in Sorted String Table (SSTable) files using MTBL.

This package contains the shared library for libdnstable and the dnstable
command-line tools.

%package devel
Summary:        passive DNS encoding format utilities (development files)
Requires:       %{name}%{?_isa} = %{version}-%{release}

%description devel
dnstable implements an encoding format for passive DNS data.  It stores
key-value records in Sorted String Table (SSTable) files using MTBL.

This package contains the static library, headers, and development
documentation for libdnstable.

%prep
%setup -q

%build
[ -x configure ] || autoreconf -fvi
%configure
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
%make_install

%files
%defattr(-,root,root,-)
%{_libdir}/*.so.*
%exclude %{_libdir}/lib%{name}.la
%_bindir/*
%_mandir/man1/*

%files devel
%{_libdir}/*.so
%{_libdir}/*.a
%{_libdir}/pkgconfig/*
%{_includedir}/*
%_mandir/man3/*
%_mandir/man5/*
%_mandir/man7/*

%doc


%changelog

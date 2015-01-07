#
# spec file for package sg3_utils
#
# Copyright (c) 2013 SUSE LINUX Products GmbH, Nuernberg, Germany.
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via http://bugs.opensuse.org/
#
#
# No patches, this is the maintainer's version for Suse targets.
# Patch lines would appear after the "Source:" line and look like:
#   Patch1:         sg3_utils-1.38r546.patch
# then under the "%setup -q" line there would be one or more lines:
#   %patch1 -p1


Name:           sg3_utils
%define lname	libsgutils2-2
Version:        1.41
Release:        0
Summary:        A collection of tools that send SCSI commands to devices
License:        GPL-2.0+ and BSD-3-Clause
Group:          Hardware/Other
Url:            http://sg.danny.cz/sg/sg3_utils.html

Source:         http://sg.danny.cz/sg/p/%name-%{version}.tar.xz
BuildRoot:      %{_tmppath}/%{name}-%{version}-build
BuildRequires:  xz
Requires(pre):  %insserv_prereq
Provides:       scsi
Provides:       sg_utils
Obsoletes:      scsi <= 1.7_2.38_1.25_0.19_1.02_0.93

%description
The sg3_utils package contains utilities that send SCSI commands to
devices. As well as devices on transports traditionally associated with
SCSI (e.g. Fibre Channel (FCP), Serial Attached SCSI (SAS) and the SCSI
Parallel Interface(SPI)) many other devices use SCSI command sets.
ATAPI cd/dvd drives and SATA disks that connect via a translation layer
or a bridge device are examples of devices that use SCSI command sets.

%package -n %lname
Summary:        Library to hold functions common to the SCSI utilities
License:        BSD-3-Clause
Group:          System/Libraries

%description -n %lname
The sg3_utils package contains utilities that send SCSI commands to
devices. As well as devices on transports traditionally associated with
SCSI (e.g. Fibre Channel (FCP), Serial Attached SCSI (SAS) and the SCSI
Parallel Interface(SPI)) many other devices use SCSI command sets.
ATAPI cd/dvd drives and SATA disks that connect via a translation layer
or a bridge device are examples of devices that use SCSI command sets.

This subpackage contains the library of common sg_utils code, such as
SCSI error processing.

%package -n libsgutils-devel
Summary:        A collection of tools that send SCSI commands to devices
License:        BSD-3-Clause
Group:          Development/Libraries/C and C++
Requires:       %lname = %version
# Added for 13.1
Obsoletes:      %name-devel < %version-%release
Provides:       %name-devel = %version-%release

%description -n libsgutils-devel
The sg3_utils package contains utilities that send SCSI commands to
devices. As well as devices on transports traditionally associated with
SCSI (e.g. Fibre Channel (FCP), Serial Attached SCSI (SAS) and the SCSI
Parallel Interface(SPI)) many other devices use SCSI command sets.
ATAPI cd/dvd drives and SATA disks that connect via a translation layer
or a bridge device are examples of devices that use SCSI command sets.

This subpackage contains libraries and header files for developing
applications that want to make use of libsgutils.

%prep
%setup -q

%build
%configure --disable-static --with-pic
make %{?_smp_mflags}

%install
make install DESTDIR="%buildroot"
install -m 755 scripts/scsi_logging_level $RPM_BUILD_ROOT%{_bindir}
install -m 755 scripts/rescan-scsi-bus.sh $RPM_BUILD_ROOT%{_bindir}
%{__rm} -f %{buildroot}%{_libdir}/*.la

%post   -p /sbin/ldconfig -n %lname

%postun -p /sbin/ldconfig -n %lname

%files
%defattr(-,root,root)
%doc README README.sg_start
%doc ChangeLog CREDITS NEWS
%_bindir/sg_*
%_bindir/scsi_*
%_bindir/sginfo
%_bindir/sgp_dd
%_bindir/sgm_dd
%_bindir/scsi_logging_level
%_bindir/rescan-scsi-bus.sh
%_mandir/man8/*.8*

%files -n %lname
%defattr(-,root,root)
%_libdir/libsgutils2.so.2*

%files -n libsgutils-devel
%defattr(-,root,root)
%_libdir/libsgutils2.so
%_includedir/scsi/

%changelog

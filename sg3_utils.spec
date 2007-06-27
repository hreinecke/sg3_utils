%define	name	sg3_utils
%define	version	1.15
%define	release	1

%define	major	1
%define	minor	0
%define libname	%{_lib}sgutils-%{major}_%{minor}

Summary:	Utilities for SCSI devices in Linux
Name:		%{name}
Version:	%{version}
Release:	%{release}
License:	GPL/FreeBSD
Group:		Utilities/System
URL:		http://www.torque.net/sg/u_index.html
Source0:	http://www.torque.net/sg/p/%{name}-%{version}.tgz
BuildRoot:	%{_tmppath}/%{name}-%{version}-root
Packager:	Douglas Gilbert <dgilbert at interlog dot com>

%description
Collection of Linux utilities for devices that use the SCSI command set.
Includes utilities to copy data based on "dd" syntax and semantics (called
sg_dd, sgp_dd and sgm_dd); check INQUIRY data and VPD pages (sg_inq); check
mode and log pages (sginfo, sg_modes and sg_logs); spin up and down
disks (sg_start); do self tests (sg_senddiag); and various other functions.
See the README, CHANGELOG and COVERAGE files. Requires the linux kernel 2.4
series or later. In the 2.4 series SCSI generic device names (e.g. /dev/sg0)
must be used. In the 2.6 series other device names may be used as
well (e.g. /dev/sda).

Warning: Some of these tools access the internals of your system
and the incorrect usage of them may render your system inoperable.

%package -n	%{libname}
Summary:	Shared library for %{name}
Group:          System/Libraries

%description -n	%{libname}
This package contains the shared library for %{name}.

%package -n	%{libname}-devel
Summary:	Static library and header files for the sgutils library
Group:		Development/C
Obsoletes:	%{name}-devel
Provides:	%{name}-devel
Provides:	libsgutils-devel
Requires:	%{libname} = %{version}-%{release}

%description -n	%{libname}-devel
This package contains the static sgutils library and its header
files.

%prep

%setup -q

%build

make \
     CFLAGS="%{optflags} -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64" \
     LIBDIR="%{_libdir}"

%install
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

make install \
 	PREFIX=%{_prefix} \
 	LIBDIR=%{buildroot}/%{_libdir} \
 	INSTDIR=%{buildroot}/%{_bindir} \
 	MANDIR=%{buildroot}/%{_mandir} \
	INCLUDEDIR=%{buildroot}/%{_includedir} \
	LIB_VINFO=1:0:0

%post -n %{libname} -p /sbin/ldconfig

%postun -n %{libname} -p /sbin/ldconfig

%clean
[ "%{buildroot}" != "/" ] && rm -rf %{buildroot}

%files
%defattr(-,root,root)
%doc CHANGELOG COVERAGE CREDITS INSTALL README README.sg_start
%attr(0755,root,root) %{_bindir}/*
%{_mandir}/man8/*

%files -n %{libname}
%defattr(-,root,root)
%{_libdir}/*.so.*

%files -n %{libname}-devel
%defattr(-,root,root)
%{_includedir}/scsi/*.h
%{_libdir}/*.so
%{_libdir}/*.a
%{_libdir}/*.la

%changelog
* Sun Jun 05 2005 - dgilbert at interlog dot com
- use O_NONBLOCK on all fds that use SG_IO ioctl
  * sg3_utils-1.15

* Fri May 06 2005 - dgilbert at interlog dot com
- produce libsgutils (+ -devel variant) as well as sg3_utils binary rpm
  * sg3_utils-1.14

* Sun Mar 13 2005 - dgilbert at interlog dot com
- add sg_format, sg_dd extensions
  * sg3_utils-1.13

* Fri Jan 21 2005 - dgilbert at interlog dot com
- add sg_wr_mode, sg_rtpg + sg_reassign; sginfo sas tweaks
  * sg3_utils-1.12

* Fri Nov 26 2004 - dgilbert at interlog dot com
- add sg_sync, sg_prevent and sg_get_config; fix sg_requests
  * sg3_utils-1.11

* Sat Oct 30 2004 - dgilbert at interlog dot com
- fix read capacity (10+16), add sg_luns
  * sg3_utils-1.10

* Thu Oct 21 2004 - dgilbert at interlog dot com
- sg_requests, sg_ses, sg_verify, libsgutils(sg_lib.c+sg_cmds.c), devel rpm
  * sg3_utils-1.09

* Tue Aug 31 2004 - dgilbert at interlog dot com
- 'register+move' in sg_persist, sg_opcodes sorts, sg_write_long
  * sg3_utils-1.08

* Thu Jul 08 2004 - dgilbert at interlog dot com
- add '-fHead' to sginfo, '-i' for sg_inq, new sg_opcodes + sg_persist
  * sg3_utils-1.07

* Mon Apr 26 2004 - dgilbert at interlog dot com
- sg3_utils.spec for mandrake; more sginfo work, sg_scan, sg_logs
  * sg3_utils-1.06

* Wed Nov 12 2003 - dgilbert at interlog dot com
- sg_readcap: sizes; sg_logs: double fetch; sg_map 256 sg devices; sginfo
  * sg3_utils-1.05

* Tue May 13 2003 - dgilbert at interlog dot com
- default sg_turs '-n=' to 1, sg_logs gets '-t' for temperature, CREDITS
  * sg3_utils-1.04

* Wed Apr 02 2003 - dgilbert at interlog dot com
- 6 byte CDBs for sg_modes, sg_start on block devs, sg_senddiag, man pages
  * sg3_utils-1.03

* Wed Jan 01 2003 - dgilbert at interlog dot com
- interwork with block SG_IO, fix in sginfo, '-t' for sg_turs
  * sg3_utils-1.02

* Wed Aug 14 2002 - dgilbert at interlog dot com
- raw switch in sg_inq
  * sg3_utils-1.01

* Sun Jul 28 2002 - dgilbert at interlog dot com
- decode sg_logs pages, add dio to sgm_dd, drop "gen=1" arg, "of=/dev/null"
  * sg3_utils-1.00

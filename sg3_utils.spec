Summary: Utilities for devices that use SCSI command sets
Name: sg3_utils
Version: 1.36
# Release: 1%{?dist}
Release: 1
License: GPL
Group: Utilities/System
Source: ftp://sg.danny.cz/sg/p/sg3_utils-%{version}.tgz
Url: http://sg.danny.cz/sg/sg3_utils.html
Provides: sg_utils
BuildRequires: libtool
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Packager: Douglas Gilbert <dgilbert@interlog.com>

%description
Collection of Linux utilities for devices that use the SCSI command set.
Includes utilities to copy data based on "dd" syntax and semantics (called
sg_dd, sgp_dd and sgm_dd); check INQUIRY data and VPD pages (sg_inq); check
mode and log pages (sginfo, sg_modes and sg_logs); spin up and down
disks (sg_start); do self tests (sg_senddiag); and various other functions.
See the README, ChangeLog and COVERAGE files. Requires the linux kernel 2.4
series or later. In the 2.4 series SCSI generic device names (e.g. /dev/sg0)
must be used. In the 2.6 series other device names may be used as
well (e.g. /dev/sda).

Warning: Some of these tools access the internals of your system
and the incorrect usage of them may render your system inoperable.

%package libs
Summary: Shared library for %{name}
Group: System/Libraries

%description libs
This package contains the shared library for %{name}.

%package devel
Summary: Static library and header files for the sgutils library
Group: Development/C
Requires: %{name}-libs = %{version}-%{release}

%description devel
This package contains the static %{name} library and its header files for
developing applications.

%prep
%setup -q

%build
%configure

%install
if [ "$RPM_BUILD_ROOT" != "/" ]; then
        rm -rf $RPM_BUILD_ROOT
fi

make install \
        DESTDIR=$RPM_BUILD_ROOT

%clean
if [ "$RPM_BUILD_ROOT" != "/" ]; then
        rm -rf $RPM_BUILD_ROOT
fi

%files
%defattr(-,root,root)
%doc AUTHORS ChangeLog COPYING COVERAGE CREDITS INSTALL NEWS README README.sg_start
%attr(755,root,root) %{_bindir}/*
%{_mandir}/man8/*

%files libs
%defattr(-,root,root)
%{_libdir}/*.so.*

%files devel
%defattr(-,root,root)
%{_includedir}/scsi/*.h
%{_libdir}/*.so
%{_libdir}/*.a
%{_libdir}/*.la

%changelog
* Tue Mar 12 2013 - dgilbert at interlog dot com
- track t10 changes
  * sg3_utils-1.36

* Thu Jan 17 2013 - dgilbert at interlog dot com
- add sg_compare_and_write, track t10 changes
  * sg3_utils-1.35

* Sat Oct 13 2012 - dgilbert at interlog dot com
- add sg_xcopy and sg_copy_results; track t10 changes
  * sg3_utils-1.34

* Wed Jan 18 2012 - dgilbert at interlog dot com
- track t10 changes
  * sg3_utils-1.33

* Wed Jun 22 2011 - dgilbert at interlog dot com
- track t10 changes
  * sg3_utils-1.32

* Wed Feb 16 2011 - dgilbert at interlog dot com
- add sg_decode_sense; track t10 changes
  * sg3_utils-1.31

* Fri Nov 05 2010 - dgilbert at interlog dot com
- add sg_referrals; track t10 changes
  * sg3_utils-1.30

* Wed Mar 31 2010 - dgilbert at interlog dot com
- track t10 changes
  * sg3_utils-1.29

* Fri Oct 02 2009 - dgilbert at interlog dot com
- add sg_get_lba_status, sg_unmap, sg_read_block_limits
  * sg3_utils-1.28

* Sat Apr 11 2009 - dgilbert at interlog dot com
- add sg_write_same; sg_dd split; spc4r18 sync
  * sg3_utils-1.27

* Wed Jun 25 2008 - dgilbert at interlog dot com
- add sg_sat_phy_event, sync with drafts prior to this date
  * sg3_utils-1.26

* Tue Oct 16 2007 - dgilbert at interlog dot com
- add sg_sat_set_features, sg_stpg, sg_safte; sg_dd oflag=sparse,null
  * sg3_utils-1.25

* Mon May 07 2007 - dgilbert at interlog dot com
- add sg_raw; sg_rtpg, sg_log, sg_inq and sg_format updates
  * sg3_utils-1.24

* Wed Jan 31 2007 - dgilbert at interlog dot com
- add sg_read_buffer + sg_write_buffer
  * sg3_utils-1.23

* Mon Oct 16 2006 - dgilbert at interlog dot com
- add sg_sat_identify, expand sg_format and sg_requests
  * sg3_utils-1.22

* Thu Jul 06 2006 - dgilbert at interlog dot com
- add sg_vpd and sg_rdac, uniform exit statuses
  * sg3_utils-1.21

* Tue Apr 18 2006 - dgilbert at interlog dot com
- sg_logs: sas port specific page decoding, sg*_dd updates
  * sg3_utils-1.20

* Fri Jan 27 2006 - dgilbert at interlog dot com
- sg_get_config: resync features with mmc5 rev 1
  * sg3_utils-1.19

* Fri Nov 18 2005 - dgilbert at interlog dot com
- add sg_map26; sg_inq '-rr' option to play with hdparm
  * sg3_utils-1.18

* Thu Sep 22 2005 - dgilbert at interlog dot com
- add ATA information VPD page to sg_inq
  * sg3_utils-1.17

* Wed Aug 10 2005 - dgilbert at interlog dot com
- add sg_ident, sg_inq VPD page extensions
  * sg3_utils-1.16

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

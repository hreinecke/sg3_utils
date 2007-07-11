Summary: Utilities for devices that use SCSI command sets
Name: sg3_utils
Version: 1.25
Release: 1
Packager: Douglas Gilbert <dgilbert at interlog dot com>
License: GPL/FreeBSD
Group: Utilities/System
Source: ftp://www.torque.net/sg/p/sg3_utils-%{version}.tgz
Url: http://www.torque.net/sg/sg3_utils.html
Provides: sg_utils
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root/

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

Warning: Some of these tools access the internals of your system and their
incorrect usage may render your system inoperable.

Authors:
--------
    Doug Gilbert <dgilbert at interlog dot com>
    See CREDITS file

%prep
%setup

%build
make

%install
if [ "$RPM_BUILD_ROOT" != "/" ]; then
        rm -rf $RPM_BUILD_ROOT
fi
make install INSTDIR=$RPM_BUILD_ROOT/usr/bin MANDIR=$RPM_BUILD_ROOT/usr/share/man

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(-,root,root) %doc CREDITS README README.sg_start
%attr(-,root,root) %doc CHANGELOG INSTALL COVERAGE COPYING
%attr(755,root,root) %{_bindir}/sg_dd
%attr(755,root,root) %{_bindir}/sg_inq
%attr(755,root,root) %{_bindir}/sg_scan
%attr(755,root,root) %{_bindir}/sg_rbuf
%attr(755,root,root) %{_bindir}/sginfo
%attr(755,root,root) %{_bindir}/sg_readcap
%attr(755,root,root) %{_bindir}/sgp_dd
%attr(755,root,root) %{_bindir}/sg_map
%attr(755,root,root) %{_bindir}/sg_turs
%attr(755,root,root) %{_bindir}/sg_test_rwbuf
%attr(755,root,root) %{_bindir}/sg_start
%attr(755,root,root) %{_bindir}/sgm_dd
%attr(755,root,root) %{_bindir}/sg_read
%attr(755,root,root) %{_bindir}/sg_reset
%attr(755,root,root) %{_bindir}/sg_modes
%attr(755,root,root) %{_bindir}/sg_logs
%attr(755,root,root) %{_bindir}/sg_senddiag
%attr(755,root,root) %{_bindir}/sg_opcodes
%attr(755,root,root) %{_bindir}/sg_persist
%attr(755,root,root) %{_bindir}/sg_write_long
%attr(755,root,root) %{_bindir}/sg_read_long
%attr(755,root,root) %{_bindir}/sg_requests
%attr(755,root,root) %{_bindir}/sg_ses
%attr(755,root,root) %{_bindir}/sg_verify
%attr(755,root,root) %{_bindir}/sg_emc_trespass
%attr(755,root,root) %{_bindir}/sg_luns
%attr(755,root,root) %{_bindir}/sg_sync
%attr(755,root,root) %{_bindir}/sg_prevent
%attr(755,root,root) %{_bindir}/sg_get_config
%attr(755,root,root) %{_bindir}/sg_wr_mode
%attr(755,root,root) %{_bindir}/sg_rtpg
%attr(755,root,root) %{_bindir}/sg_reassign
%attr(755,root,root) %{_bindir}/sg_format
%attr(755,root,root) %{_bindir}/sg_rmsn
%attr(755,root,root) %{_bindir}/sg_ident
%attr(755,root,root) %{_bindir}/sg_map26
%attr(755,root,root) %{_bindir}/sg_vpd
%attr(755,root,root) %{_bindir}/sg_rdac
%attr(755,root,root) %{_bindir}/sg_sat_identify
%attr(755,root,root) %{_bindir}/sg_read_buffer
%attr(755,root,root) %{_bindir}/sg_write_buffer
%attr(755,root,root) %{_bindir}/sg_raw
# Mandrake compresses man pages with bzip2, RedHat with gzip
%attr(-,root,root) %doc %{_mandir}/man8/sg_dd.8*
%attr(-,root,root) %doc %{_mandir}/man8/sgp_dd.8*
%attr(-,root,root) %doc %{_mandir}/man8/sgm_dd.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_read.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_map.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_scan.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_rbuf.8*
%attr(-,root,root) %doc %{_mandir}/man8/sginfo.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_readcap.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_turs.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_inq.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_test_rwbuf.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_start.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_reset.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_modes.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_logs.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_senddiag.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_opcodes.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_persist.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_write_long.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_read_long.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_requests.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_ses.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_verify.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_emc_trespass.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_luns.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_sync.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_prevent.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_get_config.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_wr_mode.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_rtpg.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_reassign.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_format.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_rmsn.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_ident.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_map26.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_vpd.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_rdac.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_sat_identify.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_read_buffer.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_write_buffer.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg_raw.8*
%attr(-,root,root) %doc %{_mandir}/man8/sg3_utils.8*
 

%changelog
* Wed Jul 11 2007 - dgilbert at interlog dot com
- sg_dd oflag=sparse,null
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
- add sg_map26, sg_inq: '-rr' option to play with hdparm
  * sg3_utils-1.18

* Thu Sep 22 2005 - dgilbert at interlog dot com
- add ATA information VPD page
  * sg3_utils-1.17

* Wed Aug 10 2005 - dgilbert at interlog dot com
- add sg_ident, sg_inq VPD page extensions
  * sg3_utils-1.16

* Sun Jun 05 2005 - dgilbert at interlog dot com
- use O_NONBLOCK on all fds that use SG_IO iotcl
  * sg3_utils-1.15

* Fri May 06 2005 - dgilbert at interlog dot com
- add sg_rmsn; sg_ses update to SES-2 rev 11
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

* Tue Oct 26 2004 - dgilbert at interlog dot com
- read_capacity (10+16) fix, add sg_luns
  * sg3_utils-1.10

* Thu Oct 21 2004 - dgilbert at interlog dot com
- sg_requests, sg_ses, sg_verify, sg_err->sg_lib
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

* Sun Mar 17 2002 - dgilbert at interlog dot com
- add sg_modes+sg_logs for sense pages, expand sg_inq, add fua+sync to sg_dd++
  * sg3_utils-0.99

* Sat Feb 16 2002 - dgilbert at interlog dot com
- resurrect sg_reset; snprintf cleanup, time,gen+cdbsz args to sg_dd++
  * sg3_utils-0.98

* Sun Dec 23 2001 - dgilbert at interlog dot com
- move isosize to archive directory; now found in util-linux-2.10s and later
  * sg3_utils-0.97

* Fri Dec 21 2001 - dgilbert at interlog dot com
- add sgm_dd, sg_read, sg_simple4 and sg_simple16 [add mmap-ed IO support]
  * sg3_utils-0.96

* Sun Sep 15 2001 - dgilbert at interlog dot com
- sg_map can do inquiry; sg_dd, sgp_dd + sgq_dd dio help
  * sg3_utils-0.95

* Sun Apr 19 2001 - dgilbert at interlog dot com
- add sg_start, improve sginfo and sg_map [Kurt Garloff]
  * sg3_utils-0.94

* Sun Mar 5 2001 - dgilbert at interlog dot com
- add scsi_devfs_scan, add sg_include.h, 'coe' more general in sgp_dd
  * sg3_utils-0.93

* Tue Jan 16 2001 - dgilbert at interlog dot com
- clean sg_err.h include dependencies, bug fixes, Makefile in archive directory
  * sg3_utils-0.92

* Mon Dec 21 2000 - dgilbert at interlog dot com
- signals for sg_dd, man pages and additions for sg_rbuf and isosize
  * sg3_utils-0.91

* Mon Dec 11 2000 - dgilbert at interlog dot com
- Initial version of package
  * sg3_utils-0.90

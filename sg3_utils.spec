#
# spec file for sg3_utils
# 
# please send bugfixes or comments to dgilbert@interlog.com
#

Summary: Utils for Linux's SCSI generic driver devices + raw devices
Name: sg3_utils
Version: 1.03
Release: 1
Packager: dgilbert@interlog.com
License: GPL
Group: Utilities/System
Source: ftp://www.torque.net/sg/p/sg3_utils-1.03.tgz
Url: http://www.torque.net/sg/u_index.html
Provides: sg_utils

%description
Collection of small useful tools, that are based on the Linux SCSI generic
(sg) interface and give info on the SCSI bus, copy data,... The utilities
to copy data are based on the Unix dd command and are called sg_dd, sgp_dd
and sgm_dd. These 3 commands can also act on raw devices (e.g. /dev/raw/raw1).

Warning: Some of these tools access the internals of your system and the
incorrect usage of them may render your system inoperable.

Authors:
--------
    Doug Gilbert <dgilbert@interlog.com>
    Kurt Garloff <garloff@suse.de>  [sg_test_rwbuff]
    Peter Allworth  [contribution to sg_dd and sgp_dd]
    Martin Schwenke <martin@meltin.net> [contribution to sg_inq]

%prep
%setup

%build
make

%install
make install INSTDIR=%{_bindir} MANDIR=%{_mandir}

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%attr(-,root,root) %doc README README.sg_start CHANGELOG INSTALL
%attr(755,root,root) %{_bindir}/sg_dd
%attr(755,root,root) %{_bindir}/sg_debug
%attr(755,root,root) %{_bindir}/sg_inq
%attr(755,root,root) %{_bindir}/sg_scan
%attr(755,root,root) %{_bindir}/sg_rbuf
%attr(755,root,root) %{_bindir}/sginfo
%attr(755,root,root) %{_bindir}/sg_simple1
%attr(755,root,root) %{_bindir}/sg_simple2
%attr(755,root,root) %{_bindir}/sg_simple3
%attr(755,root,root) %{_bindir}/sg_simple4
%attr(755,root,root) %{_bindir}/sg_simple16
%attr(755,root,root) %{_bindir}/sg_readcap
%attr(755,root,root) %{_bindir}/scsi_inquiry
%attr(755,root,root) %{_bindir}/sgp_dd
%attr(755,root,root) %{_bindir}/sg_map
%attr(755,root,root) %{_bindir}/sg_turs
%attr(755,root,root) %{_bindir}/sg_test_rwbuf
%attr(755,root,root) %{_bindir}/scsi_devfs_scan
%attr(755,root,root) %{_bindir}/sg_start
%attr(755,root,root) %{_bindir}/sgm_dd
%attr(755,root,root) %{_bindir}/sg_read
%attr(755,root,root) %{_bindir}/sg_reset
%attr(755,root,root) %{_bindir}/sg_modes
%attr(755,root,root) %{_bindir}/sg_logs
%attr(755,root,root) %{_bindir}/sg_senddiag
%attr(-,root,root) %doc %{_mandir}/man8/sg_dd.8.gz
%attr(-,root,root) %doc %{_mandir}/man8/sgp_dd.8.gz
%attr(-,root,root) %doc %{_mandir}/man8/sgm_dd.8.gz
%attr(-,root,root) %doc %{_mandir}/man8/sg_read.8.gz
%attr(-,root,root) %doc %{_mandir}/man8/sg_map.8.gz
%attr(-,root,root) %doc %{_mandir}/man8/sg_rbuf.8.gz
%attr(-,root,root) %doc %{_mandir}/man8/sg_inq.8.gz
%attr(-,root,root) %doc %{_mandir}/man8/sg_modes.8.gz
%attr(-,root,root) %doc %{_mandir}/man8/sg_logs.8.gz
%attr(-,root,root) %doc %{_mandir}/man8/sg_senddiag.8.gz
 

%changelog
* Wed Apr 02 2003 - dgilbert@interlog.com
- 6 byte CDBs for sg_modes, sg_start on block devs, sg_senddiag, man pages
  * sg3_utils-1.03
* Wed Jan 01 2003 - dgilbert@interlog.com
- interwork with block SG_IO, fix in sginfo, '-t' for sg_turs
  * sg3_utils-1.02
* Wed Aug 14 2002 - dgilbert@interlog.com
- raw switch in sg_inq
  * sg3_utils-1.01
* Sun Jul 28 2002 - dgilbert@interlog.com
- decode sg_logs pages, add dio to sgm_dd, drop "gen=1" arg, "of=/dev/null"
  * sg3_utils-1.00
* Sun Mar 17 2002 - dgilbert@interlog.com
- add sg_modes+sg_logs for sense pages, expand sg_inq, add fua+sync to sg_dd++
  * sg3_utils-0.99
* Sat Feb 16 2002 - dgilbert@interlog.com
- resurrect sg_reset; snprintf cleanup, time,gen+cdbsz args to sg_dd++
  * sg3_utils-0.98
* Sun Dec 23 2001 - dgilbert@interlog.com
- move isosize to archive directory; now found in util-linux-2.10s and later
  * sg3_utils-0.97
* Fri Dec 21 2001 - dgilbert@interlog.com
- add sgm_dd, sg_read, sg_simple4 and sg_simple16 [add mmap-ed IO support]
  * sg3_utils-0.96
* Sun Sep 15 2001 - dgilbert@interlog.com
- sg_map can do inquiry; sg_dd, sgp_dd + sgq_dd dio help
  * sg3_utils-0.95
* Sun Apr 19 2001 - dgilbert@interlog.com
- add sg_start, improve sginfo and sg_map [Kurt Garloff]
  * sg3_utils-0.94
* Sun Mar 5 2001 - dgilbert@interlog.com
- add scsi_devfs_scan, add sg_include.h, 'coe' more general in sgp_dd
  * sg3_utils-0.93
* Tue Jan 16 2001 - dgilbert@interlog.com
- clean sg_err.h include dependencies, bug fixes, Makefile in archive directory
  * sg3_utils-0.92
* Mon Dec 21 2000 - dgilbert@interlog.com
- signals for sg_dd, man pages and additions for sg_rbuf and isosize
  * sg3_utils-0.91
* Mon Dec 11 2000 - dgilbert@interlog.com
- Initial creation of package, containing
  * sg3_utils-0.90

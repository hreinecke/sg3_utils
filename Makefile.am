# SUBDIRS = src
EXTRA_DIST=autogen.sh

scsiincludedir      = $(includedir)/scsi

if OS_LINUX

# sg_dd, sg_emc_trespass(?), sginfo, sg_map26, sg_map, sgm_dd, sgp_dd,
# sg_rbuf, sg_read, sg_reset, sg_test_rwbuf
# are Linux only utilities
#
# sg_scan is shared by Linux and Win32

bin_PROGRAMS = \
	sg_dd sg_emc_trespass sg_format sg_get_config sg_ident \
	sginfo sg_inq sg_logs sg_luns sg_map26 sg_map \
	sgm_dd sg_modes sg_opcodes sgp_dd sg_persist \
	sg_prevent sg_raw sg_rbuf sg_rdac sg_read sg_readcap \
	sg_read_long sg_reassign sg_requests sg_reset sg_rmsn \
	sg_rtpg sg_sat_identify sg_scan sg_senddiag sg_ses \
	sg_start sg_sync sg_test_rwbuf sg_turs sg_verify \
	sg_vpd sg_write_buffer sg_write_long sg_wr_mode

man_MANS = \
	sg_dd.8 sg_emc_trespass.8 sg_format.8 sg_get_config.8 sg_ident.8 \
	sginfo.8 sg_inq.8 sg_logs.8 sg_luns.8 sg_map26.8 sg_map.8 \
	sgm_dd.8 sg_modes.8 sg_opcodes.8 sgp_dd.8 sg_persist.8 \
	sg_prevent.8 sg_raw.8 sg_rbuf.8 sg_rdac.8 sg_read.8 sg_readcap.8 \
	sg_read_long.8 sg_reassign.8 sg_requests.8 sg_reset.8 sg_rmsn.8 \
	sg_rtpg.8 sg_sat_identify.8 sg_scan.8 sg_senddiag.8 sg_ses.8 \
	sg_start.8 sg_sync.8 sg_test_rwbuf.8 sg_turs.8 sg_verify.8 \
	sg_vpd.8 sg_write_buffer.8 sg_write_long.8 sg_wr_mode.8

libsgutils_la_SOURCES = \
	sg_lib.c sg_lib.h \
	sg_cmds_basic.c sg_cmds_basic.h \
	sg_cmds_extra.c sg_cmds_extra.h \
	sg_pt.h \
	sg_pt_linux.c

EXTRA_libsgutils_la_SOURCES = \
	sg_linux_inc.h \
	sg_pt_freebsd.c \
	sg_pt_osf1.c \
	sg_pt_win32.c sg_pt_win32.h \
	getopt_long.c port_getopt.h

scsiinclude_HEADERS = \
	sg_lib.h \
	sg_cmds.h \
	sg_cmds_basic.h \
	sg_cmds_extra.h \
	sg_pt.h \
	sg_linux_inc.h \
	sg_io_linux.h
	
noinst_HEADERS = \
	sg_pt_win32.h

endif


if OS_WIN32_MINGW

bin_PROGRAMS = \
	sg_format sg_get_config sg_ident \
	sg_inq sg_logs sg_luns \
	sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap \
	sg_read_long sg_reassign sg_requests sg_rmsn \
	sg_rtpg sg_sat_identify sg_scan sg_senddiag sg_ses \
	sg_start sg_sync sg_turs sg_verify \
	sg_vpd sg_write_buffer sg_write_long sg_wr_mode

man_MANS = \
	sg_format.8 sg_get_config.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 \
	sg_modes.8 sg_opcodes.8 sg_persist.8 \
	sg_prevent.8 sg_raw.8 sg_rdac.8 sg_readcap.8 \
	sg_read_long.8 sg_reassign.8 sg_requests.8 sg_rmsn.8 \
	sg_rtpg.8 sg_sat_identify.8 sg_scan.8 sg_senddiag.8 sg_ses.8 \
	sg_start.8 sg_sync.8 sg_turs.8 sg_verify.8 \
	sg_vpd.8 sg_write_buffer.8 sg_write_long.8 sg_wr_mode.8

libsgutils_la_SOURCES = \
	sg_lib.c sg_lib.h \
	sg_cmds_basic.c sg_cmds_basic.h \
	sg_cmds_extra.c sg_cmds_extra.h \
	sg_pt.h \
	sg_pt_win32.c sg_pt_win32.h

EXTRA_libsgutils_la_SOURCES = \
	sg_pt_linux.c \
	sg_linux_inc.h \
	sg_pt_freebsd.c \
	sg_pt_osf1.c \
	getopt_long.c port_getopt.h

scsiinclude_HEADERS = \
	sg_lib.h \
	sg_cmds.h \
	sg_cmds_basic.h \
	sg_cmds_extra.h \
	sg_pt.h \
	sg_pt_win32.h
	
noinst_HEADERS = \
	sg_linux_inc.h \
	sg_io_linux.h

endif


if OS_WIN32_CYGWIN

bin_PROGRAMS = \
	sg_format sg_get_config sg_ident \
	sg_inq sg_logs sg_luns \
	sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap \
	sg_read_long sg_reassign sg_requests sg_rmsn \
	sg_rtpg sg_sat_identify sg_scan sg_senddiag sg_ses \
	sg_start sg_sync sg_turs sg_verify \
	sg_vpd sg_write_buffer sg_write_long sg_wr_mode

man_MANS = \
	sg_format.8 sg_get_config.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 \
	sg_modes.8 sg_opcodes.8 sg_persist.8 \
	sg_prevent.8 sg_raw.8 sg_rdac.8 sg_readcap.8 \
	sg_read_long.8 sg_reassign.8 sg_requests.8 sg_rmsn.8 \
	sg_rtpg.8 sg_sat_identify.8 sg_scan.8 sg_senddiag.8 sg_ses.8 \
	sg_start.8 sg_sync.8 sg_turs.8 sg_verify.8 \
	sg_vpd.8 sg_write_buffer.8 sg_write_long.8 sg_wr_mode.8

libsgutils_la_SOURCES = \
	sg_lib.c sg_lib.h \
	sg_cmds_basic.c sg_cmds_basic.h \
	sg_cmds_extra.c sg_cmds_extra.h \
	sg_pt.h \
	sg_pt_win32.c sg_pt_win32.h

EXTRA_libsgutils_la_SOURCES = \
	sg_pt_linux.c \
	sg_linux_inc.h \
	sg_pt_freebsd.c \
	sg_pt_osf1.c \
	getopt_long.c port_getopt.h

scsiinclude_HEADERS = \
	sg_lib.h \
	sg_cmds.h \
	sg_cmds_basic.h \
	sg_cmds_extra.h \
	sg_pt.h \
	sg_pt_win32.h
	
noinst_HEADERS = \
	sg_linux_inc.h \
	sg_io_linux.h

endif


if OS_FREEBSD

bin_PROGRAMS = \
	sg_format sg_get_config sg_ident \
	sg_inq sg_logs sg_luns \
	sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap \
	sg_read_long sg_reassign sg_requests sg_rmsn \
	sg_rtpg sg_sat_identify sg_senddiag sg_ses \
	sg_start sg_sync sg_turs sg_verify \
	sg_vpd sg_write_buffer sg_write_long sg_wr_mode

man_MANS = \
	sg_format.8 sg_get_config.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 \
	sg_modes.8 sg_opcodes.8 sg_persist.8 \
	sg_prevent.8 sg_raw.8 sg_rdac.8 sg_readcap.8 \
	sg_read_long.8 sg_reassign.8 sg_requests.8 sg_rmsn.8 \
	sg_rtpg.8 sg_sat_identify.8 sg_senddiag.8 sg_ses.8 \
	sg_start.8 sg_sync.8 sg_turs.8 sg_verify.8 \
	sg_vpd.8 sg_write_buffer.8 sg_write_long.8 sg_wr_mode.8

libsgutils_la_SOURCES = \
	sg_lib.c sg_lib.h \
	sg_cmds_basic.c sg_cmds_basic.h \
	sg_cmds_extra.c sg_cmds_extra.h \
	sg_pt.h \
	sg_pt_freebsd.c

EXTRA_libsgutils_la_SOURCES = \
	sg_pt_linux.c \
	sg_linux_inc.h \
	sg_pt_osf1.c \
	sg_pt_win32.c sg_pt_win32.h \
	getopt_long.c port_getopt.h

scsiinclude_HEADERS = \
	sg_lib.h \
	sg_cmds.h \
	sg_cmds_basic.h \
	sg_cmds_extra.h \
	sg_pt.h
	
noinst_HEADERS = \
	sg_linux_inc.h \
	sg_io_linux.h \
	sg_pt_win32.h

endif


if OS_SOLARIS

bin_PROGRAMS = \
	sg_format sg_get_config sg_ident \
	sg_inq sg_logs sg_luns \
	sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap \
	sg_read_long sg_reassign sg_requests sg_rmsn \
	sg_rtpg sg_sat_identify sg_senddiag sg_ses \
	sg_start sg_sync sg_turs sg_verify \
	sg_vpd sg_write_buffer sg_write_long sg_wr_mode

man_MANS = \
	sg_format.8 sg_get_config.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 \
	sg_modes.8 sg_opcodes.8 sg_persist.8 \
	sg_prevent.8 sg_raw.8 sg_rdac.8 sg_readcap.8 \
	sg_read_long.8 sg_reassign.8 sg_requests.8 sg_rmsn.8 \
	sg_rtpg.8 sg_sat_identify.8 sg_senddiag.8 sg_ses.8 \
	sg_start.8 sg_sync.8 sg_turs.8 sg_verify.8 \
	sg_vpd.8 sg_write_buffer.8 sg_write_long.8 sg_wr_mode.8

libsgutils_la_SOURCES = \
	sg_lib.c sg_lib.h \
	sg_cmds_basic.c sg_cmds_basic.h \
	sg_cmds_extra.c sg_cmds_extra.h \
	sg_pt.h \
	sg_pt_freebsd.c

EXTRA_libsgutils_la_SOURCES = \
	sg_pt_linux.c \
	sg_linux_inc.h \
	sg_pt_osf1.c \
	sg_pt_win32.c sg_pt_win32.h \
	getopt_long.c port_getopt.h

scsiinclude_HEADERS = \
	sg_lib.h \
	sg_cmds.h \
	sg_cmds_basic.h \
	sg_cmds_extra.h \
	sg_pt.h
	
noinst_HEADERS = \
	sg_linux_inc.h \
	sg_io_linux.h \
	sg_pt_win32.h

endif


if OS_OSF

bin_PROGRAMS = \
	sg_format sg_get_config sg_ident \
	sg_inq sg_logs sg_luns \
	sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap \
	sg_read_long sg_reassign sg_requests sg_rmsn \
	sg_rtpg sg_sat_identify sg_senddiag sg_ses \
	sg_start sg_sync sg_turs sg_verify \
	sg_vpd sg_write_buffer sg_write_long sg_wr_mode

man_MANS = \
	sg_format.8 sg_get_config.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 \
	sg_modes.8 sg_opcodes.8 sg_persist.8 \
	sg_prevent.8 sg_raw.8 sg_rdac.8 sg_readcap.8 \
	sg_read_long.8 sg_reassign.8 sg_requests.8 sg_rmsn.8 \
	sg_rtpg.8 sg_sat_identify.8 sg_senddiag.8 sg_ses.8 \
	sg_start.8 sg_sync.8 sg_turs.8 sg_verify.8 \
	sg_vpd.8 sg_write_buffer.8 sg_write_long.8 sg_wr_mode.8

libsgutils_la_SOURCES = \
	sg_lib.c sg_lib.h \
	sg_cmds_basic.c sg_cmds_basic.h \
	sg_cmds_extra.c sg_cmds_extra.h \
	sg_pt.h \
	sg_pt_freebsd.c

EXTRA_libsgutils_la_SOURCES = \
	sg_pt_linux.c \
	sg_linux_inc.h \
	sg_pt_osf1.c \
	sg_pt_win32.c sg_pt_win32.h \
	getopt_long.c port_getopt.h

scsiinclude_HEADERS = \
	sg_lib.h \
	sg_cmds.h \
	sg_cmds_basic.h \
	sg_cmds_extra.h \
	sg_pt.h
	
noinst_HEADERS = \
	sg_linux_inc.h \
	sg_io_linux.h \
	sg_pt_win32.h

endif


AM_CFLAGS = -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -W
# AM_CFLAGS = -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -W -pedantic -std=c99

lib_LTLIBRARIES = libsgutils.la

libsgutils_la_LDFLAGS = -version-info 1:0:0

libsgutils_la_LIBADD = @GETOPT_O_FILES@ @os_libs@
libsgutils_la_DEPENDENCIES = @GETOPT_O_FILES@


sg_dd_SOURCES =	sg_dd.c sg_io_linux.c
sg_dd_LDADD = libsgutils.la @os_libs@

sg_emc_trespass_SOURCES = sg_emc_trespass.c
sg_emc_trespass_LDADD = libsgutils.la @os_libs@

sg_format_SOURCES = sg_format.c
sg_format_LDADD = libsgutils.la @os_libs@

sg_get_config_SOURCES = sg_get_config.c
sg_get_config_LDADD = libsgutils.la @os_libs@

sg_ident_SOURCES = sg_ident.c
sg_ident_LDADD = libsgutils.la @os_libs@

sginfo_SOURCES = sginfo.c sg_io_linux.c
sginfo_LDADD = libsgutils.la @os_libs@

sg_inq_SOURCES = sg_inq.c
sg_inq_LDADD = libsgutils.la @os_libs@

sg_logs_SOURCES = sg_logs.c
sg_logs_LDADD = libsgutils.la @os_libs@

sg_luns_SOURCES = sg_luns.c
sg_luns_LDADD = libsgutils.la @os_libs@

sg_map26_SOURCES = sg_map26.c
sg_map26_LDADD = @os_libs@

sg_map_SOURCES = sg_map.c sg_io_linux.c
sg_map_LDADD = libsgutils.la @os_libs@

sgm_dd_SOURCES = sgm_dd.c sg_io_linux.c
sgm_dd_LDADD = libsgutils.la @os_libs@

sg_modes_SOURCES = sg_modes.c
sg_modes_LDADD = libsgutils.la @os_libs@

sg_opcodes_SOURCES = sg_opcodes.c
sg_opcodes_LDADD = libsgutils.la @os_libs@

sgp_dd_SOURCES = sgp_dd.c sg_io_linux.c
sgp_dd_LDADD = libsgutils.la @os_libs@ -lpthread

sg_persist_SOURCES = sg_persist.c
sg_persist_LDADD = libsgutils.la @os_libs@

sg_prevent_SOURCES = sg_prevent.c
sg_prevent_LDADD = libsgutils.la @os_libs@

sg_raw_SOURCES = sg_raw.c
sg_raw_LDADD = libsgutils.la @os_libs@

sg_rbuf_SOURCES = sg_rbuf.c sg_io_linux.c
sg_rbuf_LDADD = libsgutils.la @os_libs@

sg_rdac_SOURCES = sg_rdac.c
sg_rdac_LDADD = libsgutils.la @os_libs@

sg_read_SOURCES = sg_read.c sg_io_linux.c
sg_read_LDADD = libsgutils.la @os_libs@

sg_readcap_SOURCES = sg_readcap.c
sg_readcap_LDADD = libsgutils.la @os_libs@

sg_read_long_SOURCES = sg_read_long.c
sg_read_long_LDADD = libsgutils.la @os_libs@

sg_reassign_SOURCES = sg_reassign.c
sg_reassign_LDADD = libsgutils.la @os_libs@

sg_requests_SOURCES = sg_requests.c
sg_requests_LDADD = libsgutils.la @os_libs@

sg_reset_SOURCES = sg_reset.c
sg_reset_LDADD = @os_libs@

sg_rmsn_SOURCES = sg_rmsn.c
sg_rmsn_LDADD = libsgutils.la @os_libs@

sg_rtpg_SOURCES = sg_rtpg.c
sg_rtpg_LDADD = libsgutils.la @os_libs@

sg_sat_identify_SOURCES = sg_sat_identify.c
sg_sat_identify_LDADD = libsgutils.la @os_libs@

sg_scan_SOURCES = sg_scan.c sg_io_linux.c
sg_scan_LDADD = libsgutils.la @os_libs@

sg_senddiag_SOURCES = sg_senddiag.c
sg_senddiag_LDADD = libsgutils.la @os_libs@

sg_ses_SOURCES = sg_ses.c
sg_ses_LDADD = libsgutils.la @os_libs@

sg_start_SOURCES = sg_start.c
sg_start_LDADD = libsgutils.la @os_libs@

sg_sync_SOURCES = sg_sync.c
sg_sync_LDADD = libsgutils.la @os_libs@

sg_test_rwbuf_SOURCES = sg_test_rwbuf.c sg_io_linux.c
sg_test_rwbuf_LDADD = libsgutils.la @os_libs@

sg_turs_SOURCES = sg_turs.c
sg_turs_LDADD = libsgutils.la @os_libs@

sg_verify_SOURCES = sg_verify.c
sg_verify_LDADD = libsgutils.la @os_libs@

sg_vpd_SOURCES = sg_vpd.c sg_vpd_vendor.c
sg_vpd_LDADD = libsgutils.la @os_libs@

sg_write_buffer_SOURCES = sg_write_buffer.c
sg_write_buffer_LDADD = libsgutils.la @os_libs@

sg_write_long_SOURCES = sg_write_long.c
sg_write_long_LDADD = libsgutils.la @os_libs@

sg_wr_mode_SOURCES = sg_wr_mode.c
sg_wr_mode_LDADD = libsgutils.la @os_libs@



## spare stuff below vvvvvvvvvvvvv

# sg_dd_LDADD = @os_deps@ @GETOPT_O_FILES@ libsgutils.la @os_libs@
# sg_dd_DEPENDENCIES = @os_deps@ @GETOPT_O_FILES@

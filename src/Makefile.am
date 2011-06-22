
if OS_LINUX

# sg_dd, sg_emc_trespass(?), sginfo, sg_map26, sg_map, sgm_dd, sgp_dd,
# sg_rbuf, sg_read, sg_reset, sg_test_rwbuf
# are Linux only utilities
#
# sg_scan is shared by Linux and Win32

bin_PROGRAMS = \
	sg_dd sg_decode_sense sg_emc_trespass sg_format sg_get_config \
	sg_get_lba_status sg_ident sginfo sg_inq sg_logs sg_luns sg_map26 \
	sg_map sgm_dd sg_modes sg_opcodes sgp_dd sg_persist sg_prevent \
	sg_raw sg_rbuf sg_rdac sg_read sg_readcap sg_read_block_limits \
	sg_read_buffer sg_read_long sg_reassign sg_referrals \
	sg_requests sg_reset sg_rmsn sg_rtpg sg_safte sg_sanitize \
	sg_sat_identify sg_sat_phy_event sg_sat_set_features sg_scan \
	sg_senddiag sg_ses sg_start sg_stpg sg_sync sg_test_rwbuf sg_turs \
	sg_unmap sg_verify sg_vpd sg_write_buffer sg_write_long \
	sg_write_same sg_wr_mode

distclean-local:
	rm -f sg_scan.c

sg_scan.c : sg_scan.c.linux
	cp sg_scan.c.linux sg_scan.c

endif


if OS_WIN32_MINGW

bin_PROGRAMS = \
	sg_decode_sense sg_format sg_get_config sg_get_lba_status sg_ident \
	sg_inq sg_logs sg_luns sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap sg_read_block_limits \
	sg_read_buffer sg_read_long sg_reassign sg_referrals sg_requests \
	sg_rmsn sg_rtpg sg_safte sg_sanitize sg_sat_identify \
	sg_sat_phy_event sg_sat_set_features sg_scan sg_senddiag sg_ses \
	sg_start sg_stpg sg_sync sg_turs sg_unmap sg_verify sg_vpd \
	sg_write_buffer sg_write_long sg_write_same sg_wr_mode

distclean-local:
	rm -f sg_scan.c

sg_scan.c : sg_scan.c.win32
	cp sg_scan.c.win32 sg_scan.c

endif


if OS_WIN32_CYGWIN

bin_PROGRAMS = \
	sg_decode_sense sg_format sg_get_config sg_get_lba_status sg_ident \
	sg_inq sg_logs sg_luns sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap sg_read_block_limits \
	sg_read_buffer sg_read_long sg_reassign sg_referrals sg_requests \
	sg_rmsn sg_rtpg sg_safte sg_sanitize sg_sat_identify \
	sg_sat_phy_event sg_sat_set_features sg_scan sg_senddiag sg_ses \
	sg_start sg_stpg sg_sync sg_turs sg_unmap sg_verify sg_vpd \
	sg_write_buffer sg_write_long sg_write_same sg_wr_mode

distclean-local:
	rm -f sg_scan.c

sg_scan.c : sg_scan.c.win32
	cp sg_scan.c.win32 sg_scan.c

endif


if OS_FREEBSD

bin_PROGRAMS = \
	sg_decode_sense sg_format sg_get_config sg_get_lba_status sg_ident \
	sg_inq sg_logs sg_luns sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap sg_read_block_limits \
	sg_read_buffer sg_read_long sg_reassign sg_referrals sg_requests \
	sg_rmsn sg_rtpg sg_safte sg_sanitize sg_sat_identify \
	sg_sat_phy_event sg_sat_set_features sg_senddiag sg_ses sg_start \
	sg_stpg sg_sync sg_turs sg_unmap sg_verify sg_vpd sg_write_buffer \
	sg_write_long sg_write_same sg_wr_mode

endif


if OS_SOLARIS

bin_PROGRAMS = \
	sg_decode_sense sg_format sg_get_config sg_get_lba_status sg_ident \
	sg_inq sg_logs sg_luns sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap sg_read_block_limits \
	sg_read_buffer sg_read_long sg_reassign sg_referrals sg_requests \
	sg_rmsn sg_rtpg sg_safte sg_sanitize sg_sat_identify \
	sg_sat_phy_event sg_sat_set_features sg_senddiag sg_ses sg_start \
	sg_stpg sg_sync sg_turs sg_unmap sg_verify sg_vpd sg_write_buffer \
	sg_write_long sg_write_same sg_wr_mode

endif


if OS_OSF

bin_PROGRAMS = \
	sg_decode_sense sg_format sg_get_config sg_get_lba_status sg_ident \
	sg_inq sg_logs sg_luns sg_modes sg_opcodes sg_persist \
	sg_prevent sg_raw sg_rdac sg_readcap sg_read_block_limits \
	sg_read_buffer sg_read_long sg_reassign sg_referrals sg_requests \
	sg_rmsn sg_rtpg sg_safte sg_sanitize sg_sat_identify \
	sg_sat_phy_event sg_sat_set_features sg_senddiag sg_ses sg_start \
	sg_stpg sg_sync sg_turs sg_unmap sg_verify sg_vpd sg_write_buffer \
	sg_write_long sg_write_same sg_wr_mode

endif


AM_CFLAGS = -I ../include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -W
# AM_CFLAGS = -I ../include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -W -pedantic -std=c99

sg_dd_SOURCES =	sg_dd.c
sg_dd_LDADD = ../lib/libsgutils2.la @os_libs@

sg_decode_sense_SOURCES =	sg_decode_sense.c
sg_decode_sense_LDADD = ../lib/libsgutils2.la @os_libs@

sg_emc_trespass_SOURCES = sg_emc_trespass.c
sg_emc_trespass_LDADD = ../lib/libsgutils2.la @os_libs@

sg_format_SOURCES = sg_format.c
sg_format_LDADD = ../lib/libsgutils2.la @os_libs@

sg_get_config_SOURCES = sg_get_config.c
sg_get_config_LDADD = ../lib/libsgutils2.la @os_libs@

sg_get_lba_status_SOURCES = sg_get_lba_status.c
sg_get_lba_status_LDADD = ../lib/libsgutils2.la @os_libs@

sg_ident_SOURCES = sg_ident.c
sg_ident_LDADD = ../lib/libsgutils2.la @os_libs@

sginfo_SOURCES = sginfo.c
sginfo_LDADD = ../lib/libsgutils2.la @os_libs@

sg_inq_SOURCES = sg_inq.c sg_inq_data.c
sg_inq_LDADD = ../lib/libsgutils2.la @os_libs@

sg_logs_SOURCES = sg_logs.c
sg_logs_LDADD = ../lib/libsgutils2.la @os_libs@

sg_luns_SOURCES = sg_luns.c
sg_luns_LDADD = ../lib/libsgutils2.la @os_libs@

sg_map26_SOURCES = sg_map26.c
sg_map26_LDADD = @os_libs@

sg_map_SOURCES = sg_map.c
sg_map_LDADD = ../lib/libsgutils2.la @os_libs@

sgm_dd_SOURCES = sgm_dd.c
sgm_dd_LDADD = ../lib/libsgutils2.la @os_libs@

sg_modes_SOURCES = sg_modes.c
sg_modes_LDADD = ../lib/libsgutils2.la @os_libs@

sg_opcodes_SOURCES = sg_opcodes.c
sg_opcodes_LDADD = ../lib/libsgutils2.la @os_libs@

sgp_dd_SOURCES = sgp_dd.c
sgp_dd_LDADD = ../lib/libsgutils2.la @os_libs@ -lpthread

sg_persist_SOURCES = sg_persist.c
sg_persist_LDADD = ../lib/libsgutils2.la @os_libs@

sg_prevent_SOURCES = sg_prevent.c
sg_prevent_LDADD = ../lib/libsgutils2.la @os_libs@

sg_raw_SOURCES = sg_raw.c
sg_raw_LDADD = ../lib/libsgutils2.la @os_libs@

sg_rbuf_SOURCES = sg_rbuf.c
sg_rbuf_LDADD = ../lib/libsgutils2.la @os_libs@

sg_rdac_SOURCES = sg_rdac.c
sg_rdac_LDADD = ../lib/libsgutils2.la @os_libs@

sg_read_SOURCES = sg_read.c
sg_read_LDADD = ../lib/libsgutils2.la @os_libs@

sg_readcap_SOURCES = sg_readcap.c
sg_readcap_LDADD = ../lib/libsgutils2.la @os_libs@

sg_read_block_limits_SOURCES = sg_read_block_limits.c
sg_read_block_limits_LDADD = ../lib/libsgutils2.la @os_libs@

sg_read_buffer_SOURCES = sg_read_buffer.c
sg_read_buffer_LDADD = ../lib/libsgutils2.la @os_libs@

sg_read_long_SOURCES = sg_read_long.c
sg_read_long_LDADD = ../lib/libsgutils2.la @os_libs@

sg_reassign_SOURCES = sg_reassign.c
sg_reassign_LDADD = ../lib/libsgutils2.la @os_libs@

sg_requests_SOURCES = sg_requests.c
sg_requests_LDADD = ../lib/libsgutils2.la @os_libs@

sg_referrals_SOURCES = sg_referrals.c
sg_referrals_LDADD = ../lib/libsgutils2.la @os_libs@

sg_reset_SOURCES = sg_reset.c
sg_reset_LDADD = @os_libs@

sg_rmsn_SOURCES = sg_rmsn.c
sg_rmsn_LDADD = ../lib/libsgutils2.la @os_libs@

sg_rtpg_SOURCES = sg_rtpg.c
sg_rtpg_LDADD = ../lib/libsgutils2.la @os_libs@

sg_safte_SOURCES = sg_safte.c
sg_safte_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sanitize_SOURCES = sg_sanitize.c
sg_sanitize_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sat_identify_SOURCES = sg_sat_identify.c
sg_sat_identify_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sat_phy_event_SOURCES = sg_sat_phy_event.c
sg_sat_phy_event_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sat_set_features_SOURCES = sg_sat_set_features.c
sg_sat_set_features_LDADD = ../lib/libsgutils2.la @os_libs@

sg_scan_SOURCES = sg_scan.c
sg_scan_LDADD = ../lib/libsgutils2.la @os_libs@

sg_senddiag_SOURCES = sg_senddiag.c
sg_senddiag_LDADD = ../lib/libsgutils2.la @os_libs@

sg_ses_SOURCES = sg_ses.c
sg_ses_LDADD = ../lib/libsgutils2.la @os_libs@

sg_start_SOURCES = sg_start.c
sg_start_LDADD = ../lib/libsgutils2.la @os_libs@

sg_stpg_SOURCES = sg_stpg.c
sg_stpg_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sync_SOURCES = sg_sync.c
sg_sync_LDADD = ../lib/libsgutils2.la @os_libs@

sg_test_rwbuf_SOURCES = sg_test_rwbuf.c
sg_test_rwbuf_LDADD = ../lib/libsgutils2.la @os_libs@

sg_turs_SOURCES = sg_turs.c
sg_turs_LDADD = ../lib/libsgutils2.la @os_libs@

sg_unmap_SOURCES = sg_unmap.c
sg_unmap_LDADD = ../lib/libsgutils2.la @os_libs@

sg_verify_SOURCES = sg_verify.c
sg_verify_LDADD = ../lib/libsgutils2.la @os_libs@

sg_vpd_SOURCES = sg_vpd.c sg_vpd_vendor.c
sg_vpd_LDADD = ../lib/libsgutils2.la @os_libs@

sg_write_buffer_SOURCES = sg_write_buffer.c
sg_write_buffer_LDADD = ../lib/libsgutils2.la @os_libs@

sg_write_long_SOURCES = sg_write_long.c
sg_write_long_LDADD = ../lib/libsgutils2.la @os_libs@

sg_write_same_SOURCES = sg_write_same.c
sg_write_same_LDADD = ../lib/libsgutils2.la @os_libs@

sg_wr_mode_SOURCES = sg_wr_mode.c
sg_wr_mode_LDADD = ../lib/libsgutils2.la @os_libs@


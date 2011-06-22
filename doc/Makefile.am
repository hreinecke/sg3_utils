
if OS_LINUX

# sg_dd, sg_emc_trespass(?), sginfo, sg_map26, sg_map, sgm_dd, sgp_dd,
# sg_rbuf, sg_read, sg_reset, sg_test_rwbuf
# are Linux only utilities
#
# sg_scan is shared by Linux and Win32

man_MANS = \
	sg3_utils.8 sg_decode_sense.8 \
	scsi_readcap.8  scsi_ready.8  scsi_start.8  scsi_stop.8 \
	sg_dd.8 sg_emc_trespass.8 sg_format.8 sg_get_config.8 \
	sg_get_lba_status.8 sg_ident.8 sginfo.8 sg_inq.8 sg_logs.8 \
	sg_luns.8 sg_map26.8 sg_map.8 sgm_dd.8 sg_modes.8 sg_opcodes.8 \
	sgp_dd.8 sg_persist.8 sg_prevent.8 sg_raw.8 sg_rbuf.8 sg_rdac.8 \
	sg_read.8 sg_readcap.8 sg_read_block_limits.8 sg_read_buffer.8 \
	sg_read_long.8 sg_reassign.8 sg_referrals.8 sg_requests.8 \
	sg_reset.8 sg_rmsn.8 sg_rtpg.8 sg_safte.8 sg_sanitize.8 \
	sg_sat_identify.8 sg_sat_phy_event.8 sg_sat_set_features.8 \
	sg_scan.8 sg_senddiag.8 sg_ses.8 sg_start.8 sg_stpg.8 sg_sync.8 \
	sg_test_rwbuf.8 sg_turs.8 sg_unmap.8 sg_verify.8 sg_vpd.8 \
	sg_write_buffer.8 sg_write_long.8 sg_write_same.8 sg_wr_mode.8

distclean-local:
	rm -f sg_scan.8

sg_scan.8 : sg_scan.8.linux
	cp -p sg_scan.8.linux sg_scan.8

endif


if OS_WIN32_MINGW

man_MANS = \
	sg3_utils.8 sg_decode_sense.8 \
	scsi_readcap.8  scsi_ready.8  scsi_start.8  scsi_stop.8 \
	sg_format.8 sg_get_config.8 sg_get_lba_status.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 sg_modes.8 sg_opcodes.8 sg_persist.8 \
	sg_prevent.8 sg_raw.8 sg_rdac.8 sg_readcap.8 \
	sg_read_block_limits.8 sg_read_buffer.8 sg_read_long.8 \
	sg_reassign.8 sg_referrals.8 sg_requests.8 sg_rmsn.8 sg_rtpg.8 \
	sg_safte.8 sg_sanitize.8 sg_sat_identify.8 sg_sat_phy_event.8 \
	sg_sat_set_features.8 sg_scan.8 sg_senddiag.8 sg_ses.8 sg_start.8 \
	sg_stpg.8 sg_sync.8 sg_turs.8 sg_unmap.8 sg_verify.8 sg_vpd.8 \
	sg_write_buffer.8 sg_write_long.8 sg_write_same.8 sg_wr_mode.8

distclean-local:
	rm -f sg_scan.8

sg_scan.8 : sg_scan.8.win32
	cp -p sg_scan.8.win32 sg_scan.8

endif


if OS_WIN32_CYGWIN

man_MANS = \
	sg3_utils.8 sg_decode_sense.8 \
	scsi_readcap.8  scsi_ready.8  scsi_start.8  scsi_stop.8 \
	sg_format.8 sg_get_config.8 sg_get_lba_status.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 sg_modes.8 sg_opcodes.8 \
	sg_persist.8 sg_prevent.8 sg_raw.8 sg_rdac.8 sg_readcap.8 \
	sg_read_block_limits.8 sg_read_buffer.8 sg_read_long.8 \
	sg_reassign.8 sg_referrals.8 sg_requests.8 sg_rmsn.8 sg_rtpg.8 \
	sg_safte.8 sg_sanitize.8 sg_sat_identify.8 sg_sat_phy_event.8 \
	sg_sat_set_features.8 sg_scan.8 sg_senddiag.8 sg_ses.8 sg_start.8 \
	sg_stpg.8 sg_sync.8 sg_turs.8 sg_unmap.8 sg_verify.8 sg_vpd.8 \
	sg_write_buffer.8 sg_write_long.8 sg_write_same.8 sg_wr_mode.8

distclean-local:
	rm -f sg_scan.8

sg_scan.8 : sg_scan.8.win32
	cp -p sg_scan.8.win32 sg_scan.8

endif


if OS_FREEBSD

man_MANS = \
	sg3_utils.8 sg_decode_sense.8 \
	scsi_readcap.8  scsi_ready.8  scsi_start.8  scsi_stop.8 \
	sg_format.8 sg_get_config.8 sg_get_lba_status.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 \
	sg_modes.8 sg_opcodes.8 sg_persist.8 sg_prevent.8 sg_raw.8 \
	sg_rdac.8 sg_readcap.8 sg_read_block_limits.8 sg_read_buffer.8 \
	sg_read_long.8 sg_reassign.8 sg_referrals.8 sg_requests.8 sg_rmsn.8 \
	sg_rtpg.8 sg_safte.8 sg_sanitize.8 sg_sat_identify.8 \
	sg_sat_phy_event.8 sg_sat_set_features.8 sg_senddiag.8 sg_ses.8 \
	sg_start.8 sg_stpg.8 sg_sync.8 sg_turs.8 sg_unmap.8 sg_verify.8 \
	sg_vpd.8 sg_write_buffer.8 sg_write_long.8 sg_write_same.8 \
	sg_wr_mode.8

endif


if OS_SOLARIS

man_MANS = \
	sg3_utils.8 sg_decode_sense.8 \
	scsi_readcap.8  scsi_ready.8  scsi_start.8  scsi_stop.8 \
	sg_format.8 sg_get_config.8 sg_get_lba_status.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 \
	sg_modes.8 sg_opcodes.8 sg_persist.8 sg_prevent.8 sg_raw.8 \
	sg_rdac.8 sg_readcap.8 sg_read_block_limits.8 sg_read_buffer.8 \
	sg_read_long.8 sg_reassign.8 sg_referrals.8 sg_requests.8 sg_rmsn.8 \
	sg_rtpg.8 sg_safte.8 sg_sanitize.8 sg_sat_identify.8 \
	sg_sat_phy_event.8 sg_sat_set_features.8 sg_senddiag.8 sg_ses.8 \
	sg_start.8 sg_stpg.8 sg_sync.8 sg_turs.8 sg_unmap.8 sg_verify.8 \
	sg_vpd.8 sg_write_buffer.8 sg_write_long.8 sg_write_same.8 \
	sg_wr_mode.8

endif


if OS_OSF

man_MANS = \
	sg3_utils.8 sg_decode_sense.8 \
	scsi_readcap.8  scsi_ready.8  scsi_start.8  scsi_stop.8 \
	sg_format.8 sg_get_config.8 sg_get_lba_status.8 sg_ident.8 \
	sg_inq.8 sg_logs.8 sg_luns.8 \
	sg_modes.8 sg_opcodes.8 sg_persist.8 sg_prevent.8 sg_raw.8 \
	sg_rdac.8 sg_readcap.8 sg_read_block_limits.8 sg_read_buffer.8 \
	sg_read_long.8 sg_reassign.8 sg_referrals.8 sg_requests.8 sg_rmsn.8 \
	sg_rtpg.8 sg_safte.8 sg_sanitize.8 sg_sat_identify.8 \
	sg_sat_phy_event.8 sg_sat_set_features.8 sg_senddiag.8 sg_ses.8 \
	sg_start.8 sg_stpg.8 sg_sync.8 sg_turs.8 sg_unmap.8 sg_verify.8 \
	sg_vpd.8 sg_write_buffer.8 sg_write_long.8 sg_write_same.8 \
	sg_wr_mode.8

endif


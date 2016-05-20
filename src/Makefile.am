
bin_PROGRAMS = \
	sg_bg_ctl sg_compare_and_write sg_decode_sense sg_format \
	sg_get_config sg_get_lba_status sg_ident sg_inq sg_logs sg_luns \
	sg_modes sg_opcodes sg_persist sg_prevent sg_raw sg_rdac \
	sg_read_attr sg_read_block_limits sg_read_buffer sg_read_long \
	sg_readcap sg_reassign sg_referrals sg_rep_zones sg_requests \
	sg_reset_wp sg_rmsn sg_rtpg sg_safte sg_sanitize sg_sat_identify \
	sg_sat_phy_event sg_sat_read_gplog sg_sat_set_features sg_senddiag \
	sg_ses sg_ses_microcode sg_start sg_stpg sg_sync sg_timestamp \
	sg_turs sg_unmap sg_verify sg_vpd sg_wr_mode sg_write_buffer \
	sg_write_long sg_write_same sg_write_verify sg_zone
sg_scan_SOURCES =


if OS_LINUX
bin_PROGRAMS += \
	sg_copy_results sg_dd sg_emc_trespass sg_map sg_map26 sg_rbuf \
	sg_read sg_reset sg_scan sg_test_rwbuf sg_xcopy sginfo sgm_dd sgp_dd
sg_scan_SOURCES += sg_scan_linux.c
endif


if OS_WIN32_MINGW
bin_PROGRAMS += sg_scan
sg_scan_SOURCES += sg_scan_win32.c
endif


if OS_WIN32_CYGWIN
bin_PROGRAMS += sg_scan
sg_scan_SOURCES += sg_scan_win32.c
endif


# For C++/clang testing
## CC = gcc
## CC = g++
## CC = clang
## CC = clang++

# -std=<s> can be c99, c11, gnu11, etc. Default is gnu89 (gnu90 is the same)
# -Wall is no longer all warnings. Add -W (since renamed to -Wextra) for more
AM_CPPFLAGS = -iquote ${top_srcdir}/include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -Wall -W @os_cflags@
# AM_CFLAGS = -Wall -W @os_cflags@ -pedantic -std=c11
# AM_CFLAGS = -Wall -W @os_cflags@ -pedantic -std=c11 --analyze
# AM_CFLAGS = -Wall -W @os_cflags@ -pedantic -std=c++14

sg_bg_ctl_LDADD = ../lib/libsgutils2.la @os_libs@

sg_compare_and_write_LDADD = ../lib/libsgutils2.la @os_libs@

sg_copy_results_LDADD = ../lib/libsgutils2.la @os_libs@

sg_dd_LDADD = ../lib/libsgutils2.la @os_libs@

sg_decode_sense_LDADD = ../lib/libsgutils2.la @os_libs@

sg_emc_trespass_LDADD = ../lib/libsgutils2.la @os_libs@

sg_format_LDADD = ../lib/libsgutils2.la @os_libs@

sg_get_config_LDADD = ../lib/libsgutils2.la @os_libs@

sg_get_lba_status_LDADD = ../lib/libsgutils2.la @os_libs@

sg_ident_LDADD = ../lib/libsgutils2.la @os_libs@

sginfo_LDADD = ../lib/libsgutils2.la @os_libs@

sg_inq_SOURCES = sg_inq.c sg_inq_data.c
sg_inq_LDADD = ../lib/libsgutils2.la @os_libs@

sg_logs_LDADD = ../lib/libsgutils2.la @os_libs@

sg_luns_LDADD = ../lib/libsgutils2.la @os_libs@

sg_map26_LDADD = @os_libs@

sg_map_LDADD = ../lib/libsgutils2.la @os_libs@

sgm_dd_LDADD = ../lib/libsgutils2.la @os_libs@

sg_modes_LDADD = ../lib/libsgutils2.la @os_libs@

sg_opcodes_LDADD = ../lib/libsgutils2.la @os_libs@

sgp_dd_LDADD = ../lib/libsgutils2.la @os_libs@ -lpthread

sg_persist_LDADD = ../lib/libsgutils2.la @os_libs@

sg_prevent_LDADD = ../lib/libsgutils2.la @os_libs@

sg_raw_LDADD = ../lib/libsgutils2.la @os_libs@

sg_rbuf_LDADD = ../lib/libsgutils2.la @os_libs@

sg_rdac_LDADD = ../lib/libsgutils2.la @os_libs@

sg_read_LDADD = ../lib/libsgutils2.la @os_libs@

sg_read_attr_LDADD = ../lib/libsgutils2.la @os_libs@

sg_readcap_LDADD = ../lib/libsgutils2.la @os_libs@

sg_read_block_limits_LDADD = ../lib/libsgutils2.la @os_libs@

sg_read_buffer_LDADD = ../lib/libsgutils2.la @os_libs@

sg_read_long_LDADD = ../lib/libsgutils2.la @os_libs@

sg_reassign_LDADD = ../lib/libsgutils2.la @os_libs@

sg_requests_LDADD = ../lib/libsgutils2.la @os_libs@

sg_referrals_LDADD = ../lib/libsgutils2.la @os_libs@

sg_rep_zones_LDADD = ../lib/libsgutils2.la @os_libs@

sg_reset_LDADD = @os_libs@

sg_reset_wp_LDADD = ../lib/libsgutils2.la @os_libs@

sg_rmsn_LDADD = ../lib/libsgutils2.la @os_libs@

sg_rtpg_LDADD = ../lib/libsgutils2.la @os_libs@

sg_safte_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sanitize_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sat_identify_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sat_phy_event_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sat_read_gplog_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sat_set_features_LDADD = ../lib/libsgutils2.la @os_libs@

# sg_scan_SOURCES list is already set above in the platform-specific sections
sg_scan_LDADD = ../lib/libsgutils2.la @os_libs@

sg_senddiag_LDADD = ../lib/libsgutils2.la @os_libs@

sg_ses_LDADD = ../lib/libsgutils2.la @os_libs@

sg_ses_microcode_LDADD = ../lib/libsgutils2.la @os_libs@

sg_start_LDADD = ../lib/libsgutils2.la @os_libs@

sg_stpg_LDADD = ../lib/libsgutils2.la @os_libs@

sg_sync_LDADD = ../lib/libsgutils2.la @os_libs@

sg_test_rwbuf_LDADD = ../lib/libsgutils2.la @os_libs@

sg_timestamp_LDADD = ../lib/libsgutils2.la @os_libs@

sg_turs_LDADD = ../lib/libsgutils2.la @os_libs@

sg_unmap_LDADD = ../lib/libsgutils2.la @os_libs@

sg_verify_LDADD = ../lib/libsgutils2.la @os_libs@

sg_vpd_SOURCES = sg_vpd.c sg_vpd_vendor.c
sg_vpd_LDADD = ../lib/libsgutils2.la @os_libs@

sg_write_buffer_LDADD = ../lib/libsgutils2.la @os_libs@

sg_write_long_LDADD = ../lib/libsgutils2.la @os_libs@

sg_write_same_LDADD = ../lib/libsgutils2.la @os_libs@

sg_write_verify_LDADD = ../lib/libsgutils2.la @os_libs@

sg_wr_mode_LDADD = ../lib/libsgutils2.la @os_libs@

sg_xcopy_LDADD = ../lib/libsgutils2.la @os_libs@

sg_zone_LDADD = ../lib/libsgutils2.la @os_libs@

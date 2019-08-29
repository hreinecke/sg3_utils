
bin_PROGRAMS = \
	sg_bg_ctl sg_compare_and_write sg_decode_sense sg_format \
	sg_get_config sg_get_elem_status sg_get_lba_status sg_ident sg_inq \
	sg_logs sg_luns sg_modes sg_opcodes sg_persist sg_prevent sg_raw \
	sg_rdac sg_read_attr sg_read_block_limits sg_read_buffer \
	sg_read_long sg_readcap sg_reassign sg_referrals sg_rep_zones \
	sg_requests sg_reset_wp sg_rmsn sg_rtpg sg_safte sg_sanitize \
	sg_sat_identify sg_sat_phy_event sg_sat_read_gplog \
	sg_sat_set_features sg_seek sg_senddiag sg_ses sg_ses_microcode \
	sg_start sg_stpg sg_stream_ctl sg_sync sg_timestamp sg_turs sg_unmap \
	sg_verify sg_vpd sg_wr_mode sg_write_buffer sg_write_long \
	sg_write_same sg_write_verify sg_write_x sg_zone
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

# This is active if --enable-debug given to ./configure
# removed -Wduplicated-branches because needs gcc-8
if DEBUG
DBG_CFLAGS = -Wextra -Wmisleading-indentation -Wduplicated-cond -Wlogical-op -Wnull-dereference -Wshadow -Wjump-misses-init
DBG_CPPFLAGS = -DDEBUG
else
DBG_CFLAGS =
DBG_CPPFLAGS =
endif

# For C++/clang testing
## CC = gcc-9
## CC = g++
## CC = clang
## CC = clang++
## CC = powerpc64-linux-gnu-gcc

# -std=<s> can be c99, c11, gnu11, etc. Default is gnu11
# -Wall is no longer all warnings. Add -W (since renamed to -Wextra) for more
AM_CPPFLAGS = -iquote ${top_srcdir}/include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 $(DBG_CPPFLAGS)
AM_CFLAGS = -Wall -W $(DBG_CFLAGS)
# AM_CFLAGS = -Wall -W -Wextra -Wmisleading-indentation -Wduplicated-cond -Wduplicated-branches -Wlogical-op -Wnull-dereference -Wshadow -Wjump-misses-init
# AM_CFLAGS = -Wall -W -pedantic -std=c11
# AM_CFLAGS = -Wall -W -pedantic -std=c11 --analyze
# AM_CFLAGS = -Wall -W -pedantic -std=c++14
# AM_CFLAGS = -Wall -W -pedantic -std=c++1z

sg_bg_ctl_LDADD = ../lib/libsgutils2.la

sg_compare_and_write_LDADD = ../lib/libsgutils2.la

sg_copy_results_LDADD = ../lib/libsgutils2.la

sg_dd_LDADD = ../lib/libsgutils2.la

sg_decode_sense_LDADD = ../lib/libsgutils2.la

sg_emc_trespass_LDADD = ../lib/libsgutils2.la

sg_format_LDADD = ../lib/libsgutils2.la

sg_get_config_LDADD = ../lib/libsgutils2.la

sg_get_elem_status_LDADD = ../lib/libsgutils2.la

sg_get_lba_status_LDADD = ../lib/libsgutils2.la

sg_ident_LDADD = ../lib/libsgutils2.la

sginfo_LDADD = ../lib/libsgutils2.la

sg_inq_SOURCES = sg_inq.c sg_inq_data.c
sg_inq_LDADD = ../lib/libsgutils2.la

sg_logs_LDADD = ../lib/libsgutils2.la

sg_luns_LDADD = ../lib/libsgutils2.la

sg_map_LDADD = ../lib/libsgutils2.la

sgm_dd_LDADD = ../lib/libsgutils2.la

sg_modes_LDADD = ../lib/libsgutils2.la

sg_opcodes_LDADD = ../lib/libsgutils2.la

sgp_dd_LDADD = ../lib/libsgutils2.la @PTHREAD_LIB@

sg_persist_LDADD = ../lib/libsgutils2.la

sg_prevent_LDADD = ../lib/libsgutils2.la

sg_raw_LDADD = ../lib/libsgutils2.la

sg_rbuf_LDADD = ../lib/libsgutils2.la

sg_rdac_LDADD = ../lib/libsgutils2.la

sg_read_LDADD = ../lib/libsgutils2.la

sg_read_attr_LDADD = ../lib/libsgutils2.la

sg_readcap_LDADD = ../lib/libsgutils2.la

sg_read_block_limits_LDADD = ../lib/libsgutils2.la

sg_read_buffer_LDADD = ../lib/libsgutils2.la

sg_read_long_LDADD = ../lib/libsgutils2.la

sg_reassign_LDADD = ../lib/libsgutils2.la

sg_requests_LDADD = ../lib/libsgutils2.la

sg_referrals_LDADD = ../lib/libsgutils2.la

sg_rep_zones_LDADD = ../lib/libsgutils2.la

sg_reset_wp_LDADD = ../lib/libsgutils2.la

sg_rmsn_LDADD = ../lib/libsgutils2.la

sg_rtpg_LDADD = ../lib/libsgutils2.la

sg_safte_LDADD = ../lib/libsgutils2.la

sg_sanitize_LDADD = ../lib/libsgutils2.la

sg_sat_identify_LDADD = ../lib/libsgutils2.la

sg_sat_phy_event_LDADD = ../lib/libsgutils2.la

sg_sat_read_gplog_LDADD = ../lib/libsgutils2.la

sg_sat_set_features_LDADD = ../lib/libsgutils2.la

# sg_scan_SOURCES list is already set above in the platform-specific sections
sg_scan_LDADD = ../lib/libsgutils2.la

sg_seek_LDADD = ../lib/libsgutils2.la @RT_LIB@

sg_senddiag_LDADD = ../lib/libsgutils2.la

sg_ses_LDADD = ../lib/libsgutils2.la

sg_ses_microcode_LDADD = ../lib/libsgutils2.la

sg_start_LDADD = ../lib/libsgutils2.la

sg_stpg_LDADD = ../lib/libsgutils2.la

sg_stream_ctl_LDADD = ../lib/libsgutils2.la

sg_sync_LDADD = ../lib/libsgutils2.la

sg_test_rwbuf_LDADD = ../lib/libsgutils2.la

sg_timestamp_LDADD = ../lib/libsgutils2.la

sg_turs_LDADD = ../lib/libsgutils2.la @RT_LIB@

sg_unmap_LDADD = ../lib/libsgutils2.la

sg_verify_LDADD = ../lib/libsgutils2.la

sg_vpd_SOURCES = sg_vpd.c sg_vpd_vendor.c
sg_vpd_LDADD = ../lib/libsgutils2.la

sg_wr_mode_LDADD = ../lib/libsgutils2.la

sg_write_buffer_LDADD = ../lib/libsgutils2.la

sg_write_long_LDADD = ../lib/libsgutils2.la

sg_write_same_LDADD = ../lib/libsgutils2.la

sg_write_verify_LDADD = ../lib/libsgutils2.la

sg_write_x_LDADD = ../lib/libsgutils2.la

sg_xcopy_LDADD = ../lib/libsgutils2.la

sg_zone_LDADD = ../lib/libsgutils2.la

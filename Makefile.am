
SUBDIRS = \
	include \
	lib \
	src \
	doc \
	scripts

EXTRA_DIST = \
	autogen.sh \
	COVERAGE \
	CREDITS \
	BSD_LICENSE \
	build_debian.sh \
	README.details \
	README.freebsd \
	README.iscsi \
	README.sg_start \
	README.solaris \
	README.tru64 \
	README.win32 \
	sg3_utils.man8.html \
	sg3_utils.spec

EXTRA_DIST += \
	archive/align_b4_memalign.c \
	archive/llseek.c \
	archive/llseek.h \
	archive/o_scsi_logging_level \
	archive/README \
	archive/sg_json_writer.c \
	archive/sg_json_writer.h

EXTRA_DIST += \
	debian/changelog \
	debian/compat \
	debian/control \
	debian/copyright \
	debian/docs \
	debian/libsgutils2-2.install \
	debian/libsgutils2-dev.install \
	debian/README.debian4 \
	debian/rules \
	debian/sg3-utils.examples \
	debian/sg3-utils.install

EXTRA_DIST += \
	examples/Makefile.freebsd \
	examples/README \
	examples/reassign_addr.txt \
	examples/scsi_inquiry.c \
	examples/sdiag_sas_p0_cjtpat.txt \
	examples/sdiag_sas_p0_prbs9.txt \
	examples/sdiag_sas_p1_cjtpat.txt \
	examples/sdiag_sas_p1_idle.txt \
	examples/sdiag_sas_p1_prbs15.txt \
	examples/sdiag_sas_p1_stop.txt \
	examples/sg_compare_and_write.txt \
	examples/sg_excl.c \
	examples/sg_persist_tst.sh \
	examples/sgq_dd.c \
	examples/sg_sat_chk_power.c \
	examples/sg__sat_identify.c \
	examples/sg__sat_phy_event.c \
	examples/sg__sat_set_features.c \
	examples/sg_sat_smart_rd_data.c \
	examples/sg_simple16.c \
	examples/sg_simple1.c \
	examples/sg_simple2.c \
	examples/sg_simple3.c \
	examples/sg_simple4.c \
	examples/sg_simple5.c \
	examples/sg_unmap_example.txt \
	examples/transport_ids.txt \
	examples/Makefile

EXTRA_DIST += \
	getopt_long/getopt.h \
	getopt_long/getopt_long.c

EXTRA_DIST += \
	include/freebsd_nvme_ioctl.h

EXTRA_DIST += \
	inhex/descriptor_sense.hex \
	inhex/fixed_sense.hex \
	inhex/forwarded_sense.hex \
	inhex/get_elem_status.hex \
	inhex/get_lba_status.hex \
	inhex/inq_standard.hex \
	inhex/logs_last_n.hex \
	inhex/nvme_dev_self_test.hex \
	inhex/nvme_identify_ctl.hex \
	inhex/nvme_read_ctl.hex \
	inhex/nvme_read_oob_ctl.hex \
	inhex/nvme_write_ctl.hex \
	inhex/opcodes.hex \
	inhex/README \
	inhex/ref_sense.hex \
	inhex/rep_density.hex \
	inhex/rep_density_media.hex \
	inhex/rep_density_media_typem.hex \
	inhex/rep_density_typem.hex \
	inhex/rep_realms.hex \
	inhex/rep_zdomains.hex \
	inhex/rep_zones.hex \
	inhex/ses_areca_all.hex \
	inhex/vpd_bdce.hex \
	inhex/vpd_consistuents.hex \
	inhex/vpd_cpr.hex \
	inhex/vpd_dev_id.hex \
	inhex/vpd_di_all.hex \
	inhex/vpd_fp.hex \
	inhex/vpd_lbpro.hex \
	inhex/vpd_lbpv.hex \
	inhex/vpd_ref.hex \
	inhex/vpd_sbl.hex \
	inhex/vpd_sdeb.hex \
	inhex/vpd_sfs.hex \
	inhex/vpd_tpc.hex \
	inhex/vpd_zbdc.hex \
	inhex/vpd_zbdc.raw \
	inhex/z_act_query.hex

EXTRA_DIST += \
	scripts/40-usb-blacklist.rules \
	scripts/54-before-scsi-sg3_id.rules \
	scripts/55-scsi-sg3_id.rules \
	scripts/58-scsi-sg3_symlink.rules \
	scripts/59-fc-wwpn-id.rules \
	scripts/59-scsi-cciss_id.rules \
	scripts/cciss_id \
	scripts/fc_wwpn_id \
	scripts/lunmask.service \
	scripts/scsi-enable-target-scan.sh

EXTRA_DIST += \
	suse/sg3_utils.changes \
	suse/sg3_utils.spec

EXTRA_DIST += \
	testing/bsg_queue_tst.c \
	testing/Makefile \
	testing/Makefile.cyg \
	testing/Makefile.freebsd \
	testing/README \
	testing/sg_chk_asc.c \
	testing/sgh_dd.cpp \
	testing/sg_iovec_tst.cpp \
	testing/sg_json_builder_test.c \
	testing/sg_mrq_dd.cpp \
	testing/sg_queue_tst.c \
	testing/sg_scat_gath.cpp \
	testing/sg_scat_gath.h \
	testing/sgs_dd.c \
	testing/sg_sense_test.c \
	testing/sg_take_snap.c \
	testing/sg_tst_async.cpp \
	testing/sg_tst_bidi.c \
	testing/sg_tst_context.cpp \
	testing/sg_tst_excl2.cpp \
	testing/sg_tst_excl3.cpp \
	testing/sg_tst_excl.cpp \
	testing/sg_tst_ioctl.c \
	testing/sg_tst_json_builder.c \
	testing/sg_tst_nvme.c \
	testing/tst_sg_lib.c \
	testing/uapi_sg.h

EXTRA_DIST += \
	utils/hxascdmp.1 \
	utils/hxascdmp.c \
	utils/Makefile \
	utils/Makefile.cygwin \
	utils/Makefile.freebsd \
	utils/Makefile.mingw \
	utils/Makefile.solaris \
	utils/README

distclean-local:
	rm -rf autom4te.cache
	rm -f build-stamp configure-stamp
	rm -rf lib/.deps
	rm -rf src/.deps

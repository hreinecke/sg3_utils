#!/bin/sh
# Any Bourne style shell should be okay

# Test the hex "inhex" files in this directory using the corresponding
# sg3_utils utility which is assumed to be installed.

# the following are invoked in the order the hex files appear in the
# inhex directory (e.g. with the ls command).

# Get each utility to send its version string and command line options
# to stderr. Comment out the next line to stop that.
export SG3_UTILS_INVOCATION=1

# In all cases below the '-i <filename>' or '-I < filename>' option can be
# replaced by '--inhex=<filename>' .

sg_decode_sense -i descriptor_sense.hex
sg_decode_sense -i fixed_sense.hex 
sg_decode_sense -i forwarded_sense.hex

sg_get_elem_status -i get_elem_status.hex

sg_get_lba_status -i get_lba_status.hex 

sg_inq -I inq_standard.hex

sg_luns -i luns_lu_cong.hex
sg_luns -i luns_wlun.hex

# modes_mm_sdeb.hex and modes_sdeb.hex are output by sg_modes which is
# unable to decode mode pages. For that there is the sdparm utility in
# a package of the same name. Won't assume it is installed so skip.

# The nvme*.hex files are meant as input to the sg_raw utility where
# the corresponding DEVICE is a NVMe (storage) device. Will skip in this
# script as they require the appropriate hardware.

sg_opcodes -i opcodes.hex

sg_readcap -i readcap_zbc.hex

sg_decode_sense -i ref_sense.hex

sg_rep_density -i rep_density.hex
sg_rep_density -i rep_density_media.hex
sg_rep_density --typem -i rep_density_media_typem.hex
sg_rep_density --typem -i rep_density_typem.hex

sg_rep_zones --realm --i rep_realms.hex
sg_rep_zones --domain --i rep_zdomains.hex
sg_rep_zones --i rep_zones.hex

sg_ses --all --inhex=ses_areca_all.hex
# test indexing on Voltage sensor ('vs') element type [0x12]
sg_ses --get=disable --inhex=ses_areca_all.hex --index=vs,-1
sg_ses --get=disable --inhex=ses_areca_all.hex --index=vs,-1:-1
sg_ses --get=disable --inhex=ses_areca_all.hex --index=vs,-1:0
sg_ses --get=disable --inhex=ses_areca_all.hex --index=vs,-1:1
sg_ses --get=disable --inhex=ses_areca_all.hex --index=vs,-1:2
sg_ses --get=disable --inhex=ses_areca_all.hex --index=vs,-1:255
sg_ses --get=disable --inhex=ses_areca_all.hex --index=vs,1
echo ""
echo "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
echo "expect error cause only 2 individual Voltage sensors"
sg_ses --get=disable --inhex=ses_areca_all.hex --index=vs,2
echo ""
# The Voltage sensor number given rather than abbreviation
sg_ses --get=disable --inhex=ses_areca_all.hex --index=_0x12,1
# Voltage sensor given but no individual index so defaults to overall
sg_ses --get=disable --inhex=ses_areca_all.hex --index=vs

sg_vpd -I vpd_bdce.hex
sg_vpd -I vpd_constituents.hex
sg_vpd -I vpd_cpr.hex
sg_vpd -I vpd_dev_id.hex
sg_vpd -I vpd_di_all.hex
sg_vpd -I vpd_fp.hex
sg_vpd -I vpd_lbpro.hex
sg_vpd -I vpd_lbpv.hex
sg_vpd -I vpd_ref.hex
sg_vpd -I vpd_sbl.hex
sg_vpd -I vpd_sdeb.hex
sg_vpd -I vpd_sfs.hex
sg_vpd -I vpd_tpc.hex
sg_vpd -I vpd_zbdc.hex

sg_z_act_query --inhex=z_act_query.hex

# D. Gilbert, last updated 20230420


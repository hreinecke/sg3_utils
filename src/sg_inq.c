/* A utility program originally written for the Linux OS SCSI subsystem.
 * Copyright (C) 2000-2020 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program outputs information provided by a SCSI INQUIRY command.
 * It is mainly based on the SCSI SPC-5 document at http://www.t10.org .
 *
 * Acknowledgment:
 *    - Martin Schwenke <martin at meltin dot net> added the raw switch and
 *      other improvements [20020814]
 *    - Lars Marowsky-Bree <lmb at suse dot de> contributed Unit Path Report
 *      VPD page decoding for EMC CLARiiON devices [20041016]
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <errno.h>

#ifdef SG_LIB_LINUX
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/hdreg.h>
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"
#if (HAVE_NVME && (! IGNORE_NVME))
#include "sg_pt_nvme.h"
#endif

static const char * version_str = "2.05 20200223";    /* SPC-6 rev 01 */

/* INQUIRY notes:
 * It is recommended that the initial allocation length given to a
 * standard INQUIRY is 36 (bytes), especially if this is the first
 * SCSI command sent to a logical unit. This is compliant with SCSI-2
 * and another major operating system. There are devices out there
 * that use one of the SCSI commands sets and lock up if they receive
 * an allocation length other than 36. This technique is sometimes
 * referred to as a "36 byte INQUIRY".
 *
 * A "standard" INQUIRY is one that has the EVPD and the CmdDt bits
 * clear.
 *
 * When doing device discovery on a SCSI transport (e.g. bus scanning)
 * the first SCSI command sent to a device should be a standard (36
 * byte) INQUIRY.
 *
 * The allocation length field in the INQUIRY command was changed
 * from 1 to 2 bytes in SPC-3, revision 9, 17 September 2002.
 * Be careful using allocation lengths greater than 252 bytes, especially
 * if the lower byte is 0x0 (e.g. a 512 byte allocation length may
 * not be a good arbitrary choice (as 512 == 0x200) ).
 *
 * From SPC-3 revision 16 the CmdDt bit in an INQUIRY is obsolete. There
 * is now a REPORT SUPPORTED OPERATION CODES command that yields similar
 * information [MAINTENANCE IN, service action = 0xc]; see sg_opcodes.
 */


/* Following VPD pages are in ascending page number order */
#define VPD_SUPPORTED_VPDS 0x0
#define VPD_UNIT_SERIAL_NUM 0x80
#define VPD_DEVICE_ID  0x83
#define VPD_SOFTW_INF_ID 0x84
#define VPD_MAN_NET_ADDR  0x85
#define VPD_EXT_INQ  0x86               /* Extended Inquiry */
#define VPD_MODE_PG_POLICY  0x87
#define VPD_SCSI_PORTS  0x88
#define VPD_ATA_INFO  0x89
#define VPD_POWER_CONDITION  0x8a
#define VPD_DEVICE_CONSTITUENTS 0x8b
#define VPD_CFA_PROFILE_INFO  0x8c
#define VPD_POWER_CONSUMPTION  0x8d
#define VPD_3PARTY_COPY  0x8f
#define VPD_PROTO_LU 0x90
#define VPD_PROTO_PORT 0x91
#define VPD_SCSI_FEATURE_SETS 0x92      /* spc5r11 */
#define VPD_BLOCK_LIMITS 0xb0
#define VPD_BLOCK_DEV_CHARS 0xb1
#define VPD_MAN_ASS_SN 0xb1
#define VPD_LB_PROVISIONING 0xb2
#define VPD_REFERRALS 0xb3
#define VPD_SUP_BLOCK_LENS 0xb4         /* sbc4r01 */
#define VPD_BLOCK_DEV_C_EXTENS 0xb5     /* sbc4r02 */
#define VPD_ZBC_DEV_CHARS 0xb6          /* zbc-r01b */
#define VPD_BLOCK_LIMITS_EXT 0xb7       /* sbc4r08 */
#define VPD_FORMAT_PRESETS 0xb8         /* sbc4r18 */

#ifndef SG_NVME_VPD_NICR
#define SG_NVME_VPD_NICR 0xde
#endif

#define VPD_NOPE_WANT_STD_INQ -2        /* request for standard inquiry */

/* Vendor specific VPD pages (typically >= 0xc0) */
#define VPD_UPR_EMC 0xc0
#define VPD_RDAC_VERS 0xc2
#define VPD_RDAC_VAC 0xc9

/* values for selection one or more associations (2**vpd_assoc),
   except _AS_IS */
#define VPD_DI_SEL_LU 1
#define VPD_DI_SEL_TPORT 2
#define VPD_DI_SEL_TARGET 4
#define VPD_DI_SEL_AS_IS 32

#define DEF_ALLOC_LEN 252       /* highest 1 byte value that is modulo 4 */
#define SAFE_STD_INQ_RESP_LEN 36
#define MX_ALLOC_LEN (0xc000 + 0x80)
#define VPD_ATA_INFO_LEN  572

#define SENSE_BUFF_LEN  64       /* Arbitrary, could be larger */
#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define DEF_PT_TIMEOUT  60       /* 60 seconds */


static uint8_t * rsp_buff;
static uint8_t * free_rsp_buff;
static const int rsp_buff_sz = MX_ALLOC_LEN + 1;

static char xtra_buff[MX_ALLOC_LEN + 1];
static char usn_buff[MX_ALLOC_LEN + 1];

static const char * find_version_descriptor_str(int value);
static void decode_dev_ids(const char * leadin, uint8_t * buff,
                           int len, int do_hex, int verbose);

#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS) && \
    defined(HDIO_GET_IDENTITY)
static int try_ata_identify(int ata_fd, int do_hex, int do_raw,
                            int verbose);
struct opts_t;
static void prepare_ata_identify(const struct opts_t * op, int inhex_len);
#endif

/* This structure is a duplicate of one of the same name in sg_vpd_vendor.c .
   Take care that both have the same fields (and types). */
struct svpd_values_name_t {
    int value;
    int subvalue;
    int pdt;         /* peripheral device type id, -1 is the default */
                     /* (all or not applicable) value */
    int vendor;      /* vendor flag */
    const char * acron;
    const char * name;
};

/* Note that this table is sorted by acronym */
static struct svpd_values_name_t vpd_pg[] = {
    {VPD_ATA_INFO, 0, -1, 0, "ai", "ATA information (SAT)"},
    {VPD_BLOCK_DEV_CHARS, 0, 0, 0, "bdc",
     "Block device characteristics (SBC)"},
    {VPD_BLOCK_DEV_C_EXTENS, 0, 0, 0, "bdce", "Block device characteristics "
     "extension (SBC)"},
    {VPD_BLOCK_LIMITS, 0, 0, 0, "bl", "Block limits (SBC)"},
    {VPD_BLOCK_LIMITS_EXT, 0, 0, 0, "ble", "Block limits extension (SBC)"},
    {VPD_DEVICE_ID, 0, -1, 0, "di", "Device identification"},
#if 0           /* following found in sg_vpd */
    {VPD_DEVICE_ID, VPD_DI_SEL_AS_IS, -1, 0, "di_asis", "Like 'di' "
     "but designators ordered as found"},
    {VPD_DEVICE_ID, VPD_DI_SEL_LU, -1, 0, "di_lu", "Device identification, "
     "lu only"},
    {VPD_DEVICE_ID, VPD_DI_SEL_TPORT, -1, 0, "di_port", "Device "
     "identification, target port only"},
    {VPD_DEVICE_ID, VPD_DI_SEL_TARGET, -1, 0, "di_target", "Device "
     "identification, target device only"},
#endif
    {VPD_EXT_INQ, 0, -1, 0, "ei", "Extended inquiry data"},
    {VPD_FORMAT_PRESETS, 0, 0, 0, "fp", "Format presets"},
    {VPD_LB_PROVISIONING, 0, 0, 0, "lbpv", "Logical block provisioning "
     "(SBC)"},
    {VPD_MAN_NET_ADDR, 0, -1, 0, "mna", "Management network addresses"},
    {VPD_MODE_PG_POLICY, 0, -1, 0, "mpp", "Mode page policy"},
    {VPD_POWER_CONDITION, 0, -1, 0, "po", "Power condition"},
    {VPD_POWER_CONSUMPTION, 0, -1, 0, "psm", "Power consumption"},
    {VPD_PROTO_LU, 0, 0x0, 0, "pslu", "Protocol-specific logical unit "
     "information"},
    {VPD_PROTO_PORT, 0, 0x0, 0, "pspo", "Protocol-specific port information"},
    {VPD_REFERRALS, 0, 0, 0, "ref", "Referrals (SBC)"},
    {VPD_SUP_BLOCK_LENS, 0, 0, 0, "sbl", "Supported block lengths and "
     "protection types (SBC)"},
    {VPD_SCSI_FEATURE_SETS, 0, -1, 0, "sfs", "SCSI Feature sets"},
    {VPD_SOFTW_INF_ID, 0, -1, 0, "sii", "Software interface identification"},
    {VPD_NOPE_WANT_STD_INQ, 0, -1, 0, "sinq", "Standard inquiry response"},
    {VPD_UNIT_SERIAL_NUM, 0, -1, 0, "sn", "Unit serial number"},
    {VPD_SCSI_PORTS, 0, -1, 0, "sp", "SCSI ports"},
    {VPD_SUPPORTED_VPDS, 0, -1, 0, "sv", "Supported VPD pages"},
    {VPD_3PARTY_COPY, 0, -1, 0, "tpc", "Third party copy"},
    {VPD_ZBC_DEV_CHARS, 0, -1, 0, "zbdch", "Zoned block device "
     "characteristics"},
    /* Following are vendor specific */
    {SG_NVME_VPD_NICR, 0, -1, 1, "nicr",
     "NVMe Identify Controller Response (sg3_utils)"},
    {VPD_RDAC_VAC, 0, -1, 1, "rdac_vac", "RDAC volume access control (RDAC)"},
    {VPD_RDAC_VERS, 0, -1, 1, "rdac_vers", "RDAC software version (RDAC)"},
    {VPD_UPR_EMC, 0, -1, 1, "upr", "Unit path report (EMC)"},
    {0, 0, 0, 0, NULL, NULL},
};

static struct option long_options[] = {
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS) && \
    defined(HDIO_GET_IDENTITY)
        {"ata", no_argument, 0, 'a'},
#endif
        {"block", required_argument, 0, 'B'},
        {"cmddt", no_argument, 0, 'c'},
        {"descriptors", no_argument, 0, 'd'},
        {"export", no_argument, 0, 'u'},
        {"extended", no_argument, 0, 'x'},
        {"force", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"id", no_argument, 0, 'i'},
        {"inhex", required_argument, 0, 'I'},
        {"len", required_argument, 0, 'l'},
        {"long", no_argument, 0, 'L'},
        {"maxlen", required_argument, 0, 'm'},
#ifdef SG_SCSI_STRINGS
        {"new", no_argument, 0, 'N'},
        {"old", no_argument, 0, 'O'},
#endif
        {"only", no_argument, 0, 'o'},
        {"page", required_argument, 0, 'p'},
        {"raw", no_argument, 0, 'r'},
        {"vendor", no_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"vpd", no_argument, 0, 'e'},
        {0, 0, 0, 0},
};

struct opts_t {
    bool do_ata;
    bool do_decode;
    bool do_descriptors;
    bool do_export;
    bool do_force;
    bool do_only;  /* --only  after standard inq don't fetch VPD page 0x80 */
    bool verbose_given;
    bool version_given;
    bool do_vpd;
    bool page_given;
    bool possible_nvme;
    int do_block;
    int do_cmddt;
    int do_help;
    int do_hex;
    int do_long;
    int do_raw;
    int do_vendor;
    int verbose;
    int resp_len;
    int page_num;
    int page_pdt;
    int num_pages;
    const char * page_arg;
    const char * device_name;
    const char * inhex_fn;
#ifdef SG_SCSI_STRINGS
    bool opt_new;
#endif
};


static void
usage()
{
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS) && \
    defined(HDIO_GET_IDENTITY)

    pr2serr("Usage: sg_inq [--ata] [--block=0|1] [--cmddt] [--descriptors] "
            "[--export]\n"
            "              [--extended] [--help] [--hex] [--id] [--inhex=FN] "
            "[--len=LEN]\n"
            "              [--long] [--maxlen=LEN] [--only] [--page=PG] "
            "[--raw]\n"
            "              [--vendor] [--verbose] [--version] [--vpd] "
            "DEVICE\n"
            "  where:\n"
            "    --ata|-a        treat DEVICE as (directly attached) ATA "
            "device\n");
#else
    pr2serr("Usage: sg_inq [--block=0|1] [--cmddt] [--descriptors] "
            "[--export]\n"
            "              [--extended] [--help] [--hex] [--id] [--inhex=FN] "
            "[--len=LEN]\n"
            "              [--long] [--maxlen=LEN] [--only] [--page=PG] "
            "[--raw]\n"
            "              [--verbose] [--version] [--vpd] DEVICE\n"
            "  where:\n");
#endif
    pr2serr("    --block=0|1     0-> open(non-blocking); 1-> "
            "open(blocking)\n"
            "      -B 0|1        (def: depends on OS; Linux pt: 0)\n"
            "    --cmddt|-c      command support data mode (set opcode "
            "with '--page=PG')\n"
            "                    use twice for list of supported "
            "commands; obsolete\n"
            "    --descriptors|-d    fetch and decode version descriptors\n"
            "    --export|-u     SCSI_IDENT_<assoc>_<type>=<ident> output "
            "format.\n"
            "                    Defaults to device id page (0x83) if --page "
            "not given,\n"
            "                    only supported for VPD pages 0x80 and 0x83\n"
            "    --extended|-E|-x    decode extended INQUIRY data VPD page "
            "(0x86)\n"
            "    --force|-f      skip VPD page 0 check; directly fetch "
            "requested page\n"
            "    --help|-h       print usage message then exit\n"
            "    --hex|-H        output response in hex\n"
            "    --id|-i         decode device identification VPD page "
            "(0x83)\n"
            "    --inhex=FN|-I FN    read ASCII hex from file FN instead of "
            "DEVICE;\n"
            "                        if used with --raw then read binary "
            "from FN\n"
            "    --len=LEN|-l LEN    requested response length (def: 0 "
            "-> fetch 36\n"
            "                        bytes first, then fetch again as "
            "indicated)\n"
            "    --long|-L       supply extra information on NVMe devices\n"
            "    --maxlen=LEN|-m LEN    same as '--len='\n"
            "    --old|-O        use old interface (use as first option)\n"
            "    --only|-o       for std inquiry do not fetch serial number "
            "vpd page;\n"
            "                    for NVMe device only do Identify "
            "controller\n"
            "    --page=PG|-p PG     Vital Product Data (VPD) page number "
            "or\n"
            "                        abbreviation (opcode number if "
            "'--cmddt' given)\n"
            "    --raw|-r        output response in binary (to stdout)\n"
            "    --vendor|-s     show vendor specific fields in std "
            "inquiry\n"
            "    --verbose|-v    increase verbosity\n"
            "    --version|-V    print version string then exit\n"
            "    --vpd|-e        vital product data (set page with "
            "'--page=PG')\n\n"
            "Performs a SCSI INQUIRY command on DEVICE or decodes INQUIRY "
            "response\nheld in file FN. If no options given then does a "
            "'standard' INQUIRY.\nCan list VPD pages with '--vpd' or "
            "'--page=PG' option. The sg_vpd\nand sdparm utilities decode "
            "more VPD pages than this utility.\n");
}

#ifdef SG_SCSI_STRINGS
static void
usage_old()
{
#ifdef SG_LIB_LINUX
    pr2serr("Usage:  sg_inq [-a] [-A] [-b] [-B=0|1] [-c] [-cl] [-d] [-e] "
            "[-h]\n"
            "               [-H] [-i] [I=FN] [-l=LEN] [-L] [-m] [-M] "
            "[-o]\n"
            "               [-p=VPD_PG] [-P] [-r] [-s] [-u] [-U] [-v] [-V] "
            "[-x]\n"
            "               [-36] [-?] DEVICE\n"
            "  where:\n"
            "    -a    decode ATA information VPD page (0x89)\n"
            "    -A    treat <device> as (directly attached) ATA device\n");
#else
    pr2serr("Usage:  sg_inq [-a] [-b] [-B 0|1] [-c] [-cl] [-d] [-e] [-h] "
            "[-H]\n"
            "               [-i] [-l=LEN] [-L] [-m] [-M] [-o] "
            "[-p=VPD_PG]\n"
            "               [-P] [-r] [-s] [-u] [-v] [-V] [-x] [-36] "
            "[-?]\n"
            "               DEVICE\n"
            "  where:\n"
            "    -a    decode ATA information VPD page (0x89)\n");

#endif  /* SG_LIB_LINUX */
    pr2serr("    -b    decode Block limits VPD page (0xb0) (SBC)\n"
            "    -B=0|1    0-> open(non-blocking); 1->open(blocking)\n"
            "    -c    set CmdDt mode (use -o for opcode) [obsolete]\n"
            "    -cl   list supported commands using CmdDt mode [obsolete]\n"
            "    -d    decode: version descriptors or VPD page\n"
            "    -e    set VPD mode (use -p for page code)\n"
            "    -h    output in hex (ASCII to the right)\n"
            "    -H    output in hex (ASCII to the right) [same as '-h']\n"
            "    -i    decode device identification VPD page (0x83)\n"
            "    -I=FN    use ASCII hex in file FN instead of DEVICE\n"
            "    -l=LEN    requested response length (def: 0 "
            "-> fetch 36\n"
            "                    bytes first, then fetch again as "
            "indicated)\n"
            "    -L    supply extra information on NVMe devices\n"
            "    -m    decode management network addresses VPD page "
            "(0x85)\n"
            "    -M    decode mode page policy VPD page (0x87)\n"
            "    -N|--new   use new interface\n"
            "    -o    for std inquiry only do that, not serial number vpd "
            "page\n"
            "    -p=VPD_PG    vpd page code in hex (def: 0)\n"
            "    -P    decode Unit Path Report VPD page (0xc0) (EMC)\n"
            "    -r    output response in binary ('-rr': output for hdparm)\n"
            "    -s    decode SCSI Ports VPD page (0x88)\n"
            "    -u    SCSI_IDENT_<assoc>_<type>=<ident> output format\n"
            "    -v    verbose (output cdb and, if non-zero, resid)\n"
            "    -V    output version string\n"
            "    -x    decode extended INQUIRY data VPD page (0x86)\n"
            "    -36   perform standard INQUIRY with a 36 byte response\n"
            "    -?    output this usage message\n\n"
            "If no options given then does a standard SCSI INQUIRY\n");
}

static void
usage_for(const struct opts_t * op)
{
    if (op->opt_new)
        usage();
    else
        usage_old();
}

#else  /* SG_SCSI_STRINGS */

static void
usage_for(const struct opts_t * op)
{
    if (op) { }         /* suppress warning */
    usage();
}

#endif /* SG_SCSI_STRINGS */

/* Processes command line options according to new option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
new_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int c, n;

    while (1) {
        int option_index = 0;

#ifdef SG_LIB_LINUX
#ifdef SG_SCSI_STRINGS
        c = getopt_long(argc, argv, "aB:cdeEfhHiI:l:Lm:NoOp:rsuvVx",
                        long_options, &option_index);
#else
        c = getopt_long(argc, argv, "B:cdeEfhHiI:l:Lm:op:rsuvVx",
                        long_options, &option_index);
#endif /* SG_SCSI_STRINGS */
#else  /* SG_LIB_LINUX */
#ifdef SG_SCSI_STRINGS
        c = getopt_long(argc, argv, "B:cdeEfhHiI:l:Lm:NoOp:rsuvVx",
                        long_options, &option_index);
#else
        c = getopt_long(argc, argv, "B:cdeEfhHiI:l:Lm:op:rsuvVx",
                        long_options, &option_index);
#endif /* SG_SCSI_STRINGS */
#endif /* SG_LIB_LINUX */
        if (c == -1)
            break;

        switch (c) {
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS) && \
    defined(HDIO_GET_IDENTITY)
        case 'a':
            op->do_ata = true;
            break;
#endif
        case 'B':
            if ('-' == optarg[0])
                n = -1;
            else {
                n = sg_get_num(optarg);
                if ((n < 0) || (n > 1)) {
                    pr2serr("bad argument to '--block=' want 0 or 1\n");
                    usage_for(op);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            op->do_block = n;
            break;
        case 'c':
            ++op->do_cmddt;
            break;
        case 'd':
            op->do_descriptors = true;
            break;
        case 'e':
            op->do_vpd = true;
            break;
        case 'E':       /* --extended */
        case 'x':
            op->do_decode = true;
            op->do_vpd = true;
            op->page_num = VPD_EXT_INQ;
            op->page_given = true;
            break;
        case 'f':
            op->do_force = true;
            break;
        case 'h':
            ++op->do_help;
            break;
        case 'o':
            op->do_only = true;
            break;
        case '?':
            if (! op->do_help)
                ++op->do_help;
            break;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            op->do_decode = true;
            op->do_vpd = true;
            op->page_num = VPD_DEVICE_ID;
            op->page_given = true;
            break;
        case 'I':
            op->inhex_fn = optarg;
            break;
        case 'l':
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 65532)) {
                pr2serr("bad argument to '--len='\n");
                usage_for(op);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->resp_len = n;
            break;
        case 'L':
            ++op->do_long;
            break;
#ifdef SG_SCSI_STRINGS
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = false;
            return 0;
#endif
        case 'p':
            op->page_arg = optarg;
            op->page_given = true;
            break;
        case 'r':
            ++op->do_raw;
            break;
        case 's':
            ++op->do_vendor;
            break;
        case 'u':
            op->do_export = true;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x]\n", c, c);
            if (op->do_help)
                break;
            usage_for(op);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == op->device_name) {
            op->device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage_for(op);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

#ifdef SG_SCSI_STRINGS
/* Processes command line options according to old option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
old_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    bool jmp_out;
    int k, plen, num, n;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case '3':
                    if ('6' == *(cp + 1)) {
                        op->resp_len = 36;
                        --plen;
                        ++cp;
                    } else
                        jmp_out = true;
                    break;
                case 'a':
                    op->page_num = VPD_ATA_INFO;
                    op->do_vpd = true;
                    op->page_given = true;
                    ++op->num_pages;
                    break;
#ifdef SG_LIB_LINUX
                case 'A':
                    op->do_ata = true;
                    break;
#endif
                case 'b':
                    op->page_num = VPD_BLOCK_LIMITS;
                    op->do_vpd = true;
                    op->page_given = true;
                    ++op->num_pages;
                    break;
                case 'c':
                    ++op->do_cmddt;
                    if ('l' == *(cp + 1)) {
                        ++op->do_cmddt;
                        --plen;
                        ++cp;
                    }
                    break;
                case 'd':
                    op->do_descriptors = true;
                    op->do_decode = true;
                    break;
                case 'e':
                    op->do_vpd = true;
                    break;
                case 'f':
                    op->do_force = true;
                    break;
                case 'h':
                case 'H':
                    ++op->do_hex;
                    break;
                case 'i':
                    op->page_num = VPD_DEVICE_ID;
                    op->do_vpd = true;
                    op->page_given = true;
                    ++op->num_pages;
                    break;
                case 'L':
                    ++op->do_long;
                    break;
                case 'm':
                    op->page_num = VPD_MAN_NET_ADDR;
                    op->do_vpd = true;
                    ++op->num_pages;
                    op->page_given = true;
                    break;
                case 'M':
                    op->page_num = VPD_MODE_PG_POLICY;
                    op->do_vpd = true;
                    op->page_given = true;
                    ++op->num_pages;
                    break;
                case 'N':
                    op->opt_new = true;
                    return 0;
                case 'o':
                    op->do_only = true;
                    break;
                case 'O':
                    break;
                case 'P':
                    op->page_num = VPD_UPR_EMC;
                    op->do_vpd = true;
                    op->page_given = true;
                    ++op->num_pages;
                    break;
                case 'r':
                    ++op->do_raw;
                    break;
                case 's':
                    op->page_num = VPD_SCSI_PORTS;
                    op->do_vpd = true;
                    op->page_given = true;
                    ++op->num_pages;
                    break;
                case 'u':
                    op->do_export = true;
                    break;
                case 'v':
                    op->verbose_given = true;
                    ++op->verbose;
                    break;
                case 'V':
                    op->version_given = true;
                    break;
                case 'x':
                    op->page_num = VPD_EXT_INQ;
                    op->do_vpd = true;
                    op->page_given = true;
                    ++op->num_pages;
                    break;
                case '?':
                    if (! op->do_help)
                        ++op->do_help;
                    break;
                default:
                    jmp_out = true;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            else if (0 == strncmp("B=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n < 0) || (n > 1)) {
                    pr2serr("'B=' option expects 0 or 1\n");
                    usage_for(op);
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->do_block = n;
            } else if (0 == strncmp("I=", cp, 2))
                op->inhex_fn = cp + 2;
            else if (0 == strncmp("l=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n < 1)) {
                    pr2serr("Inappropriate value after 'l=' option\n");
                    usage_for(op);
                    return SG_LIB_SYNTAX_ERROR;
                } else if (n > MX_ALLOC_LEN) {
                    pr2serr("value after 'l=' option too large\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->resp_len = n;
            } else if (0 == strncmp("p=", cp, 2)) {
                op->page_arg = cp + 2;
                op->page_given = true;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage_for(op);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == op->device_name)
            op->device_name = cp;
        else {
            pr2serr("too many arguments, got: %s, not expecting: %s\n",
                    op->device_name, cp);
            usage_for(op);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

/* Process command line options. First check using new option format unless
 * the SG3_UTILS_OLD_OPTS environment variable is defined which causes the
 * old option format to be checked first. Both new and old format can be
 * countermanded by a '-O' and '-N' options respectively. As soon as either
 * of these options is detected (when processing the other format), processing
 * stops and is restarted using the other format. Clear? */
static int
parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opt_new = false;
        res = old_parse_cmd_line(op, argc, argv);
        if ((0 == res) && op->opt_new)
            res = new_parse_cmd_line(op, argc, argv);
    } else {
        op->opt_new = true;
        res = new_parse_cmd_line(op, argc, argv);
        if ((0 == res) && (! op->opt_new))
            res = old_parse_cmd_line(op, argc, argv);
    }
    return res;
}

#else  /* SG_SCSI_STRINGS */

static int
parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    return new_parse_cmd_line(op, argc, argv);
}

#endif  /* SG_SCSI_STRINGS */


static const struct svpd_values_name_t *
sdp_find_vpd_by_acron(const char * ap)
{
    const struct svpd_values_name_t * vnp;

    for (vnp = vpd_pg; vnp->acron; ++vnp) {
        if (0 == strcmp(vnp->acron, ap))
            return vnp;
    }
    return NULL;
}

static void
enumerate_vpds()
{
    const struct svpd_values_name_t * vnp;

    for (vnp = vpd_pg; vnp->acron; ++vnp) {
        if (vnp->name) {
            if (vnp->value < 0)
                printf("  %-10s   -1      %s\n", vnp->acron, vnp->name);
            else
                printf("  %-10s 0x%02x      %s\n", vnp->acron, vnp->value,
                       vnp->name);
        }
    }
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* Strip initial and trailing whitespaces; convert one or repeated
 * whitespaces to a single "_"; convert non-printable characters to "."
 * and if there are no valid (i.e. printable) characters return 0.
 * Process 'str' in place (i.e. it's input and output) and return the
 * length of the output, excluding the trailing '\0'. To cover any
 * potential unicode string an intermediate zero is skipped; two
 * consecutive zeroes indicate a string termination.
 */
static int
encode_whitespaces(uint8_t *str, int inlen)
{
    int k, res;
    int j;
    bool valid = false;
    int outlen = inlen, zeroes = 0;

    /* Skip initial whitespaces */
    for (j = 0; (j < inlen) && isblank(str[j]); ++j)
        ;
    if (j < inlen) {
        /* Skip possible unicode prefix characters */
        for ( ; (j < inlen) && (str[j] < 0x20); ++j)
            ;
    }
    k = j;
    /* Strip trailing whitespaces */
    while ((outlen > k) &&
           (isblank(str[outlen - 1]) || ('\0' == str[outlen - 1]))) {
        str[outlen - 1] = '\0';
        outlen--;
    }
    for (res = 0; k < outlen; ++k) {
        if (isblank(str[k])) {
            if ((res > 0) && ('_' != str[res - 1])) {
                str[res++] = '_';
                valid = true;
            }
            zeroes = 0;
        } else if (! isprint(str[k])) {
            if (str[k] == 0x00) {
                /* Stop on more than one consecutive zero */
                if (zeroes)
                    break;
                zeroes++;
                continue;
            }
            str[res++] = '.';
            zeroes = 0;
        } else {
            str[res++] = str[k];
            valid = true;
            zeroes = 0;
        }
    }
    if (! valid)
        res = 0;
    if (res < inlen)
        str[res] = '\0';
    return res;
}

static int
encode_unicode(uint8_t *str, int inlen)
{
    int k = 0, res;
    int zeroes = 0;

    for (res = 0; k < inlen; ++k) {
        if (str[k] == 0x00) {
            if (zeroes) {
                str[res++] = '\0';
                break;
            }
            zeroes++;
        } else {
            zeroes = 0;
            if (isprint(str[k]))
                str[res++] = str[k];
            else
                str[res++] = ' ';
        }
    }

    return res;
}

static int
encode_string(char *out, const uint8_t *in, int inlen)
{
    int i, j = 0;

    for (i = 0; (i < inlen); ++i) {
        if (isblank(in[i]) || !isprint(in[i])) {
            sprintf(&out[j], "\\x%02x", in[i]);
            j += 4;
        } else {
            out[j] = in[i];
            j++;
        }
    }
    out[j] = '\0';
    return j;
}

struct vpd_name {
    int number;
    int peri_type;
    const char * name;
};

/* In numerical order */
static struct vpd_name vpd_name_arr[] = {
    {VPD_SUPPORTED_VPDS, 0, "Supported VPD pages"},             /* 0x0 */
    {VPD_UNIT_SERIAL_NUM, 0, "Unit serial number"},             /* 0x80 */
    {0x81, 0, "Implemented operating definitions (obsolete)"},
    {0x82, 0, "ASCII implemented operating definition (obsolete)"},
    {VPD_DEVICE_ID, 0, "Device identification"},
    {VPD_SOFTW_INF_ID, 0, "Software interface identification"},
    {VPD_MAN_NET_ADDR, 0, "Management network addresses"},
    {VPD_EXT_INQ, 0, "Extended INQUIRY data"},
    {VPD_MODE_PG_POLICY, 0, "Mode page policy"},
    {VPD_SCSI_PORTS, 0, "SCSI ports"},
    {VPD_ATA_INFO, 0, "ATA information"},
    {VPD_POWER_CONDITION, 0, "Power condition"},
    {VPD_DEVICE_CONSTITUENTS, 0, "Device constituents"},
    {VPD_CFA_PROFILE_INFO, 0, "CFA profile information"},       /* 0x8c */
    {VPD_POWER_CONSUMPTION, 0, "Power consumption"},            /* 0x8d */
    {VPD_3PARTY_COPY, 0, "Third party copy"},                   /* 0x8f */
    {VPD_PROTO_LU, 0, "Protocol-specific logical unit information"}, /* 0x90 */
    {VPD_PROTO_PORT, 0, "Protocol-specific port information"},  /* 0x91 */
    {VPD_SCSI_FEATURE_SETS, 0, "SCSI Feature sets"},            /* 0x92 */
    /* 0xb0 to 0xbf are per peripheral device type */
    {VPD_BLOCK_LIMITS, 0, "Block limits (sbc2)"},               /* 0xb0 */
    {VPD_BLOCK_DEV_CHARS, 0, "Block device characteristics (sbc3)"},
    {VPD_LB_PROVISIONING, 0, "Logical block provisioning (sbc3)"},
    {VPD_REFERRALS, 0, "Referrals (sbc3)"},
    {0xb0, PDT_TAPE, "Sequential access device capabilities (ssc3)"},
    {0xb2, PDT_TAPE, "TapeAlert supported flags (ssc3)"},
    {0xb0, PDT_OSD, "OSD information (osd)"},
    {0xb1, PDT_OSD, "Security token (osd)"},
    /* 0xc0 to 0xff are vendor specific */
    {0xc0, 0, "vendor: Firmware numbers (seagate); Unit path report (EMC)"},
    {0xc1, 0, "vendor: Date code (seagate)"},
    {0xc2, 0, "vendor: Jumper settings (seagate); Software version (RDAC)"},
    {0xc3, 0, "vendor: Device behavior (seagate)"},
    {0xc9, 0, "Volume Access Control (RDAC)"},
};

static const char *
get_vpd_page_str(int vpd_page_num, int scsi_ptype)
{
    int k;
    int vpd_name_arr_sz = (int)SG_ARRAY_SIZE(vpd_name_arr);

    if ((vpd_page_num >= 0xb0) && (vpd_page_num < 0xc0)) {
        /* peripheral device type relevant for 0xb0..0xbf range */
        for (k = 0; k < vpd_name_arr_sz; ++k) {
            if ((vpd_name_arr[k].number == vpd_page_num) &&
                (vpd_name_arr[k].peri_type == scsi_ptype))
                break;
        }
        if (k < vpd_name_arr_sz)
            return vpd_name_arr[k].name;
        for (k = 0; k < vpd_name_arr_sz; ++k) {
            if ((vpd_name_arr[k].number == vpd_page_num) &&
                (vpd_name_arr[k].peri_type == 0))
                break;
        }
        if (k < vpd_name_arr_sz)
            return vpd_name_arr[k].name;
        else
            return NULL;
    } else {
        /* rest of 0x0..0xff range doesn't depend on peripheral type */
        for (k = 0; k < vpd_name_arr_sz; ++k) {
            if (vpd_name_arr[k].number == vpd_page_num)
                break;
        }
        if (k < vpd_name_arr_sz)
            return vpd_name_arr[k].name;
        else
            return NULL;
    }
}

static void
decode_supported_vpd(uint8_t * buff, int len, int do_hex)
{
    int vpd, k, rlen, pdt;
    const char * cp;

    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Supported VPD pages VPD page length too short=%d\n", len);
        return;
    }
    pdt = 0x1f & buff[0];
    rlen = buff[3] + 4;
    if (rlen > len)
        pr2serr("Supported VPD pages VPD page truncated, indicates %d, got "
                "%d\n", rlen, len);
    else
        len = rlen;
    printf("   Supported VPD pages:\n");
    for (k = 0; k < len - 4; ++k) {
        vpd = buff[4 + k];
        cp = get_vpd_page_str(vpd, pdt);
        if (cp)
            printf("     0x%x\t%s\n", vpd, cp);
        else
            printf("     0x%x\n", vpd);
    }
}

static bool
vpd_page_is_supported(uint8_t * vpd_pg0, int v0_len, int pg_num, int vb)
{
    int k, rlen;

    if (v0_len < 4)
        return false;

    rlen = vpd_pg0[3] + 4;
    if (rlen > v0_len)
        pr2serr("Supported VPD pages VPD page truncated, indicates %d, got "
                "%d\n", rlen, v0_len);
    else
        v0_len = rlen;
    if (vb > 1) {
        pr2serr("Supported VPD pages, hex list: ");
        hex2stderr(vpd_pg0 + 4, v0_len - 4, -1);
    }
    for (k = 4; k < v0_len; ++k) {
        if(vpd_pg0[k] == pg_num)
            return true;
    }
    return false;
}

static bool
vpd_page_not_supported(uint8_t * vpd_pg0, int v0_len, int pg_num, int vb)
{
    return ! vpd_page_is_supported(vpd_pg0, v0_len, pg_num, vb);
}

/* ASCII Information VPD pages (page numbers: 0x1 to 0x7f) */
static void
decode_ascii_inf(uint8_t * buff, int len, int do_hex)
{
    int al, k, bump;
    uint8_t * bp;
    uint8_t * p;

    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("ASCII information VPD page length too short=%d\n", len);
        return;
    }
    if (4 == len)
        return;
    al = buff[4];
    if ((al + 5) > len)
        al = len - 5;
    for (k = 0, bp = buff + 5; k < al; k += bump, bp += bump) {
        p = (uint8_t *)memchr(bp, 0, al - k);
        if (! p) {
            printf("  %.*s\n", al - k, (const char *)bp);
            break;
        }
        printf("  %s\n", (const char *)bp);
        bump = (p - bp) + 1;
    }
    bp = buff + 5 + al;
    if (bp < (buff + len)) {
        printf("Vendor specific information in hex:\n");
        hex2stdout(bp, len - (al + 5), 0);
    }
}

static void
decode_id_vpd(uint8_t * buff, int len, int do_hex, int verbose)
{
    if (len < 4) {
        pr2serr("Device identification VPD page length too "
                "short=%d\n", len);
        return;
    }
    decode_dev_ids("Device identification", buff + 4, len - 4, do_hex,
                   verbose);
}

static const char * assoc_arr[] =
{
    "addressed logical unit",
    "target port",      /* that received request; unless SCSI ports VPD */
    "target device that contains addressed lu",
    "reserved [0x3]",
};

static const char * network_service_type_arr[] =
{
    "unspecified",
    "storage configuration service",
    "diagnostics",
    "status",
    "logging",
    "code download",
    "copy service",
    "administrative configuration service",
    "[0x8]", "[0x9]", "[0xa]", "[0xb]", "[0xc]", "[0xd]",
    "[0xe]", "[0xf]", "[0x10]", "[0x11]", "[0x12]", "[0x13]", "[0x14]",
    "[0x15]", "[0x16]", "[0x17]", "[0x18]", "[0x19]", "[0x1a]",
    "[0x1b]", "[0x1c]", "[0x1d]", "[0x1e]", "[0x1f]",
};

/* VPD_MAN_NET_ADDR */
static void
decode_net_man_vpd(uint8_t * buff, int len, int do_hex)
{
    int k, bump, na_len;
    uint8_t * bp;

    if (len < 4) {
        pr2serr("Management network addresses VPD page length too short=%d\n",
                len);
        return;
    }
    if (do_hex > 2) {
        hex2stdout(buff, len, -1);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        printf("  %s, Service type: %s\n",
               assoc_arr[(bp[0] >> 5) & 0x3],
               network_service_type_arr[bp[0] & 0x1f]);
        na_len = sg_get_unaligned_be16(bp + 2);
        bump = 4 + na_len;
        if ((k + bump) > len) {
            pr2serr("Management network addresses VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (na_len > 0) {
            if (do_hex) {
                printf("    Network address:\n");
                hex2stdout(bp + 4, na_len, 0);
            } else
                printf("    %s\n", bp + 4);
        }
    }
}

static const char * mode_page_policy_arr[] =
{
    "shared",
    "per target port",
    "per initiator port",
    "per I_T nexus",
};

/* VPD_MODE_PG_POLICY */
static void
decode_mode_policy_vpd(uint8_t * buff, int len, int do_hex)
{
    int k, bump;
    uint8_t * bp;

    if (len < 4) {
        pr2serr("Mode page policy VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex > 2) {
        hex2stdout(buff, len, -1);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            pr2serr("Mode page policy VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (do_hex)
            hex2stdout(bp, 4, (1 == do_hex) ? 1 : -1);
        else {
            printf("  Policy page code: 0x%x", (bp[0] & 0x3f));
            if (bp[1])
                printf(",  subpage code: 0x%x\n", bp[1]);
            else
                printf("\n");
            printf("    MLUS=%d,  Policy: %s\n", !!(bp[2] & 0x80),
                   mode_page_policy_arr[bp[2] & 0x3]);
        }
    }
}

/* VPD_SCSI_PORTS */
static void
decode_scsi_ports_vpd(uint8_t * buff, int len, int do_hex, int verbose)
{
    int k, bump, rel_port, ip_tid_len, tpd_len;
    uint8_t * bp;

    if (len < 4) {
        pr2serr("SCSI Ports VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex > 2) {
        hex2stdout(buff, len, -1);
        return;
    }
    len -= 4;
    bp = buff + 4;
    for (k = 0; k < len; k += bump, bp += bump) {
        rel_port = sg_get_unaligned_be16(bp + 2);
        printf("Relative port=%d\n", rel_port);
        ip_tid_len = sg_get_unaligned_be16(bp + 6);
        bump = 8 + ip_tid_len;
        if ((k + bump) > len) {
            pr2serr("SCSI Ports VPD page, short descriptor "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (ip_tid_len > 0) {
            if (do_hex) {
                printf(" Initiator port transport id:\n");
                hex2stdout((bp + 8), ip_tid_len, (1 == do_hex) ? 1 : -1);
            } else {
                char b[1024];

                printf("%s", sg_decode_transportid_str(" ", bp + 8,
                                 ip_tid_len, true, sizeof(b), b));
            }
        }
        tpd_len = sg_get_unaligned_be16(bp + bump + 2);
        if ((k + bump + tpd_len + 4) > len) {
            pr2serr("SCSI Ports VPD page, short descriptor(tgt) "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (tpd_len > 0) {
            printf(" Target port descriptor(s):\n");
            if (do_hex)
                hex2stdout(bp + bump + 4, tpd_len, (1 == do_hex) ? 1 : -1);
            else
                decode_dev_ids("SCSI Ports", bp + bump + 4, tpd_len,
                               do_hex, verbose);
        }
        bump += tpd_len + 4;
    }
}

/* These are target port, device server (i.e. target) and LU identifiers */
static void
decode_dev_ids(const char * leadin, uint8_t * buff, int len, int do_hex,
               int verbose)
{
    int u, j, m, id_len, p_id, c_set, piv, assoc, desig_type, i_len;
    int off, ci_off, c_id, d_id, naa, vsi, k;
    uint64_t vsei;
    uint64_t id_ext;
    const uint8_t * bp;
    const uint8_t * ip;
    char b[64];
    const char * cp;

    if (buff[2] != 0) {
        /*
         * Reference the 3rd byte of the first Identification descriptor
         * of a page 83 reply to determine whether the reply is compliant
         * with SCSI-2 or SPC-2/3 specifications.  A zero value in the
         * 3rd byte indicates an SPC-2/3 conforming reply ( the field is
         * reserved ).  This byte will be non-zero for a SCSI-2
         * conforming page 83 reply from these EMC Symmetrix models since
         * the 7th byte of the reply corresponds to the 4th and 5th
         * nibbles of the 6-byte OUI for EMC, that is, 0x006048.
         */
        i_len = len;
        ip = bp = buff;
        c_set = 1;
        assoc = 0;
        piv = 0;
        p_id = 0xf;
        desig_type = 3;
        j = 1;
        off = 16;
        printf("  Pre-SPC descriptor, descriptor length: %d\n", i_len);
        goto decode;
    }

    for (j = 1, off = -1;
         (u = sg_vpd_dev_id_iter(buff, len, &off, -1, -1, -1)) == 0;
         ++j) {
        bp = buff + off;
        i_len = bp[3];
        id_len = i_len + 4;
        printf("  Designation descriptor number %d, "
               "descriptor length: %d\n", j, id_len);
        if ((off + id_len) > len) {
            pr2serr("%s VPD page error: designator length longer "
                    "than\n     remaining response length=%d\n", leadin,
                    (len - off));
            return;
        }
        ip = bp + 4;
        p_id = ((bp[0] >> 4) & 0xf);   /* protocol identifier */
        c_set = (bp[0] & 0xf);         /* code set */
        piv = ((bp[1] & 0x80) ? 1 : 0); /* protocol identifier valid */
        assoc = ((bp[1] >> 4) & 0x3);
        desig_type = (bp[1] & 0xf);
  decode:
        if (piv && ((1 == assoc) || (2 == assoc)))
            printf("    transport: %s\n",
                   sg_get_trans_proto_str(p_id, sizeof(b), b));
        cp = sg_get_desig_type_str(desig_type);
        printf("    designator_type: %s,  ", cp ? cp : "-");
        cp = sg_get_desig_code_set_str(c_set);
        printf("code_set: %s\n", cp ? cp : "-");
        cp = sg_get_desig_assoc_str(assoc);
        printf("    associated with the %s\n", cp ? cp : "-");
        if (do_hex) {
            printf("    designator header(hex): %.2x %.2x %.2x %.2x\n",
                   bp[0], bp[1], bp[2], bp[3]);
            printf("    designator:\n");
            hex2stdout(ip, i_len, 0);
            continue;
        }
        switch (desig_type) {
        case 0: /* vendor specific */
            k = 0;
            if ((2 == c_set) || (3 == c_set)) { /* ASCII or UTF-8 */
                for (k = 0; (k < i_len) && isprint(ip[k]); ++k)
                    ;
                if (k >= i_len)
                    k = 1;
            }
            if (k)
                printf("      vendor specific: %.*s\n", i_len, ip);
            else {
                printf("      vendor specific:\n");
                hex2stdout(ip, i_len, -1);
            }
            break;
        case 1: /* T10 vendor identification */
            printf("      vendor id: %.8s\n", ip);
            if (i_len > 8) {
                if ((2 == c_set) || (3 == c_set)) { /* ASCII or UTF-8 */
                    printf("      vendor specific: %.*s\n", i_len - 8, ip + 8);
                } else {
                    printf("      vendor specific: 0x");
                    for (m = 8; m < i_len; ++m)
                        printf("%02x", (unsigned int)ip[m]);
                    printf("\n");
                }
            }
            break;
        case 2: /* EUI-64 based */
            printf("      EUI-64 based %d byte identifier\n", i_len);
            if (1 != c_set) {
                pr2serr("      << expected binary code_set (1)>>\n");
                hex2stderr(ip, i_len, -1);
                break;
            }
            ci_off = 0;
            if (16 == i_len) {
                ci_off = 8;
                id_ext = sg_get_unaligned_be64(ip);
                printf("      Identifier extension: 0x%" PRIx64 "\n", id_ext);
            } else if ((8 != i_len) && (12 != i_len)) {
                pr2serr("      << can only decode 8, 12 and 16 "
                        "byte ids>>\n");
                hex2stderr(ip, i_len, -1);
                break;
            }
            c_id = sg_get_unaligned_be24(ip + ci_off);
            printf("      IEEE Company_id: 0x%x\n", c_id);
            vsei = sg_get_unaligned_be48(ip + ci_off + 3);
            printf("      Vendor Specific Extension Identifier: 0x%" PRIx64
                   "\n", vsei);
            if (12 == i_len) {
                d_id = sg_get_unaligned_be32(ip + 8);
                printf("      Directory ID: 0x%x\n", d_id);
            }
            printf("      [0x");
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("]\n");
            break;
        case 3: /* NAA <n> */
            naa = (ip[0] >> 4) & 0xff;
            if (1 != c_set) {
                pr2serr("      << expected binary code_set (1), got %d for "
                        "NAA=%d>>\n", c_set, naa);
                hex2stderr(ip, i_len, -1);
                break;
            }
            switch (naa) {
            case 2:     /* NAA 2: IEEE Extended */
                if (8 != i_len) {
                    pr2serr("      << unexpected NAA 2 identifier "
                            "length: 0x%x>>\n", i_len);
                    hex2stderr(ip, i_len, -1);
                    break;
                }
                d_id = (((ip[0] & 0xf) << 8) | ip[1]);
                c_id = sg_get_unaligned_be24(ip + 2);
                vsi = sg_get_unaligned_be24(ip + 5);
                printf("      NAA 2, vendor specific identifier A: 0x%x\n",
                       d_id);
                printf("      IEEE Company_id: 0x%x\n", c_id);
                printf("      vendor specific identifier B: 0x%x\n", vsi);
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
                break;
            case 3:     /* NAA 3: Locally assigned */
                if (8 != i_len) {
                    pr2serr("      << unexpected NAA 3 identifier "
                            "length: 0x%x>>\n", i_len);
                    hex2stderr(ip, i_len, -1);
                    break;
                }
                printf("      NAA 3, Locally assigned:\n");
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
                break;
            case 5:     /* NAA 5: IEEE Registered */
                if (8 != i_len) {
                    pr2serr("      << unexpected NAA 5 identifier "
                            "length: 0x%x>>\n", i_len);
                    hex2stderr(ip, i_len, -1);
                    break;
                }
                c_id = (((ip[0] & 0xf) << 20) | (ip[1] << 12) |
                        (ip[2] << 4) | ((ip[3] & 0xf0) >> 4));
                vsei = ip[3] & 0xf;
                for (m = 1; m < 5; ++m) {
                    vsei <<= 8;
                    vsei |= ip[3 + m];
                }
                printf("      NAA 5, IEEE Company_id: 0x%x\n", c_id);
                printf("      Vendor Specific Identifier: 0x%" PRIx64
                       "\n", vsei);
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
                break;
            case 6:     /* NAA 6: IEEE Registered extended */
                if (16 != i_len) {
                    pr2serr("      << unexpected NAA 6 identifier "
                            "length: 0x%x>>\n", i_len);
                    hex2stderr(ip, i_len, 0);
                    break;
                }
                c_id = (((ip[0] & 0xf) << 20) | (ip[1] << 12) |
                        (ip[2] << 4) | ((ip[3] & 0xf0) >> 4));
                vsei = ip[3] & 0xf;
                for (m = 1; m < 5; ++m) {
                    vsei <<= 8;
                    vsei |= ip[3 + m];
                }
                printf("      NAA 6, IEEE Company_id: 0x%x\n", c_id);
                printf("      Vendor Specific Identifier: 0x%" PRIx64 "\n",
                       vsei);
                vsei = sg_get_unaligned_be64(ip + 8);
                printf("      Vendor Specific Identifier Extension: "
                       "0x%" PRIx64 "\n", vsei);
                printf("      [0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
                break;
            default:
                pr2serr("      << bad NAA nibble , expect 2, 3, 5 or 6, "
                        "got %d>>\n", naa);
                hex2stderr(ip, i_len, -1);
                break;
            }
            break;
        case 4: /* Relative target port */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                pr2serr("      << expected binary code_set, target "
                        "port association, length 4>>\n");
                hex2stderr(ip, i_len, -1);
                break;
            }
            d_id = sg_get_unaligned_be16(ip + 2);
            printf("      Relative target port: 0x%x\n", d_id);
            break;
        case 5: /* (primary) Target port group */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                pr2serr("      << expected binary code_set, target "
                        "port association, length 4>>\n");
                hex2stderr(ip, i_len, -1);
                break;
            }
            d_id = sg_get_unaligned_be16(ip + 2);
            printf("      Target port group: 0x%x\n", d_id);
            break;
        case 6: /* Logical unit group */
            if ((1 != c_set) || (0 != assoc) || (4 != i_len)) {
                pr2serr("      << expected binary code_set, logical "
                        "unit association, length 4>>\n");
                hex2stderr(ip, i_len, -1);
                break;
            }
            d_id = sg_get_unaligned_be16(ip + 2);
            printf("      Logical unit group: 0x%x\n", d_id);
            break;
        case 7: /* MD5 logical unit identifier */
            if ((1 != c_set) || (0 != assoc)) {
                pr2serr("      << expected binary code_set, logical "
                        "unit association>>\n");
                hex2stderr(ip, i_len, -1);
                break;
            }
            printf("      MD5 logical unit identifier:\n");
            hex2stdout(ip, i_len, -1);
            break;
        case 8: /* SCSI name string */
            if (3 != c_set) {
                if (2 == c_set) {
                    if (verbose)
                        pr2serr("      << expected UTF-8, use ASCII>>\n");
                } else {
                    pr2serr("      << expected UTF-8 code_set>>\n");
                    hex2stderr(ip, i_len, -1);
                    break;
                }
            }
            printf("      SCSI name string:\n");
            /* does %s print out UTF-8 ok??
             * Seems to depend on the locale. Looks ok here with my
             * locale setting: en_AU.UTF-8
             */
            printf("      %.*s\n", i_len, (const char *)ip);
            break;
        case 9: /* Protocol specific port identifier */
            /* added in spc4r36, PIV must be set, proto_id indicates */
            /* whether UAS (USB) or SOP (PCIe) or ... */
            if (! piv)
                printf("      >>>> Protocol specific port identifier "
                       "expects protocol\n"
                       "           identifier to be valid and it is not\n");
            if (TPROTO_UAS == p_id) {
                printf("      USB device address: 0x%x\n", 0x7f & ip[0]);
                printf("      USB interface number: 0x%x\n", ip[2]);
            } else if (TPROTO_SOP == p_id) {
                printf("      PCIe routing ID, bus number: 0x%x\n", ip[0]);
                printf("          function number: 0x%x\n", ip[1]);
                printf("          [or device number: 0x%x, function number: "
                       "0x%x]\n", (0x1f & (ip[1] >> 3)), 0x7 & ip[1]);
            } else
                printf("      >>>> unexpected protocol indentifier: %s\n"
                       "           with Protocol specific port "
                       "identifier\n",
                       sg_get_trans_proto_str(p_id, sizeof(b), b));
            break;
        case 0xa: /* UUID identifier [spc5r08] RFC 4122 */
            if (1 != c_set) {
                pr2serr("      << expected binary code_set >>\n");
                hex2stderr(ip, i_len, 0);
                break;
            }
            if ((1 != ((ip[0] >> 4) & 0xf)) || (18 != i_len)) {
                pr2serr("      << expected locally assigned UUID, 16 bytes "
                        "long >>\n");
                hex2stderr(ip, i_len, 0);
                break;
            }
            printf("      Locally assigned UUID: ");
            for (m = 0; m < 16; ++m) {
                if ((4 == m) || (6 == m) || (8 == m) || (10 == m))
                    printf("-");
                printf("%02x", (unsigned int)ip[2 + m]);
            }
            printf("\n");
            break;
        default: /* reserved */
            pr2serr("      reserved designator=0x%x\n", desig_type);
            hex2stderr(ip, i_len, -1);
            break;
        }
    }
    if (-2 == u)
        pr2serr("%s VPD page error: around offset=%d\n", leadin, off);
}

static void
export_dev_ids(uint8_t * buff, int len, int verbose)
{
    int u, j, m, id_len, c_set, assoc, desig_type, i_len;
    int off, d_id, naa, k, p_id;
    uint8_t * bp;
    uint8_t * ip;
    const char * assoc_str;
    const char * suffix;

    if (buff[2] != 0) {
        /*
         * Cf decode_dev_ids() for details
         */
        i_len = len;
        ip = buff;
        c_set = 1;
        assoc = 0;
        p_id = 0xf;
        desig_type = 3;
        j = 1;
        off = 16;
        goto decode;
    }

    for (j = 1, off = -1;
         (u = sg_vpd_dev_id_iter(buff, len, &off, -1, -1, -1)) == 0;
         ++j) {
        bp = buff + off;
        i_len = bp[3];
        id_len = i_len + 4;
        if ((off + id_len) > len) {
            if (verbose)
                pr2serr("Device Identification VPD page error: designator "
                        "length longer than\n     remaining response "
                        "length=%d\n", (len - off));
            return;
        }
        ip = bp + 4;
        p_id = ((bp[0] >> 4) & 0xf);   /* protocol identifier */
        c_set = (bp[0] & 0xf);
        assoc = ((bp[1] >> 4) & 0x3);
        desig_type = (bp[1] & 0xf);
  decode:
        switch (assoc) {
            case 0:
                assoc_str = "LUN";
                break;
            case 1:
                assoc_str = "PORT";
                break;
            case 2:
                assoc_str = "TARGET";
                break;
            default:
                if (verbose)
                    pr2serr("    Invalid association %d\n", assoc);
                return;
        }
        switch (desig_type) {
        case 0: /* vendor specific */
            if (i_len == 0 || i_len > 128)
                break;
            if ((2 == c_set) || (3 == c_set)) { /* ASCII or UTF-8 */
                k = encode_whitespaces(ip, i_len);
                /* udev-conforming character encoding */
                if (k > 0) {
                    printf("SCSI_IDENT_%s_VENDOR=", assoc_str);
                    for (m = 0; m < k; ++m) {
                        if ((ip[m] >= '0' && ip[m] <= '9') ||
                            (ip[m] >= 'A' && ip[m] <= 'Z') ||
                            (ip[m] >= 'a' && ip[m] <= 'z') ||
                            strchr("#+-.:=@_", ip[m]) != NULL)
                            printf("%c", ip[m]);
                        else
                            printf("\\x%02x", ip[m]);
                    }
                    printf("\n");
                }
            } else {
                printf("SCSI_IDENT_%s_VENDOR=", assoc_str);
                for (m = 0; m < i_len; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            }
            break;
        case 1: /* T10 vendor identification */
            printf("SCSI_IDENT_%s_T10=", assoc_str);
            if ((2 == c_set) || (3 == c_set)) {
                k = encode_whitespaces(ip, i_len);
                /* udev-conforming character encoding */
                for (m = 0; m < k; ++m) {
                    if ((ip[m] >= '0' && ip[m] <= '9') ||
                        (ip[m] >= 'A' && ip[m] <= 'Z') ||
                        (ip[m] >= 'a' && ip[m] <= 'z') ||
                        strchr("#+-.:=@_", ip[m]) != NULL)
                        printf("%c", ip[m]);
                    else
                        printf("\\x%02x", ip[m]);
                }
                printf("\n");
                if (!memcmp(ip, "ATA_", 4)) {
                    printf("SCSI_IDENT_%s_ATA=%.*s\n", assoc_str,
                           k - 4, ip + 4);
                }
            } else {
                for (m = 0; m < i_len; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            }
            break;
        case 2: /* EUI-64 based */
            if (1 != c_set) {
                if (verbose) {
                    pr2serr("      << expected binary code_set (1)>>\n");
                    hex2stderr(ip, i_len, 0);
                }
                break;
            }
            printf("SCSI_IDENT_%s_EUI64=", assoc_str);
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        case 3: /* NAA */
            if (1 != c_set) {
                if (verbose) {
                    pr2serr("      << expected binary code_set (1)>>\n");
                    hex2stderr(ip, i_len, 0);
                }
                break;
            }
            /*
             * Unfortunately, there are some (broken) implementations
             * which return _several_ NAA descriptors.
             * So add a suffix to differentiate between them.
             */
            naa = (ip[0] >> 4) & 0xff;
            switch (naa) {
                case 6:
                    suffix="REGEXT";
                    break;
                case 5:
                    suffix="REG";
                    break;
                case 2:
                    suffix="EXT";
                    break;
                case 3:
                default:
                    suffix="LOCAL";
                    break;
            }
            printf("SCSI_IDENT_%s_NAA_%s=", assoc_str, suffix);
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        case 4: /* Relative target port */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                if (verbose) {
                    pr2serr("      << expected binary code_set, target "
                            "port association, length 4>>\n");
                    hex2stderr(ip, i_len, 0);
                }
                break;
            }
            d_id = sg_get_unaligned_be16(ip + 2);
            printf("SCSI_IDENT_%s_RELATIVE=%d\n", assoc_str, d_id);
            break;
        case 5: /* (primary) Target port group */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                if (verbose) {
                    pr2serr("      << expected binary code_set, target "
                            "port association, length 4>>\n");
                    hex2stderr(ip, i_len, 0);
                }
                break;
            }
            d_id = sg_get_unaligned_be16(ip + 2);
            printf("SCSI_IDENT_%s_TARGET_PORT_GROUP=0x%x\n", assoc_str, d_id);
            break;
        case 6: /* Logical unit group */
            if ((1 != c_set) || (0 != assoc) || (4 != i_len)) {
                if (verbose) {
                    pr2serr("      << expected binary code_set, logical "
                            "unit association, length 4>>\n");
                    hex2stderr(ip, i_len, 0);
                }
                break;
            }
            d_id = sg_get_unaligned_be16(ip + 2);
            printf("SCSI_IDENT_%s_LOGICAL_UNIT_GROUP=0x%x\n", assoc_str, d_id);
            break;
        case 7: /* MD5 logical unit identifier */
            if ((1 != c_set) || (0 != assoc)) {
                if (verbose) {
                    pr2serr("      << expected binary code_set, logical "
                            "unit association>>\n");
                    hex2stderr(ip, i_len, 0);
                }
                break;
            }
            printf("SCSI_IDENT_%s_MD5=", assoc_str);
            hex2stdout(ip, i_len, -1);
            break;
        case 8: /* SCSI name string */
            if (3 != c_set) {
                if (verbose) {
                    pr2serr("      << expected UTF-8 code_set>>\n");
                    hex2stderr(ip, i_len, -1);
                }
                break;
            }
            if (! (strncmp((const char *)ip, "eui.", 4) ||
                   strncmp((const char *)ip, "EUI.", 4) ||
                   strncmp((const char *)ip, "naa.", 4) ||
                   strncmp((const char *)ip, "NAA.", 4) ||
                   strncmp((const char *)ip, "iqn.", 4))) {
                if (verbose) {
                    pr2serr("      << expected name string prefix>>\n");
                    hex2stderr(ip, i_len, -1);
                }
                break;
            }

            printf("SCSI_IDENT_%s_NAME=%.*s\n", assoc_str, i_len,
                   (const char *)ip);
            break;
        case 9: /*  Protocol specific port identifier */
            if (TPROTO_UAS == p_id) {
                if ((4 != i_len) || (1 != assoc)) {
                    if (verbose) {
                        pr2serr("      << UAS (USB) expected target "
                                "port association>>\n");
                        hex2stderr(ip, i_len, 0);
                    }
                    break;
                }
                printf("SCSI_IDENT_%s_UAS_DEVICE_ADDRESS=0x%x\n", assoc_str,
                       ip[0] & 0x7f);
                printf("SCSI_IDENT_%s_UAS_INTERFACE_NUMBER=0x%x\n", assoc_str,
                       ip[2]);
            } else if (TPROTO_SOP == p_id) {
                if ((4 != i_len) && (8 != i_len)) {   /* spc4r36h confused */
                    if (verbose) {
                        pr2serr("      << SOP (PCIe) descriptor "
                                "length=%d >>\n", i_len);
                        hex2stderr(ip, i_len, 0);
                    }
                    break;
                }
                printf("SCSI_IDENT_%s_SOP_ROUTING_ID=0x%x\n", assoc_str,
                       sg_get_unaligned_be16(ip + 0));
            } else {
                pr2serr("      << Protocol specific port identifier "
                        "protocol_id=0x%x>>\n", p_id);
            }
            break;
        case 0xa: /* UUID based */
            if (1 != c_set) {
                if (verbose) {
                    pr2serr("      << expected binary code_set (1)>>\n");
                    hex2stderr(ip, i_len, 0);
                }
                break;
            }
            if (i_len < 18) {
                if (verbose) {
                    pr2serr("      << short UUID field expected 18 or more, "
                            "got %d >>\n", i_len);
                    hex2stderr(ip, i_len, 0);
                }
                break;
            }
            printf("SCSI_IDENT_%s_UUID=", assoc_str);
            for (m = 2; m < i_len; ++m) {
                if ((6 == m) || (8 == m) || (10 == m) || (12 == m))
                    printf("-%02x", (unsigned int)ip[m]);
                else
                    printf("%02x", (unsigned int)ip[m]);
            }
            printf("\n");
            break;
        default: /* reserved */
            if (verbose) {
                pr2serr("      reserved designator=0x%x\n", desig_type);
                hex2stderr(ip, i_len, -1);
            }
            break;
        }
    }
    if (-2 == u && verbose)
        pr2serr("Device identification VPD page error: "
                "around offset=%d\n", off);
}

/* VPD_EXT_INQ   Extended Inquiry [0x86] */
static void
decode_x_inq_vpd(uint8_t * buff, int len, int do_hex)
{
    if (len < 7) {
        pr2serr("Extended INQUIRY data VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    printf("  ACTIVATE_MICROCODE=%d SPT=%d GRD_CHK=%d APP_CHK=%d "
           "REF_CHK=%d\n", ((buff[4] >> 6) & 0x3), ((buff[4] >> 3) & 0x7),
           !!(buff[4] & 0x4), !!(buff[4] & 0x2), !!(buff[4] & 0x1));
    printf("  UASK_SUP=%d GROUP_SUP=%d PRIOR_SUP=%d HEADSUP=%d ORDSUP=%d "
           "SIMPSUP=%d\n", !!(buff[5] & 0x20), !!(buff[5] & 0x10),
           !!(buff[5] & 0x8), !!(buff[5] & 0x4), !!(buff[5] & 0x2),
           !!(buff[5] & 0x1));
    /* CRD_SUP made obsolete in spc5r04 */
    printf("  WU_SUP=%d [CRD_SUP=%d] NV_SUP=%d V_SUP=%d\n",
           !!(buff[6] & 0x8), !!(buff[6] & 0x4), !!(buff[6] & 0x2),
           !!(buff[6] & 0x1));
    /* NO_PI_CHK and HSSRELEF added in spc5r02 */
    printf("  NO_PI_CHK=%d P_I_I_SUP=%d LUICLR=%d\n", !!(buff[7] & 0x20),
           !!(buff[7] & 0x10), !!(buff[7] & 0x1));
    /* RTD_SUP added in spc5r11, LU_COLL_TYPE added in spc5r09,
     * HSSRELEF added in spc5r02; CBCS obsolete in spc5r01 */
    printf("  LU_COLL_TYPE=%d R_SUP=%d RTD_SUP=%d HSSRELEF=%d [CBCS=%d]\n",
           (buff[8] >> 5) & 0x7, !!(buff[8] & 0x10), !!(buff[8] & 0x8),
           !!(buff[8] & 0x2), !!(buff[8] & 0x1));
    printf("  Multi I_T nexus microcode download=%d\n", buff[9] & 0xf);
    printf("  Extended self-test completion minutes=%d\n",
           sg_get_unaligned_be16(buff + 10));     /* spc4r27 */
    printf("  POA_SUP=%d HRA_SUP=%d VSA_SUP=%d DMS_VALID=%d\n",
           !!(buff[12] & 0x80), !!(buff[12] & 0x40), !!(buff[12] & 0x20),
           !!(buff[12] & 0x10));                /* spc5r20 */
    printf("  Maximum supported sense data length=%d\n",
           buff[13]); /* spc4r34 */
    /* All byte 14 bits added in spc5r09 */
    printf("  IBS=%d IAS=%d SAC=%d NRD1=%d NRD0=%d\n",
           !!(buff[14] & 0x80), !!(buff[14] & 0x40), !!(buff[14] & 0x4),
           !!(buff[14] & 0x2), !!(buff[14] & 0x1));
    printf("  Maximum inquiry change logs=%u\n",
           sg_get_unaligned_be16(buff + 15));     /* spc5r17 */
    printf("  Maximum mode page change logs=%u\n",
           sg_get_unaligned_be16(buff + 17));     /* spc5r17 */
    printf("  DM_MD_4=%d DM_MD_5=%d DM_MD_6=%d DM_MD_7=%d\n",
           !!(buff[19] & 0x80), !!(buff[19] & 0x40), !!(buff[19] & 0x20),
           !!(buff[19] & 0x10));                     /* spc5r20 */
    printf("  DM_MD_D=%d DM_MD_E=%d DM_MD_F=%d\n",
           !!(buff[19] & 0x8), !!(buff[19] & 0x4), !!(buff[19] & 0x2));
}

/* VPD_SOFTW_INF_ID [0x84] */
static void
decode_softw_inf_id(uint8_t * buff, int len, int do_hex)
{
    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    len -= 4;
    buff += 4;
    for ( ; len > 5; len -= 6, buff += 6)
        printf("    IEEE Company_id: 0x%06x, vendor specific extension "
               "id: 0x%06x\n", sg_get_unaligned_be24(buff + 0),
               sg_get_unaligned_be24(buff + 3));
}

/* VPD_ATA_INFO [0x89] */
static void
decode_ata_info_vpd(uint8_t * buff, int len, int do_hex)
{
    char b[80];
    int is_be, num;

    if (len < 36) {
        pr2serr("ATA information VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex && (2 != do_hex)) {
        hex2stdout(buff, len, (3 == do_hex) ? 0 : -1);
        return;
    }
    memcpy(b, buff + 8, 8);
    b[8] = '\0';
    printf("  SAT Vendor identification: %s\n", b);
    memcpy(b, buff + 16, 16);
    b[16] = '\0';
    printf("  SAT Product identification: %s\n", b);
    memcpy(b, buff + 32, 4);
    b[4] = '\0';
    printf("  SAT Product revision level: %s\n", b);
    if (len < 56)
        return;
    printf("  Signature (Device to host FIS):\n");
    hex2stdout(buff + 36, 20, 1);
    if (len < 60)
        return;
    is_be = sg_is_big_endian();
    if ((0xec == buff[56]) || (0xa1 == buff[56])) {
        printf("  ATA command IDENTIFY %sDEVICE response summary:\n",
               ((0xa1 == buff[56]) ? "PACKET " : ""));
        num = sg_ata_get_chars((const unsigned short *)(buff + 60), 27, 20,
                               is_be, b);
        b[num] = '\0';
        printf("    model: %s\n", b);
        num = sg_ata_get_chars((const unsigned short *)(buff + 60), 10, 10,
                               is_be, b);
        b[num] = '\0';
        printf("    serial number: %s\n", b);
        num = sg_ata_get_chars((const unsigned short *)(buff + 60), 23, 4,
                               is_be, b);
        b[num] = '\0';
        printf("    firmware revision: %s\n", b);
        printf("  response in hex:\n");
    } else
        printf("  ATA command 0x%x got following response:\n",
               (unsigned int)buff[56]);
    if (len < 572)
        return;
    if (2 == do_hex)
        hex2stdout(buff + 60, 512, 0);
    else
        dWordHex((const unsigned short *)(buff + 60), 256, 0,
                 sg_is_big_endian());
}

/* VPD_POWER_CONDITION [0x8a] */
static void
decode_power_condition(uint8_t * buff, int len, int do_hex)
{
    if (len < 18) {
        pr2serr("Power condition VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    printf("  Standby_y=%d Standby_z=%d Idle_c=%d Idle_b=%d Idle_a=%d\n",
           !!(buff[4] & 0x2), !!(buff[4] & 0x1),
           !!(buff[5] & 0x4), !!(buff[5] & 0x2), !!(buff[5] & 0x1));
    printf("  Stopped condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 6));
    printf("  Standby_z condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 8));
    printf("  Standby_y condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 10));
    printf("  Idle_a condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 12));
    printf("  Idle_b condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 14));
    printf("  Idle_c condition recovery time (ms) %d\n",
           sg_get_unaligned_be16(buff + 16));
}

/* VPD_SCSI_FEATURE_SETS [0x92] (sfs) */
static void
decode_feature_sets_vpd(uint8_t * buff, int len,
                        const struct opts_t * op)
{
    int k, bump;
    uint16_t sf_code;
    bool found;
    uint8_t * bp;
    char b[64];

    if ((1 == op->do_hex) || (op->do_hex > 2)) {
        hex2stdout(buff, len, (1 == op->do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("SCSI Feature sets VPD page length too short=%d\n", len);
        return;
    }
    len -= 8;
    bp = buff + 8;
    for (k = 0; k < len; k += bump, bp += bump) {
        sf_code = sg_get_unaligned_be16(bp);
        bump = 2;
        if ((k + bump) > len) {
            pr2serr("SCSI Feature sets, short descriptor length=%d, "
                    "left=%d\n", bump, (len - k));
            return;
        }
        if (2 == op->do_hex)
            hex2stdout(bp + 8, 2, 1);
        else if (op->do_hex > 2)
            hex2stdout(bp, 2, 1);
        else {
            printf("    %s", sg_get_sfs_str(sf_code, -2, sizeof(b), b,
                   &found, op->verbose));
            if (op->verbose == 1)
                printf(" [0x%x]\n", (unsigned int)sf_code);
            else if (op->verbose > 1)
                printf(" [0x%x] found=%s\n", (unsigned int)sf_code,
                       found ? "true" : "false");
            else
                printf("\n");
        }
    }
}

/* VPD_BLOCK_LIMITS sbc */
/* Sequential access device characteristics,  ssc+smc */
/* OSD information, osd */
static void
decode_b0_vpd(uint8_t * buff, int len, int do_hex)
{
    int pdt;
    unsigned int u;
    uint64_t ull;
    bool ugavalid;

    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    pdt = 0x1f & buff[0];
    switch (pdt) {
        case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
            if (len < 16) {
                pr2serr("Block limits VPD page length too short=%d\n", len);
                return;
            }
            u = buff[5];
            printf("  Maximum compare and write length: ");
            if (0 == u)
                printf("0 blocks [Command not implemented]\n");
            else
                printf("%u blocks\n", buff[5]);
            u = sg_get_unaligned_be16(buff + 6);
            printf("  Optimal transfer length granularity: ");
            if (0 == u)
                printf("0 blocks [not reported]\n");
            else
                printf("%u blocks\n", u);
            u = sg_get_unaligned_be32(buff + 8);
            printf("  Maximum transfer length: ");
            if (0 == u)
                printf("0 blocks [not reported]\n");
            else
                printf("%u blocks\n", u);
            u = sg_get_unaligned_be32(buff + 12);
            printf("  Optimal transfer length: ");
            if (0 == u)
                printf("0 blocks [not reported]\n");
            else
                printf("%u blocks\n", u);
            if (len > 19) {     /* added in sbc3r09 */
                u = sg_get_unaligned_be32(buff + 16);
                printf("  Maximum prefetch transfer length: ");
                if (0 == u)
                    printf("0 blocks [ignored]\n");
                else
                    printf("%u blocks\n", u);
            }
            if (len > 27) {     /* added in sbc3r18 */
                u = sg_get_unaligned_be32(buff + 20);
                printf("  Maximum unmap LBA count: ");
                if (0 == u)
                    printf("0 [Unmap command not implemented]\n");
                else if (SG_LIB_UNBOUNDED_32BIT == u)
                    printf("-1 [unbounded]\n");
                else
                    printf("%u\n", u);
                u = sg_get_unaligned_be32(buff + 24);
                printf("  Maximum unmap block descriptor count: ");
                if (0 == u)
                    printf("0 [Unmap command not implemented]\n");
                else if (SG_LIB_UNBOUNDED_32BIT == u)
                    printf("-1 [unbounded]\n");
                else
                    printf("%u\n", u);
            }
            if (len > 35) {     /* added in sbc3r19 */
                u = sg_get_unaligned_be32(buff + 28);
                printf("  Optimal unmap granularity: ");
                if (0 == u)
                    printf("0 blocks [not reported]\n");
                else
                    printf("%u blocks\n", u);

                ugavalid = !!(buff[32] & 0x80);
                printf("  Unmap granularity alignment valid: %s\n",
                       ugavalid ? "true" : "false");
                u = 0x7fffffff & sg_get_unaligned_be32(buff + 32);
                printf("  Unmap granularity alignment: %u%s\n", u,
                       ugavalid ? "" : " [invalid]");
            }
            if (len > 43) {     /* added in sbc3r26 */
                ull = sg_get_unaligned_be64(buff + 36);
                printf("  Maximum write same length: ");
                if (0 == ull)
                    printf("0 blocks [not reported]\n");
                else
                    printf("0x%" PRIx64 " blocks\n", ull);
            }
            if (len > 44) {     /* added in sbc4r02 */
                u = sg_get_unaligned_be32(buff + 44);
                printf("  Maximum atomic transfer length: ");
                if (0 == u)
                    printf("0 blocks [not reported]\n");
                else
                    printf("%u blocks\n", u);
                u = sg_get_unaligned_be32(buff + 48);
                printf("  Atomic alignment: ");
                if (0 == u)
                    printf("0 [unaligned atomic writes permitted]\n");
                else
                    printf("%u\n", u);
                u = sg_get_unaligned_be32(buff + 52);
                printf("  Atomic transfer length granularity: ");
                if (0 == u)
                    printf("0 [no granularity requirement\n");
                else
                    printf("%u\n", u);
            }
            if (len > 56) {
                u = sg_get_unaligned_be32(buff + 56);
                printf("  Maximum atomic transfer length with atomic "
                       "boundary: ");
                if (0 == u)
                    printf("0 blocks [not reported]\n");
                else
                    printf("%u blocks\n", u);
                u = sg_get_unaligned_be32(buff + 60);
                printf("  Maximum atomic boundary size: ");
                if (0 == u)
                    printf("0 blocks [can only write atomic 1 block]\n");
                else
                    printf("%u blocks\n", u);
            }
            break;
        case PDT_TAPE: case PDT_MCHANGER:
            printf("  WORM=%d\n", !!(buff[4] & 0x1));
            break;
        case PDT_OSD:
        default:
            printf("  Unable to decode pdt=0x%x, in hex:\n", pdt);
            hex2stdout(buff, len, 0);
            break;
    }
}

/* VPD_BLOCK_DEV_CHARS sbc */
/* VPD_MAN_ASS_SN ssc */
static void
decode_b1_vpd(uint8_t * buff, int len, int do_hex)
{
    int pdt;
    unsigned int u;

    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    pdt = 0x1f & buff[0];
    switch (pdt) {
        case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
            if (len < 64) {
                pr2serr("Block device characteristics VPD page length too "
                        "short=%d\n", len);
                return;
            }
            u = sg_get_unaligned_be16(buff + 4);
            if (0 == u)
                printf("  Medium rotation rate is not reported\n");
            else if (1 == u)
                printf("  Non-rotating medium (e.g. solid state)\n");
            else if ((u < 0x401) || (0xffff == u))
                printf("  Reserved [0x%x]\n", u);
            else
                printf("  Nominal rotation rate: %d rpm\n", u);
            printf("  Product type=%d\n", buff[6]);
            printf("  WABEREQ=%d\n", (buff[7] >> 6) & 0x3);
            printf("  WACEREQ=%d\n", (buff[7] >> 4) & 0x3);
            u = buff[7] & 0xf;
            printf("  Nominal form factor ");
            switch(u) {
            case 0:
                printf("is not reported\n");
                break;
            case 1:
                printf("5.25 inches\n");
                break;
            case 2:
                printf("3.5 inches\n");
                break;
            case 3:
                printf("2.5 inches\n");
                break;
            case 4:
                printf("1.8 inches\n");
                break;
            case 5:
                printf("less then 1.8 inches\n");
                break;
            default:
                printf("reserved [%u]\n", u);
                break;
            }
            printf("  ZONED=%d\n", (buff[8] >> 4) & 0x3);   /* sbc4r04 */
            printf("  FUAB=%d\n", buff[8] & 0x2);
            printf("  VBULS=%d\n", buff[8] & 0x1);
            printf("  DEPOPULATION_TIME=%u (seconds)\n",
                   sg_get_unaligned_be32(buff + 12));   /* added sbc4r14 */
            break;
        case PDT_TAPE: case PDT_MCHANGER: case PDT_ADC:
            printf("  Manufacturer-assigned serial number: %.*s\n",
                   len - 4, buff + 4);
            break;
        default:
            printf("  Unable to decode pdt=0x%x, in hex:\n", pdt);
            hex2stdout(buff, len, 0);
            break;
    }
}

/* VPD_REFERRALS sbc */
static void
decode_b3_vpd(uint8_t * buff, int len, int do_hex)
{
    int pdt;
    unsigned int s, m;

    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    pdt = 0x1f & buff[0];
    switch (pdt) {
        case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
            if (len < 0x10) {
                pr2serr("Referrals VPD page length too short=%d\n", len);
                return;
            }
            s = sg_get_unaligned_be32(buff + 8);
            m = sg_get_unaligned_be32(buff + 12);
            if (0 == s)
                printf("  Single user data segment\n");
            else if (0 == m)
                printf("  Segment size specified by user data segment "
                       "descriptor\n");
            else
                printf("  Segment size: %u, segment multiplier: %u\n", s, m);
            break;
        default:
            printf("  Unable to decode pdt=0x%x, in hex:\n", pdt);
            hex2stdout(buff, len, 0);
            break;
    }
}

static const char * lun_state_arr[] =
{
    "LUN not bound or LUN_Z report",
    "LUN bound, but not owned by this SP",
    "LUN bound and owned by this SP",
};

static const char * ip_mgmt_arr[] =
{
    "No IP access",
    "Reserved (undefined)",
    "via IPv4",
    "via IPv6",
};

static const char * sp_arr[] =
{
    "SP A",
    "SP B",
};

static const char * lun_op_arr[] =
{
    "Normal operations",
    "I/O Operations being rejected, SP reboot or NDU in progress",
};

static const char * failover_mode_arr[] =
{
    "Legacy mode 0",
    "Unknown mode (1)",
    "Unknown mode (2)",
    "Unknown mode (3)",
    "Active/Passive (PNR) mode 1",
    "Unknown mode (5)",
    "Active/Active (ALUA) mode 4",
    "Unknown mode (7)",
    "Legacy mode 2",
    "Unknown mode (9)",
    "Unknown mode (10)",
    "Unknown mode (11)",
    "Unknown mode (12)",
    "Unknown mode (13)",
    "AIX Active/Passive (PAR) mode 3",
    "Unknown mode (15)",
};

static void
decode_upr_vpd_c0_emc(uint8_t * buff, int len, int do_hex)
{
    int k, ip_mgmt, vpp80, lun_z;

    if (len < 3) {
        pr2serr("EMC upr VPD page [0xc0]: length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (buff[9] != 0x00) {
        pr2serr("Unsupported page revision %d, decoding not possible.\n",
                buff[9]);
        return;
    }
    printf("  LUN WWN: ");
    for (k = 0; k < 16; ++k)
        printf("%02x", buff[10 + k]);
    printf("\n");
    printf("  Array Serial Number: ");
    dStrRaw((const char *)&buff[50], buff[49]);
    printf("\n");

    printf("  LUN State: ");
    if (buff[4] > 0x02)
           printf("Unknown (%x)\n", buff[4]);
    else
           printf("%s\n", lun_state_arr[buff[4]]);

    printf("  This path connects to: ");
    if (buff[8] > 0x01)
           printf("Unknown SP (%x)", buff[8]);
    else
           printf("%s", sp_arr[buff[8]]);
    printf(", Port Number: %u\n", buff[7]);

    printf("  Default Owner: ");
    if (buff[5] > 0x01)
           printf("Unknown (%x)\n", buff[5]);
    else
           printf("%s\n", sp_arr[buff[5]]);

    printf("  NO_ATF: %s, Access Logix: %s\n",
                   buff[6] & 0x80 ? "set" : "not set",
                   buff[6] & 0x40 ? "supported" : "not supported");

    ip_mgmt = (buff[6] >> 4) & 0x3;

    printf("  SP IP Management Mode: %s\n", ip_mgmt_arr[ip_mgmt]);
    if (ip_mgmt == 2)
        printf("  SP IPv4 address: %u.%u.%u.%u\n",
               buff[44], buff[45], buff[46], buff[47]);
    else {
        printf("  SP IPv6 address: ");
        for (k = 0; k < 16; ++k)
            printf("%02x", buff[32 + k]);
        printf("\n");
    }

    vpp80 = buff[30] & 0x08;
    lun_z = buff[30] & 0x04;

    printf("  System Type: %x, Failover mode: %s\n",
           buff[27], failover_mode_arr[buff[28] & 0x0f]);

    printf("  Inquiry VPP 0x80 returns: %s, Arraycommpath: %s\n",
                   vpp80 ? "array serial#" : "LUN serial#",
                   lun_z ? "Set to 1" : "Unknown");

    printf("  Lun operations: %s\n",
               buff[48] > 1 ? "undefined" : lun_op_arr[buff[48]]);

    return;
}

static void
decode_rdac_vpd_c2(uint8_t * buff, int len, int do_hex)
{
    if (len < 3) {
        pr2serr("Software Version VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (buff[4] != 's' && buff[5] != 'w' && buff[6] != 'r') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    printf("  Software Version: %02x.%02x.%02x\n", buff[8], buff[9], buff[10]);
    printf("  Software Date: %02d/%02d/%02d\n", buff[11], buff[12], buff[13]);
    printf("  Features:");
    if (buff[14] & 0x01)
        printf(" Dual Active,");
    if (buff[14] & 0x02)
        printf(" Series 3,");
    if (buff[14] & 0x04)
        printf(" Multiple Sub-enclosures,");
    if (buff[14] & 0x08)
        printf(" DCE/DRM/DSS/DVE,");
    if (buff[14] & 0x10)
        printf(" Asymmetric Logical Unit Access,");
    printf("\n");
    printf("  Max. #of LUNS: %d\n", buff[15]);
    return;
}

static void
decode_rdac_vpd_c9_rtpg_data(uint8_t aas, uint8_t vendor)
{
    printf("  Asymmetric Access State:");
    switch(aas & 0x0F) {
        case 0x0:
            printf(" Active/Optimized");
            break;
        case 0x1:
            printf(" Active/Non-Optimized");
            break;
        case 0x2:
            printf(" Standby");
            break;
        case 0x3:
            printf(" Unavailable");
            break;
        case 0xE:
            printf(" Offline");
            break;
        case 0xF:
            printf(" Transitioning");
            break;
        default:
            printf(" (unknown)");
            break;
    }
    printf("\n");

    printf("  Vendor Specific Field:");
    switch(vendor) {
        case 0x01:
            printf(" Operating normally");
            break;
        case 0x02:
            printf(" Non-responsive to queries");
            break;
        case 0x03:
            printf(" Controller being held in reset");
            break;
        case 0x04:
            printf(" Performing controller firmware download (1st "
                   "controller)");
            break;
        case 0x05:
            printf(" Performing controller firmware download (2nd "
                   "controller)");
            break;
        case 0x06:
            printf(" Quiesced as a result of an administrative request");
            break;
        case 0x07:
            printf(" Service mode as a result of an administrative request");
            break;
        case 0xFF:
            printf(" Details are not available");
            break;
        default:
            printf(" (unknown)");
            break;
    }
    printf("\n");
}

static void
decode_rdac_vpd_c9(uint8_t * buff, int len, int do_hex)
{
    if (len < 3) {
        pr2serr("Volume Access Control VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        hex2stdout(buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (buff[4] != 'v' && buff[5] != 'a' && buff[6] != 'c') {
        pr2serr("Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    if (buff[7] != '1') {
        pr2serr("Invalid page version '%c' (should be 1)\n", buff[7]);
    }
    if ( (buff[8] & 0xE0) == 0xE0 ) {
        printf("  IOShipping (ALUA): Enabled\n");
    } else {
        printf("  AVT:");
        if (buff[8] & 0x80) {
            printf(" Enabled");
            if (buff[8] & 0x40)
                printf(" (Allow reads on sector 0)");
            printf("\n");
        } else {
            printf(" Disabled\n");
        }
    }
    printf("  Volume Access via: ");
    if (buff[8] & 0x01)
        printf("primary controller\n");
    else
        printf("alternate controller\n");

    if (buff[8] & 0x08) {
        printf("  Path priority: %d ", buff[15] & 0xf);
        switch(buff[15] & 0xf) {
            case 0x1:
                printf("(preferred path)\n");
                break;
            case 0x2:
                printf("(secondary path)\n");
                break;
            default:
                printf("(unknown)\n");
                break;
        }

        printf("  Preferred Path Auto Changeable:");
        switch(buff[14] & 0x3C) {
            case 0x14:
                printf(" No (User Disabled and Host Type Restricted)\n");
                break;
            case 0x18:
                printf(" No (User Disabled)\n");
                break;
            case 0x24:
                printf(" No (Host Type Restricted)\n");
                break;
            case 0x28:
                printf(" Yes\n");
                break;
            default:
                printf(" (Unknown)\n");
                break;
        }

        printf("  Implicit Failback:");
        switch(buff[14] & 0x03) {
            case 0x1:
                printf(" Disabled\n");
                break;
            case 0x2:
                printf(" Enabled\n");
                break;
            default:
                printf(" (Unknown)\n");
                break;
        }
    } else {
        printf("  Path priority: %d ", buff[9] & 0xf);
        switch(buff[9] & 0xf) {
            case 0x1:
                printf("(preferred path)\n");
                break;
            case 0x2:
                printf("(secondary path)\n");
                break;
            default:
                printf("(unknown)\n");
                break;
        }
    }

    if (buff[8] & 0x80) {
        printf(" Target Port Group Data (This controller):\n");
        decode_rdac_vpd_c9_rtpg_data(buff[10], buff[11]);

        printf(" Target Port Group Data (Alternate controller):\n");
        decode_rdac_vpd_c9_rtpg_data(buff[12], buff[13]);
    }

    return;
}

extern const char * sg_ansi_version_arr[];

static const char *
get_ansi_version_str(int version, char * buff, int buff_len)
{
    version &= 0xf;
    buff[buff_len - 1] = '\0';
    strncpy(buff, sg_ansi_version_arr[version], buff_len - 1);
    return buff;
}

static void
std_inq_decode(const struct opts_t * op, int act_len)
{
    int len, pqual, peri_type, ansi_version, k, j;
    const char * cp;
    int vdesc_arr[8];
    char buff[48];
    const uint8_t * rp;

    rp = rsp_buff;
    memset(vdesc_arr, 0, sizeof(vdesc_arr));
    if (op->do_raw) {
        dStrRaw((const char *)rp, act_len);
        return;
    } else if (op->do_hex) {
        /* with -H, print with address, -HH without */
        hex2stdout(rp, act_len, ((1 == op->do_hex) ? 0 : -1));
        return;
    }
    pqual = (rp[0] & 0xe0) >> 5;
    if (! op->do_raw && ! op->do_export) {
        printf("standard INQUIRY:");
        if (0 == pqual)
            printf("\n");
        else if (1 == pqual)
            printf(" [PQ indicates LU temporarily unavailable]\n");
        else if (3 == pqual)
            printf(" [PQ indicates LU not accessible via this port]\n");
        else
            printf(" [reserved or vendor specific qualifier [%d]]\n", pqual);
    }
    len = rp[4] + 5;
    /* N.B. rp[2] full byte is 'version' in SPC-2,3,4 but in SPC
     * [spc-r11a (1997)] bits 6,7: ISO/IEC version; bits 3-5: ECMA
     * version; bits 0-2: SCSI version */
    ansi_version = rp[2] & 0x7;       /* Only take SCSI version */
    peri_type = rp[0] & 0x1f;
    if (op->do_export) {
        printf("SCSI_TPGS=%d\n", (rp[5] & 0x30) >> 4);
        cp = sg_get_pdt_str(peri_type, sizeof(buff), buff);
        if (strlen(cp) > 0)
            printf("SCSI_TYPE=%s\n", cp);
    } else {
        printf("  PQual=%d  Device_type=%d  RMB=%d  LU_CONG=%d  "
               "version=0x%02x ", pqual, peri_type, !!(rp[1] & 0x80),
               !!(rp[1] & 0x40), (unsigned int)rp[2]);
        printf(" [%s]\n", get_ansi_version_str(ansi_version, buff,
                                               sizeof(buff)));
        printf("  [AERC=%d]  [TrmTsk=%d]  NormACA=%d  HiSUP=%d "
               " Resp_data_format=%d\n  SCCS=%d  ", !!(rp[3] & 0x80),
               !!(rp[3] & 0x40), !!(rp[3] & 0x20), !!(rp[3] & 0x10),
               rp[3] & 0x0f, !!(rp[5] & 0x80));
        printf("ACC=%d  TPGS=%d  3PC=%d  Protect=%d ", !!(rp[5] & 0x40),
               ((rp[5] & 0x30) >> 4), !!(rp[5] & 0x08), !!(rp[5] & 0x01));
        printf(" [BQue=%d]\n  EncServ=%d  ", !!(rp[6] & 0x80),
               !!(rp[6] & 0x40));
        if (rp[6] & 0x10)
            printf("MultiP=1 (VS=%d)  ", !!(rp[6] & 0x20));
        else
            printf("MultiP=0  ");
        printf("[MChngr=%d]  [ACKREQQ=%d]  Addr16=%d\n  [RelAdr=%d]  ",
               !!(rp[6] & 0x08), !!(rp[6] & 0x04), !!(rp[6] & 0x01),
               !!(rp[7] & 0x80));
        printf("WBus16=%d  Sync=%d  [Linked=%d]  [TranDis=%d]  ",
               !!(rp[7] & 0x20), !!(rp[7] & 0x10), !!(rp[7] & 0x08),
               !!(rp[7] & 0x04));
        printf("CmdQue=%d\n", !!(rp[7] & 0x02));
        if (act_len > 56)
            printf("  [SPI: Clocking=0x%x  QAS=%d  IUS=%d]\n",
                   (rp[56] & 0x0c) >> 2, !!(rp[56] & 0x2), !!(rp[56] & 0x1));
        if (act_len >= len)
            printf("    length=%d (0x%x)", len, len);
        else
            printf("    length=%d (0x%x), but only fetched %d bytes", len,
                   len, act_len);
        if ((ansi_version >= 2) && (len < SAFE_STD_INQ_RESP_LEN))
            printf("\n  [for SCSI>=2, len>=36 is expected]");
        cp = sg_get_pdt_str(peri_type, sizeof(buff), buff);
        if (strlen(cp) > 0)
            printf("   Peripheral device type: %s\n", cp);
    }
    if (act_len <= 8) {
        if (! op->do_export)
            printf(" Inquiry response length=%d, no vendor, product or "
                   "revision data\n", act_len);
    } else {
        int i;

        memcpy(xtra_buff, &rp[8], 8);
        xtra_buff[8] = '\0';
        /* Fixup any tab characters */
        for (i = 0; i < 8; ++i)
            if (xtra_buff[i] == 0x09)
                xtra_buff[i] = ' ';
        if (op->do_export) {
            len = encode_whitespaces((uint8_t *)xtra_buff, 8);
            if (len > 0) {
                printf("SCSI_VENDOR=%s\n", xtra_buff);
                encode_string(xtra_buff, &rp[8], 8);
                printf("SCSI_VENDOR_ENC=%s\n", xtra_buff);
            }
        } else
            printf(" Vendor identification: %s\n", xtra_buff);
        if (act_len <= 16) {
            if (! op->do_export)
                printf(" Product identification: <none>\n");
        } else {
            memcpy(xtra_buff, &rp[16], 16);
            xtra_buff[16] = '\0';
            if (op->do_export) {
                len = encode_whitespaces((uint8_t *)xtra_buff, 16);
                if (len > 0) {
                    printf("SCSI_MODEL=%s\n", xtra_buff);
                    encode_string(xtra_buff, &rp[16], 16);
                    printf("SCSI_MODEL_ENC=%s\n", xtra_buff);
                }
            } else
                printf(" Product identification: %s\n", xtra_buff);
        }
        if (act_len <= 32) {
            if (! op->do_export)
                printf(" Product revision level: <none>\n");
        } else {
            memcpy(xtra_buff, &rp[32], 4);
            xtra_buff[4] = '\0';
            if (op->do_export) {
                len = encode_whitespaces((uint8_t *)xtra_buff, 4);
                if (len > 0)
                    printf("SCSI_REVISION=%s\n", xtra_buff);
            } else
                printf(" Product revision level: %s\n", xtra_buff);
        }
        if (op->do_vendor && (act_len > 36) && ('\0' != rp[36]) &&
            (' ' != rp[36])) {
            memcpy(xtra_buff, &rp[36], act_len < 56 ? act_len - 36 :
                   20);
            if (op->do_export) {
                len = encode_whitespaces((uint8_t *)xtra_buff, 20);
                if (len > 0)
                    printf("VENDOR_SPECIFIC=%s\n", xtra_buff);
            } else
                printf(" Vendor specific: %s\n", xtra_buff);
        }
        if (op->do_descriptors) {
            for (j = 0, k = 58; ((j < 8) && ((k + 1) < act_len));
                 k +=2, ++j)
                vdesc_arr[j] = sg_get_unaligned_be16(rp + k);
        }
        if ((op->do_vendor > 1) && (act_len > 96)) {
            memcpy(xtra_buff, &rp[96], act_len - 96);
            if (op->do_export) {
                len = encode_whitespaces((uint8_t *)xtra_buff,
                                         act_len - 96);
                if (len > 0)
                    printf("VENDOR_SPECIFIC=%s\n", xtra_buff);
            } else
                printf(" Vendor specific: %s\n", xtra_buff);
        }
    }
    if (! op->do_export) {
        if ((0 == op->resp_len) && usn_buff[0])
            printf(" Unit serial number: %s\n", usn_buff);
        if (op->do_descriptors) {
            if (0 == vdesc_arr[0])
                printf("\n  No version descriptors available\n");
            else {
                printf("\n  Version descriptors:\n");
                for (k = 0; k < 8; ++k) {
                    if (0 == vdesc_arr[k])
                        break;
                    cp = find_version_descriptor_str(vdesc_arr[k]);
                    if (cp)
                        printf("    %s\n", cp);
                    else
                        printf("    [unrecognised version descriptor "
                               "code: 0x%x]\n", vdesc_arr[k]);
                }
            }
        }
    }
}

/* When sg_fd >= 0 fetch VPD page from device; mxlen is command line
 * --maxlen=LEN option (def: 0) or -1 for a VPD page with a short length
 * field (1 byte). When sg_fd < 0 then mxlen bytes have been read from
 * --inhex=FN file. Returns 0 for success. */
static int
vpd_fetch_page_from_dev(int sg_fd, uint8_t * rp, int page,
                        int mxlen, int vb, int * rlenp)
{
    int res, resid, rlen, len, n;

    if (sg_fd < 0) {
        len = sg_get_unaligned_be16(rp + 2) + 4;
        if (vb && (len > mxlen))
            pr2serr("warning: VPD page's length (%d) > bytes in --inhex=FN "
                    "file (%d)\n",  len , mxlen);
        if (rlenp)
            *rlenp = (len < mxlen) ? len : mxlen;
        return 0;
    }
    if (mxlen > MX_ALLOC_LEN) {
        pr2serr("--maxlen=LEN too long: %d > %d\n", mxlen, MX_ALLOC_LEN);
        return SG_LIB_SYNTAX_ERROR;
    }
    n = (mxlen > 0) ? mxlen : DEF_ALLOC_LEN;
    res = sg_ll_inquiry_v2(sg_fd, true, page, rp, n, DEF_PT_TIMEOUT, &resid,
                           true, vb);
    if (res)
        return res;
    rlen = n - resid;
    if (rlen < 4) {
        pr2serr("VPD response too short (len=%d)\n", rlen);
        return SG_LIB_CAT_MALFORMED;
    }
    if (page != rp[1]) {
        pr2serr("invalid VPD response; probably a STANDARD INQUIRY "
                "response\n");
        return SG_LIB_CAT_MALFORMED;
    } else if ((0x80 == page) && (0x2 == rp[2]) && (0x2 == rp[3])) {
        /* could be a Unit Serial number VPD page with a very long
         * length of 4+514 bytes; more likely standard response for
         * SCSI-2, RMB=1 and a response_data_format of 0x2. */
        pr2serr("invalid Unit Serial Number VPD response; probably a "
                "STANDARD INQUIRY response\n");
        return SG_LIB_CAT_MALFORMED;
    }
    if (mxlen < 0)
        len = rp[3] + 4;
    else
        len = sg_get_unaligned_be16(rp + 2) + 4;
    if (len <= rlen) {
        if (rlenp)
            *rlenp = len;
        return 0;
    } else if (mxlen) {
        if (rlenp)
            *rlenp = rlen;
        return 0;
    }
    if (len > MX_ALLOC_LEN) {
        pr2serr("response length too long: %d > %d\n", len, MX_ALLOC_LEN);
        return SG_LIB_CAT_MALFORMED;
    } else {
        /* First response indicated that not enough bytes of response were
         * requested, so try again, this time requesting more. */
        res = sg_ll_inquiry_v2(sg_fd, true, page, rp, len, DEF_PT_TIMEOUT,
                               &resid, true, vb);
        if (res)
            return res;
        rlen = len - resid;
        /* assume it is well behaved: hence page and len still same */
        if (rlenp)
            *rlenp = rlen;
        return 0;
    }
}

/* Returns 0 if Unit Serial Number VPD page contents found, else see
 * sg_ll_inquiry_v2() return values */
static int
fetch_unit_serial_num(int sg_fd, char * obuff, int obuff_len, int verbose)
{
    int len, k, res, c;
    uint8_t * b;
    uint8_t * free_b;

    b = sg_memalign(DEF_ALLOC_LEN, 0, &free_b, false);
    if (NULL == b) {
        pr2serr("%s: unable to allocate on heap\n", __func__);
        return sg_convert_errno(ENOMEM);
    }
    res = vpd_fetch_page_from_dev(sg_fd, b, VPD_SUPPORTED_VPDS,
                                  -1 /* 1 byte alloc_len */, verbose, &len);
    if (res) {
        if (verbose > 2)
            pr2serr("%s: no supported VPDs page\n", __func__);
        res = SG_LIB_CAT_MALFORMED;
        goto fini;
    }
    if (vpd_page_not_supported(b, len, VPD_UNIT_SERIAL_NUM, verbose)) {
        res = sg_convert_errno(EDOM); /* was SG_LIB_CAT_ILLEGAL_REQ */
        goto fini;
    }

    memset(b, 0xff, 4); /* guard against empty response */
    res = vpd_fetch_page_from_dev(sg_fd, b, VPD_UNIT_SERIAL_NUM, -1, verbose,
                                  &len);
    if ((0 == res) && (len > 3)) {
        len -= 4;
        len = (len < (obuff_len - 1)) ? len : (obuff_len - 1);
        if (len > 0) {
            /* replace non-printable characters (except NULL) with space */
            for (k = 0; k < len; ++k) {
                c = b[4 + k];
                if (c)
                    obuff[k] = isprint(c) ? c : ' ';
                else
                    break;
            }
            obuff[k] = '\0';
            res = 0;
            goto fini;
        } else {
            if (verbose > 2)
                pr2serr("%s: bad sn VPD page\n", __func__);
            res = SG_LIB_CAT_MALFORMED;
        }
    } else {
        if (verbose > 2)
            pr2serr("%s: no supported VPDs page\n", __func__);
        res = SG_LIB_CAT_MALFORMED;
    }
fini:
    if (free_b)
        free(free_b);
    return res;
}


/* Process a standard INQUIRY response. Returns 0 if successful */
static int
std_inq_process(int sg_fd, const struct opts_t * op, int inhex_len)
{
    int res, len, rlen, act_len;
    char buff[48];
    int vb, resid;

    if (sg_fd < 0) {    /* assume --inhex=FD usage */
        std_inq_decode(op, inhex_len);
        return 0;
    }
    rlen = (op->resp_len > 0) ? op->resp_len : SAFE_STD_INQ_RESP_LEN;
    vb = op->verbose;
    res = sg_ll_inquiry_v2(sg_fd, false, 0, rsp_buff, rlen, DEF_PT_TIMEOUT,
                           &resid, false, vb);
    if (0 == res) {
        if ((vb > 4) && ((rlen - resid) > 0)) {
            pr2serr("Safe (36 byte) Inquiry response:\n");
            hex2stderr(rsp_buff, rlen - resid, 0);
        }
        len = rsp_buff[4] + 5;
        if ((len > SAFE_STD_INQ_RESP_LEN) && (len < 256) &&
            (0 == op->resp_len)) {
            rlen = len;
            memset(rsp_buff, 0, rlen);
            if (sg_ll_inquiry_v2(sg_fd, false, 0, rsp_buff, rlen,
                                 DEF_PT_TIMEOUT, &resid, true, vb)) {
                pr2serr("second INQUIRY (%d byte) failed\n", len);
                return SG_LIB_CAT_OTHER;
            }
            if (len != (rsp_buff[4] + 5)) {
                pr2serr("strange, consecutive INQUIRYs yield different "
                        "'additional lengths'\n");
                len = rsp_buff[4] + 5;
            }
        }
        if (op->resp_len > 0)
            act_len = rlen;
        else
            act_len = (rlen < len) ? rlen : len;
        /* don't use more than HBA's resid says was transferred from LU */
        if (act_len > (rlen - resid))
            act_len = rlen - resid;
        if (act_len < SAFE_STD_INQ_RESP_LEN)
            rsp_buff[act_len] = '\0';
        if ((! op->do_only) && (! op->do_export) && (0 == op->resp_len)) {
            if (fetch_unit_serial_num(sg_fd, usn_buff, sizeof(usn_buff), vb))
                usn_buff[0] = '\0';
        }
        std_inq_decode(op, act_len);
        return 0;
    } else if (res < 0) { /* could be an ATA device */
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS) && \
    defined(HDIO_GET_IDENTITY)
        /* Try an ATA Identify Device command */
        res = try_ata_identify(sg_fd, op->do_hex, op->do_raw, vb);
        if (0 != res) {
            pr2serr("SCSI INQUIRY, NVMe Identify and fetching ATA "
                    "information failed on %s\n", op->device_name);
            return (res < 0) ? SG_LIB_CAT_OTHER : res;
        }
#else
        pr2serr("SCSI INQUIRY failed on %s, res=%d\n",
                op->device_name, res);
        return res;
#endif
    } else {
        char b[80];

        if (vb > 0) {
            pr2serr("    inquiry: failed requesting %d byte response: ", rlen);
            if (resid && (vb > 1))
                snprintf(buff, sizeof(buff), " [resid=%d]", resid);
            else
                buff[0] = '\0';
            sg_get_category_sense_str(res, sizeof(b), b, vb);
            pr2serr("%s%s\n", b, buff);
        }
        return res;
    }
    return 0;
}

#ifdef SG_SCSI_STRINGS
/* Returns 0 if successful */
static int
cmddt_process(int sg_fd, const struct opts_t * op)
{
    int k, j, num, len, peri_type, reserved_cmddt, support_num, res;
    char op_name[128];

    memset(rsp_buff, 0, rsp_buff_sz);
    if (op->do_cmddt > 1) {
        printf("Supported command list:\n");
        for (k = 0; k < 256; ++k) {
            res = sg_ll_inquiry(sg_fd, true /* cmddt */, false, k, rsp_buff,
                                DEF_ALLOC_LEN, true, op->verbose);
            if (0 == res) {
                peri_type = rsp_buff[0] & 0x1f;
                support_num = rsp_buff[1] & 7;
                reserved_cmddt = rsp_buff[4];
                if ((3 == support_num) || (5 == support_num)) {
                    num = rsp_buff[5];
                    for (j = 0; j < num; ++j)
                        printf(" %.2x", (int)rsp_buff[6 + j]);
                    if (5 == support_num)
                        printf("  [vendor specific manner (5)]");
                    sg_get_opcode_name((uint8_t)k, peri_type,
                                       sizeof(op_name) - 1, op_name);
                    op_name[sizeof(op_name) - 1] = '\0';
                    printf("  %s\n", op_name);
                } else if ((4 == support_num) || (6 == support_num))
                    printf("  opcode=0x%.2x vendor specific (%d)\n",
                           k, support_num);
                else if ((0 == support_num) && (reserved_cmddt > 0)) {
                    printf("  opcode=0x%.2x ignored cmddt bit, "
                           "given standard INQUIRY response, stop\n", k);
                    break;
                }
            } else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                break;
            else {
                pr2serr("CmdDt INQUIRY on opcode=0x%.2x: failed\n", k);
                break;
            }
        }
    }
    else {
        res = sg_ll_inquiry(sg_fd, true /* cmddt */, false, op->page_num,
                            rsp_buff, DEF_ALLOC_LEN, true, op->verbose);
        if (0 == res) {
            peri_type = rsp_buff[0] & 0x1f;
            if (! op->do_raw) {
                printf("CmdDt INQUIRY, opcode=0x%.2x:  [", op->page_num);
                sg_get_opcode_name((uint8_t)op->page_num, peri_type,
                                   sizeof(op_name) - 1, op_name);
                op_name[sizeof(op_name) - 1] = '\0';
                printf("%s]\n", op_name);
            }
            len = rsp_buff[5] + 6;
            reserved_cmddt = rsp_buff[4];
            if (op->do_hex)
                hex2stdout(rsp_buff, len, (1 == op->do_hex) ? 0 : -1);
            else if (op->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                bool prnt_cmd = false;
                const char * desc_p;

                support_num = rsp_buff[1] & 7;
                num = rsp_buff[5];
                switch (support_num) {
                case 0:
                    if (0 == reserved_cmddt)
                        desc_p = "no data available";
                    else
                        desc_p = "ignored cmddt bit, standard INQUIRY "
                                 "response";
                    break;
                case 1: desc_p = "not supported"; break;
                case 2: desc_p = "reserved (2)"; break;
                case 3: desc_p = "supported as per standard";
                        prnt_cmd = true;
                        break;
                case 4: desc_p = "vendor specific (4)"; break;
                case 5: desc_p = "supported in vendor specific way";
                        prnt_cmd = true;
                        break;
                case 6: desc_p = "vendor specific (6)"; break;
                case 7: desc_p = "reserved (7)"; break;
                }
                if (prnt_cmd) {
                    printf("  Support field: %s [", desc_p);
                    for (j = 0; j < num; ++j)
                        printf(" %.2x", (int)rsp_buff[6 + j]);
                    printf(" ]\n");
                } else
                    printf("  Support field: %s\n", desc_p);
            }
        } else if (SG_LIB_CAT_ILLEGAL_REQ != res) {
            if (! op->do_raw) {
                printf("CmdDt INQUIRY, opcode=0x%.2x:  [", op->page_num);
                sg_get_opcode_name((uint8_t)op->page_num, 0,
                                   sizeof(op_name) - 1, op_name);
                op_name[sizeof(op_name) - 1] = '\0';
                printf("%s]\n", op_name);
            }
            pr2serr("CmdDt INQUIRY on opcode=0x%.2x: failed\n", op->page_num);
        }
    }
    return res;
}

#else /* SG_SCSI_STRINGS */

/* Returns 0. */
static int
cmddt_process(int sg_fd, const struct opts_t * op)
{
    if (sg_fd) { }      /* suppress warning */
    if (op) { }         /* suppress warning */
    pr2serr("'--cmddt' not implemented, use sg_opcodes\n");
    return 0;
}

#endif /* SG_SCSI_STRINGS */


/* Returns 0 if successful */
static int
vpd_mainly_hex(int sg_fd, const struct opts_t * op, int inhex_len)
{
    int res, len;
    char b[128];
    const char * cp;
    uint8_t * rp;

    rp = rsp_buff;
    if ((! op->do_raw) && (op->do_hex < 2))
        printf("VPD INQUIRY, page code=0x%.2x:\n", op->page_num);
    if (sg_fd < 0) {
        len = sg_get_unaligned_be16(rp + 2) + 4;
        if (op->verbose && (len > inhex_len))
            pr2serr("warning: VPD page's length (%d) > bytes in --inhex=FN "
                    "file (%d)\n",  len , inhex_len);
        res = 0;
    } else {
        memset(rp, 0, DEF_ALLOC_LEN);
        res = vpd_fetch_page_from_dev(sg_fd, rp, op->page_num, op->resp_len,
                                      op->verbose, &len);
    }
    if (0 == res) {
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else {
            if (0 == op->page_num)
                decode_supported_vpd(rp, len, op->do_hex);
            else {
                if (op->verbose) {
                    cp = sg_get_pdt_str(rp[0] & 0x1f, sizeof(b), b);
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5, cp);
                }
                hex2stdout(rp, len, ((1 == op->do_hex) ? 0 : -1));
            }
        }
    } else {
        if (SG_LIB_CAT_ILLEGAL_REQ == res)
            pr2serr("    inquiry: field in cdb illegal (page not "
                    "supported)\n");
        else {
            sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
            pr2serr("    inquiry: %s\n", b);
        }
    }
    return res;
}

/* Returns 0 if successful */
static int
vpd_decode(int sg_fd, const struct opts_t * op, int inhex_len)
{
    int len, pdt, pn, vb, mxlen;
    int res = 0;
    uint8_t * rp;

    pn = op->page_num;
    rp = rsp_buff;
    vb = op->verbose;
    if (sg_fd >= 0)
        mxlen = op->resp_len;
    else
        mxlen = inhex_len;
    if (sg_fd != -1 && !op->do_force && pn != VPD_SUPPORTED_VPDS) {
        res = vpd_fetch_page_from_dev(sg_fd, rp, VPD_SUPPORTED_VPDS, mxlen,
                                      vb, &len);
        if (res)
            goto out;
        if (vpd_page_not_supported(rp, len, pn, vb)) {
            if (vb)
                pr2serr("Given VPD page not in supported list, use --force "
                        "to override this check\n");
            res = sg_convert_errno(EDOM); /* was SG_LIB_CAT_ILLEGAL_REQ */
            goto out;
        }
    }
    switch (pn) {
    case VPD_SUPPORTED_VPDS:
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: Supported VPD pages page\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else if (op->do_hex)
            hex2stdout(rp, len, (1 == op->do_hex) ? 0 : -1);
        else
            decode_supported_vpd(rp, len, 0x1f & rp[0]);
        break;
    case VPD_UNIT_SERIAL_NUM:
        if (! op->do_raw && ! op->do_export && (op->do_hex < 2))
            printf("VPD INQUIRY: Unit serial number page\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else if (op->do_hex)
            hex2stdout(rp, len, (1 == op->do_hex) ? 0 : -1);
        else {
            char obuff[DEF_ALLOC_LEN];
            int k, m;

            memset(obuff, 0, sizeof(obuff));
            len -= 4;
            if (len >= (int)sizeof(obuff))
                len = sizeof(obuff) - 1;
            memcpy(obuff, rp + 4, len);
            if (op->do_export) {
                k = encode_whitespaces((uint8_t *)obuff, len);
                if (k > 0) {
                    printf("SCSI_IDENT_SERIAL=");
                    /* udev-conforming character encoding */
                    for (m = 0; m < k; ++m) {
                        if ((obuff[m] >= '0' && obuff[m] <= '9') ||
                            (obuff[m] >= 'A' && obuff[m] <= 'Z') ||
                            (obuff[m] >= 'a' && obuff[m] <= 'z') ||
                            strchr("#+-.:=@_", obuff[m]) != NULL)
                            printf("%c", obuff[m]);
                        else
                            printf("\\x%02x", obuff[m]);
                    }
                    printf("\n");
                }
            } else {
                k = encode_unicode((uint8_t *)obuff, len);
                if (k > 0)
                    printf("  Unit serial number: %s\n", obuff);
            }
        }
        break;
    case VPD_DEVICE_ID:
        if (! op->do_raw && ! op->do_export && (op->do_hex < 3))
            printf("VPD INQUIRY: Device Identification page\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else if (op->do_hex > 2)
            hex2stdout(rp, len, -1);
        else if (op->do_export)
            export_dev_ids(rp + 4, len - 4, op->verbose);
        else
            decode_id_vpd(rp, len, op->do_hex, op->verbose);
        break;
    case VPD_SOFTW_INF_ID:
        if (! op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: Software interface identification page\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_softw_inf_id(rp, len, op->do_hex);
        break;
    case VPD_MAN_NET_ADDR:
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: Management network addresses page\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_net_man_vpd(rp, len, op->do_hex);
        break;
    case VPD_MODE_PG_POLICY:
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: Mode page policy\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_mode_policy_vpd(rp, len, op->do_hex);
        break;
    case VPD_EXT_INQ:
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: extended INQUIRY data page\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_x_inq_vpd(rp, len, op->do_hex);
        break;
    case VPD_ATA_INFO:
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: ATA information page\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        /* format output for 'hdparm --Istdin' with '-rr' or '-HHH' */
        if ((2 == op->do_raw) || (3 == op->do_hex))
            dWordHex((const unsigned short *)(rp + 60), 256, -2,
                     sg_is_big_endian());
        else if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_ata_info_vpd(rp, len, op->do_hex);
        break;
    case VPD_POWER_CONDITION:
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: Power condition page\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_power_condition(rp, len, op->do_hex);
        break;
    case VPD_SCSI_FEATURE_SETS:         /* 0x92 */
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: SCSI Feature sets\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_feature_sets_vpd(rp, len, op);
        break;
    case 0xb0:  /* VPD pages in B0h to BFh range depend on pdt */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (! op->do_raw && (op->do_hex < 2)) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
                    printf("VPD INQUIRY: Block limits page (SBC)\n");
                    break;
                case PDT_TAPE: case PDT_MCHANGER:
                    printf("VPD INQUIRY: Sequential access device "
                           "capabilities (SSC)\n");
                    break;
                case PDT_OSD:
                    printf("VPD INQUIRY: OSD information (OSD)\n");
                    break;
                default:
                    printf("VPD INQUIRY: page=0x%x, pdt=0x%x\n", 0xb0, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else
                decode_b0_vpd(rp, len, op->do_hex);
        } else if (! op->do_raw)
            pr2serr("VPD INQUIRY: page=0xb0\n");
        break;
    case 0xb1:  /* VPD pages in B0h to BFh range depend on pdt */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (! op->do_raw && (op->do_hex < 2)) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
                    printf("VPD INQUIRY: Block device characteristcis page "
                           "(SBC)\n");
                    break;
                case PDT_TAPE: case PDT_MCHANGER:
                    printf("Manufactured assigned serial number VPD page "
                           "(SSC):\n");
                    break;
                case PDT_OSD:
                    printf("Security token VPD page (OSD):\n");
                    break;
                case PDT_ADC:
                    printf("Manufactured assigned serial number VPD page "
                           "(ADC):\n");
                    break;
                default:
                    printf("VPD INQUIRY: page=0x%x, pdt=0x%x\n", 0xb1, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else
                decode_b1_vpd(rp, len, op->do_hex);
        } else if (! op->do_raw)
            pr2serr("VPD INQUIRY: page=0xb1\n");
        break;
    case 0xb2:  /* VPD pages in B0h to BFh range depend on pdt */
        if (!op->do_raw && (op->do_hex < 2))
            pr2serr(" Only hex output supported. The sg_vpd utility decodes "
                    "the B2h page.\n");
        return vpd_mainly_hex(sg_fd, op, inhex_len);
    case 0xb3:  /* VPD pages in B0h to BFh range depend on pdt */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (! op->do_raw && (op->do_hex < 2)) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
                    printf("VPD INQUIRY: Referrals VPD page (SBC)\n");
                    break;
                default:
                    printf("VPD INQUIRY: page=0x%x, pdt=0x%x\n", 0xb3, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else
                decode_b3_vpd(rp, len, op->do_hex);
        } else if (! op->do_raw)
            pr2serr("VPD INQUIRY: page=0xb3\n");
        break;
    case VPD_UPR_EMC:   /* 0xc0 */
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: Unit Path Report Page (EMC)\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, -1, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_upr_vpd_c0_emc(rp, len, op->do_hex);
        break;
    case VPD_RDAC_VERS:         /* 0xc2 */
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: Software Version (RDAC)\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, -1, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_rdac_vpd_c2(rp, len, op->do_hex);
        break;
    case VPD_RDAC_VAC:          /* 0xc9 */
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: Volume Access Control (RDAC)\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, -1, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_rdac_vpd_c9(rp, len, op->do_hex);
        break;
    case VPD_SCSI_PORTS:
        if (!op->do_raw && (op->do_hex < 2))
            printf("VPD INQUIRY: SCSI Ports page\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
        if (res)
            break;
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else
            decode_scsi_ports_vpd(rp, len, op->do_hex, op->verbose);
        break;
    default:
        if ((pn > 0) && (pn < 0x80)) {
            if (!op->do_raw && (op->do_hex < 2))
                printf("VPD INQUIRY: ASCII information page, FRU code=0x%x\n",
                       pn);
            res = vpd_fetch_page_from_dev(sg_fd, rp, pn, mxlen, vb, &len);
            if (0 == res) {
                if (op->do_raw)
                    dStrRaw((const char *)rp, len);
                else
                    decode_ascii_inf(rp, len, op->do_hex);
            }
        } else {
            if (op->do_hex < 2)
                pr2serr(" Only hex output supported. The sg_vpd and sdparm "
                        "utilies decode more VPD pages.\n");
            return vpd_mainly_hex(sg_fd, op, inhex_len);
        }
    }
out:
    if (res) {
        char b[80];

        if (SG_LIB_CAT_ILLEGAL_REQ == res)
            pr2serr("    inquiry: field in cdb illegal (page not "
                    "supported)\n");
        else {
            sg_get_category_sense_str(res, sizeof(b), b, vb);
            pr2serr("    inquiry: %s\n", b);
        }
    }
    return res;
}

#if (HAVE_NVME && (! IGNORE_NVME))

static void
nvme_hex_raw(const uint8_t * b, int b_len, const struct opts_t * op)
{
    if (op->do_raw)
        dStrRaw((const char *)b, b_len);
    else if (op->do_hex) {
        if (op->do_hex < 3) {
            printf("data_in buffer:\n");
            hex2stdout(b, b_len, (2 == op->do_hex));
        } else
            hex2stdout(b, b_len, -1);
    }
}

static const char * rperf[] = {"Best", "Better", "Good", "Degraded"};

static void
show_nvme_id_ns(const uint8_t * dinp, int do_long)
{
    bool got_eui_128 = false;
    uint32_t u, k, off, num_lbaf, flbas, flba_info, md_size, lb_size;
    uint64_t ns_sz, eui_64;

    num_lbaf = dinp[25] + 1;  /* spec says this is "0's based value" */
    flbas = dinp[26] & 0xf;   /* index of active LBA format (for this ns) */
    ns_sz = sg_get_unaligned_le64(dinp + 0);
    eui_64 = sg_get_unaligned_be64(dinp + 120);  /* N.B. big endian */
    if (! sg_all_zeros(dinp + 104, 16))
        got_eui_128 = true;
    printf("    Namespace size/capacity: %" PRIu64 "/%" PRIu64
           " blocks\n", ns_sz, sg_get_unaligned_le64(dinp + 8));
    printf("    Namespace utilization: %" PRIu64 " blocks\n",
           sg_get_unaligned_le64(dinp + 16));
    if (got_eui_128) {          /* N.B. big endian */
        printf("    NGUID: 0x%02x", dinp[104]);
        for (k = 1; k < 16; ++k)
            printf("%02x", dinp[104 + k]);
        printf("\n");
    } else if (do_long)
        printf("    NGUID: 0x0\n");
    if (eui_64)
        printf("    EUI-64: 0x%" PRIx64 "\n", eui_64); /* N.B. big endian */
    printf("    Number of LBA formats: %u\n", num_lbaf);
    printf("    Index LBA size: %u\n", flbas);
    for (k = 0, off = 128; k < num_lbaf; ++k, off += 4) {
        printf("    LBA format %u support:", k);
        if (k == flbas)
            printf(" <-- active\n");
        else
            printf("\n");
        flba_info = sg_get_unaligned_le32(dinp + off);
        md_size = flba_info & 0xffff;
        lb_size = flba_info >> 16 & 0xff;
        if (lb_size > 31) {
            pr2serr("%s: logical block size exponent of %u implies a LB "
                    "size larger than 4 billion bytes, ignore\n", __func__,
                    lb_size);
            continue;
        }
        lb_size = 1U << lb_size;
        ns_sz *= lb_size;
        ns_sz /= 500*1000*1000;
        if (ns_sz & 0x1)
            ns_sz = (ns_sz / 2) + 1;
        else
            ns_sz = ns_sz / 2;
        u = (flba_info >> 24) & 0x3;
        printf("      Logical block size: %u bytes\n", lb_size);
        printf("      Approximate namespace size: %" PRIu64 " GB\n", ns_sz);
        printf("      Metadata size: %u bytes\n", md_size);
        printf("      Relative performance: %s [0x%x]\n", rperf[u], u);
    }
}

/* Send Identify(CNS=0, nsid) and decode the Identify namespace response */
static int
nvme_id_namespace(struct sg_pt_base * ptvp, uint32_t nsid,
                  struct sg_nvme_passthru_cmd * id_cmdp, uint8_t * id_dinp,
                  int id_din_len, const struct opts_t * op)
{
    int ret = 0;
    int vb = op->verbose;
    uint8_t resp[16];

    clear_scsi_pt_obj(ptvp);
    id_cmdp->nsid = nsid;
    id_cmdp->cdw10 = 0x0;       /* CNS=0x0 Identify NS (CNTID=0) */
    id_cmdp->cdw11 = 0x0;       /* NVMSETID=0 (only valid when CNS=0x4) */
    id_cmdp->cdw14 = 0x0;       /* UUID index (assume not supported) */
    set_scsi_pt_data_in(ptvp, id_dinp, id_din_len);
    set_scsi_pt_sense(ptvp, resp, sizeof(resp));
    set_scsi_pt_cdb(ptvp, (const uint8_t *)id_cmdp, sizeof(*id_cmdp));
    ret = do_scsi_pt(ptvp, -1, 0 /* timeout (def: 1 min) */, vb);
    if (vb > 2)
        pr2serr("%s: do_scsi_pt() result is %d\n", __func__, ret);
    if (ret) {
        if (SCSI_PT_DO_BAD_PARAMS == ret)
            ret = SG_LIB_SYNTAX_ERROR;
        else if (SCSI_PT_DO_TIMEOUT == ret)
            ret = SG_LIB_CAT_TIMEOUT;
        else if (ret < 0)
            ret = sg_convert_errno(-ret);
        return ret;
    }
    if (op->do_hex || op->do_raw) {
        nvme_hex_raw(id_dinp, id_din_len, op);
        return 0;
    }
    show_nvme_id_ns(id_dinp, op->do_long);
    return 0;
}

static void
show_nvme_id_ctrl(const uint8_t *dinp, const char *dev_name, int do_long)
{
    bool got_fguid;
    uint8_t ver_min, ver_ter, mtds;
    uint16_t ver_maj, oacs, oncs;
    uint32_t k, ver, max_nsid, npss, j, n, m;
    uint64_t sz1, sz2;
    const uint8_t * up;

    max_nsid = sg_get_unaligned_le32(dinp + 516); /* NN */
    printf("Identify controller for %s:\n", dev_name);
    printf("  Model number: %.40s\n", (const char *)(dinp + 24));
    printf("  Serial number: %.20s\n", (const char *)(dinp + 4));
    printf("  Firmware revision: %.8s\n", (const char *)(dinp + 64));
    ver = sg_get_unaligned_le32(dinp + 80);
    ver_maj = (ver >> 16);
    ver_min = (ver >> 8) & 0xff;
    ver_ter = (ver & 0xff);
    printf("  Version: %u.%u", ver_maj, ver_min);
    if ((ver_maj > 1) || ((1 == ver_maj) && (ver_min > 2)) ||
        ((1 == ver_maj) && (2 == ver_min) && (ver_ter > 0)))
        printf(".%u\n", ver_ter);
    else
        printf("\n");
    oacs = sg_get_unaligned_le16(dinp + 256);
    if (0x1ff & oacs) {
        printf("  Optional admin command support:\n");
        if (0x200 & oacs)
            printf("    Get LBA status\n");     /* NVMe 1.4 */
        if (0x100 & oacs)
            printf("    Doorbell buffer config\n");
        if (0x80 & oacs)
            printf("    Virtualization management\n");
        if (0x40 & oacs)
            printf("    NVMe-MI send and NVMe-MI receive\n");
        if (0x20 & oacs)
            printf("    Directive send and directive receive\n");
        if (0x10 & oacs)
            printf("    Device self-test\n");
        if (0x8 & oacs)
            printf("    Namespace management and attachment\n");
        if (0x4 & oacs)
            printf("    Firmware download and commit\n");
        if (0x2 & oacs)
            printf("    Format NVM\n");
        if (0x1 & oacs)
            printf("    Security send and receive\n");
    } else
        printf("  No optional admin command support\n");
    oncs = sg_get_unaligned_le16(dinp + 256);
    if (0x7f & oncs) {
        printf("  Optional NVM command support:\n");
        if (0x80 & oncs)
            printf("    Verify\n");     /* NVMe 1.4 */
        if (0x40 & oncs)
            printf("    Timestamp feature\n");
        if (0x20 & oncs)
            printf("    Reservations\n");
        if (0x10 & oncs)
            printf("    Save and Select fields non-zero\n");
        if (0x8 & oncs)
            printf("    Write zeroes\n");
        if (0x4 & oncs)
            printf("    Dataset management\n");
        if (0x2 & oncs)
            printf("    Write uncorrectable\n");
        if (0x1 & oncs)
            printf("    Compare\n");
    } else
        printf("  No optional NVM command support\n");
    printf("  PCI vendor ID VID/SSVID: 0x%x/0x%x\n",
           sg_get_unaligned_le16(dinp + 0),
           sg_get_unaligned_le16(dinp + 2));
    printf("  IEEE OUI Identifier: 0x%x\n",
           sg_get_unaligned_le24(dinp + 73));
    got_fguid = ! sg_all_zeros(dinp + 112, 16);
    if (got_fguid) {
        printf("  FGUID: 0x%02x", dinp[112]);
        for (k = 1; k < 16; ++k)
            printf("%02x", dinp[112 + k]);
        printf("\n");
    } else if (do_long)
        printf("  FGUID: 0x0\n");
    printf("  Controller ID: 0x%x\n", sg_get_unaligned_le16(dinp + 78));
    if (do_long) {      /* Bytes 240 to 255 are reserved for NVME-MI */
        printf("  NVMe Management Interface [MI] settings:\n");
        printf("    Enclosure: %d [NVMEE]\n", !! (0x2 & dinp[253]));
        printf("    NVMe Storage device: %d [NVMESD]\n",
               !! (0x1 & dinp[253]));
        printf("    Management endpoint capabilities, over a PCIe port: %d "
               "[PCIEME]\n",
               !! (0x2 & dinp[255]));
        printf("    Management endpoint capabilities, over a SMBus/I2C port: "
               "%d [SMBUSME]\n", !! (0x1 & dinp[255]));
    }
    printf("  Number of namespaces: %u\n", max_nsid);
    sz1 = sg_get_unaligned_le64(dinp + 280);  /* lower 64 bits */
    sz2 = sg_get_unaligned_le64(dinp + 288);  /* upper 64 bits */
    if (sz2)
        printf("  Total NVM capacity: huge ...\n");
    else if (sz1)
        printf("  Total NVM capacity: %" PRIu64 " bytes\n", sz1);
    mtds = dinp[77];
    printf("  Maximum data transfer size: ");
    if (mtds)
        printf("%u pages\n", 1U << mtds);
    else
        printf("<unlimited>\n");

    if (do_long) {
        const char * const non_op = "does not process I/O";
        const char * const operat = "processes I/O";
        const char * cp;

        printf("  Total NVM capacity: 0 bytes\n");
        npss = dinp[263] + 1;
        up = dinp + 2048;
        for (k = 0; k < npss; ++k, up += 32) {
            n = sg_get_unaligned_le16(up + 0);
            n *= (0x1 & up[3]) ? 1 : 100;    /* unit: 100 microWatts */
            j = n / 10;                      /* unit: 1 milliWatts */
            m = j % 1000;
            j /= 1000;
            cp = (0x2 & up[3]) ? non_op : operat;
            printf("  Power state %u: Max power: ", k);
            if (0 == j) {
                m = n % 10;
                n /= 10;
                printf("%u.%u milliWatts, %s\n", n, m, cp);
            } else
                printf("%u.%03u Watts, %s\n", j, m, cp);
            n = sg_get_unaligned_le32(up + 4);
            if (0 == n)
                printf("    [ENLAT], ");
            else
                printf("    ENLAT=%u, ", n);
            n = sg_get_unaligned_le32(up + 8);
            if (0 == n)
                printf("[EXLAT], ");
            else
                printf("EXLAT=%u, ", n);
            n = 0x1f & up[12];
            printf("RRT=%u, ", n);
            n = 0x1f & up[13];
            printf("RRL=%u, ", n);
            n = 0x1f & up[14];
            printf("RWT=%u, ", n);
            n = 0x1f & up[15];
            printf("RWL=%u\n", n);
        }
    }
}

/* Send a NVMe Identify(CNS=1) and decode Controller info. If the
 * device name includes a namespace indication (e.g. /dev/nvme0ns1) then
 * an Identify namespace command is sent to that namespace (e.g. 1). If the
 * device name does not contain a namespace indication (e.g. /dev/nvme0)
 * and --only is not given then nvme_id_namespace() is sent for each
 * namespace in the controller. Namespaces number sequentially starting at
 * 1 . The CNS (Controller or Namespace Structure) field is CDW10 7:0, was
 * only bit 0 in NVMe 1.0 and bits 1:0 in NVMe 1.1, thereafter 8 bits. */
static int
do_nvme_identify_ctrl(int pt_fd, const struct opts_t * op)
{
    int ret = 0;
    int vb = op->verbose;
    uint32_t k, nsid, max_nsid;
    struct sg_pt_base * ptvp;
    struct sg_nvme_passthru_cmd identify_cmd;
    struct sg_nvme_passthru_cmd * id_cmdp = &identify_cmd;
    uint8_t * id_dinp = NULL;
    uint8_t * free_id_dinp = NULL;
    const uint32_t pg_sz = sg_get_page_size();
    uint8_t resp[16];

    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }
    ptvp = construct_scsi_pt_obj_with_fd(pt_fd, vb);
    if (NULL == ptvp) {
        pr2serr("%s: memory problem\n", __func__);
        return sg_convert_errno(ENOMEM);
    }
    memset(id_cmdp, 0, sizeof(*id_cmdp));
    id_cmdp->opcode = 0x6;
    nsid = get_pt_nvme_nsid(ptvp);
    id_cmdp->cdw10 = 0x1;       /* CNS=0x1 --> Identify controller */
    /* id_cmdp->nsid is a "don't care" when CNS=1, so leave as 0 */
    id_dinp = sg_memalign(pg_sz, pg_sz, &free_id_dinp, false);
    if (NULL == id_dinp) {
        pr2serr("%s: sg_memalign problem\n", __func__);
        return sg_convert_errno(ENOMEM);
    }
    set_scsi_pt_data_in(ptvp, id_dinp, pg_sz);
    set_scsi_pt_cdb(ptvp, (const uint8_t *)id_cmdp, sizeof(*id_cmdp));
    set_scsi_pt_sense(ptvp, resp, sizeof(resp));
    ret = do_scsi_pt(ptvp, -1, 0 /* timeout (def: 1 min) */, vb);
    if (vb > 2)
        pr2serr("%s: do_scsi_pt result is %d\n", __func__, ret);
    if (ret) {
        if (SCSI_PT_DO_BAD_PARAMS == ret)
            ret = SG_LIB_SYNTAX_ERROR;
        else if (SCSI_PT_DO_TIMEOUT == ret)
            ret = SG_LIB_CAT_TIMEOUT;
        else if (ret < 0)
            ret = sg_convert_errno(-ret);
        goto err_out;
    }
    max_nsid = sg_get_unaligned_le32(id_dinp + 516); /* NN */
    if (op->do_raw || op->do_hex) {
        if (op->do_only || (SG_NVME_CTL_NSID == nsid ) ||
            (SG_NVME_BROADCAST_NSID == nsid)) {
            nvme_hex_raw(id_dinp, pg_sz, op);
            goto fini;
        }
        goto skip1;
    }
    show_nvme_id_ctrl(id_dinp, op->device_name, op->do_long);
skip1:
    if (op->do_only)
        goto fini;
    if (nsid > 0) {
        if (! (op->do_raw || (op->do_hex > 2))) {
            printf("  Namespace %u (deduced from device name):\n", nsid);
            if (nsid > max_nsid)
                pr2serr("NSID from device (%u) should not exceed number of "
                        "namespaces (%u)\n", nsid, max_nsid);
        }
        ret = nvme_id_namespace(ptvp, nsid, id_cmdp, id_dinp, pg_sz, op);
        if (ret)
            goto err_out;

    } else {        /* nsid=0 so char device; loop over all namespaces */
        for (k = 1; k <= max_nsid; ++k) {
            if ((! op->do_raw) || (op->do_hex < 3))
                printf("  Namespace %u (of %u):\n", k, max_nsid);
            ret = nvme_id_namespace(ptvp, k, id_cmdp, id_dinp, pg_sz, op);
            if (ret)
                goto err_out;
            if (op->do_raw || op->do_hex)
                goto fini;
        }
    }
fini:
    ret = 0;
err_out:
    destruct_scsi_pt_obj(ptvp);
    free(free_id_dinp);
    return ret;
}
#endif          /* (HAVE_NVME && (! IGNORE_NVME)) */


int
main(int argc, char * argv[])
{
    int res, n, err;
    int sg_fd = -1;
    int ret = 0;
    int inhex_len = 0;
    const struct svpd_values_name_t * vnp;
    struct opts_t opts;
    struct opts_t * op;

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->page_num = -1;
    op->page_pdt = -1;
    op->do_block = -1;         /* use default for OS */
    res = parse_cmd_line(op, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (op->do_help) {
        usage_for(op);
        if (op->do_help > 1) {
            pr2serr("\n>>> Available VPD page abbreviations:\n");
            enumerate_vpds();
        }
        return 0;
    }

#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (op->verbose_given && op->version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        op->verbose_given = false;
        op->version_given = false;
        op->verbose = 0;
    } else if (! op->verbose_given) {
        pr2serr("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", op->verbose);
#else
    if (op->verbose_given && op->version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }
    if (op->page_arg) {
        if (op->page_num >= 0) {
            pr2serr("Given '-p' option and another option that "
                    "implies a page\n");
            return SG_LIB_CONTRADICT;
        }
        if (isalpha(op->page_arg[0])) {
            vnp = sdp_find_vpd_by_acron(op->page_arg);
            if (NULL == vnp) {
#ifdef SG_SCSI_STRINGS
                if (op->opt_new)
                    pr2serr("abbreviation %s given to '--page=' "
                            "not recognized\n", op->page_arg);
                else
                    pr2serr("abbreviation %s given to '-p=' "
                            "not recognized\n", op->page_arg);
#else
                pr2serr("abbreviation %s given to '--page=' "
                        "not recognized\n", op->page_arg);
#endif
                pr2serr(">>> Available abbreviations:\n");
                enumerate_vpds();
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((1 != op->do_hex) && (0 == op->do_raw))
                op->do_decode = true;
            op->page_num = vnp->value;
            op->page_pdt = vnp->pdt;
        } else if ('-' == op->page_arg[0])
            op->page_num = VPD_NOPE_WANT_STD_INQ;
        else {
#ifdef SG_SCSI_STRINGS
            if (op->opt_new) {
                n = sg_get_num(op->page_arg);
                if ((n < 0) || (n > 255)) {
                    pr2serr("Bad argument to '--page=', "
                            "expecting 0 to 255 inclusive\n");
                    usage_for(op);
                    return SG_LIB_SYNTAX_ERROR;
                }
                if ((1 != op->do_hex) && (0 == op->do_raw))
                    op->do_decode = true;
            } else {
                int num;
                unsigned int u;

                num = sscanf(op->page_arg, "%x", &u);
                if ((1 != num) || (u > 255)) {
                    pr2serr("Inappropriate value after '-o=' "
                            "or '-p=' option\n");
                    usage_for(op);
                    return SG_LIB_SYNTAX_ERROR;
                }
                n = u;
            }
#else
            n = sg_get_num(op->page_arg);
            if ((n < 0) || (n > 255)) {
                pr2serr("Bad argument to '--page=', "
                        "expecting 0 to 255 inclusive\n");
                usage_for(op);
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((1 != op->do_hex) && (0 == op->do_raw))
                op->do_decode = true;
#endif /* SG_SCSI_STRINGS */
            op->page_num = n;
        }
    }
    rsp_buff = sg_memalign(rsp_buff_sz, 0 /* page align */, &free_rsp_buff,
                           false);
    if (NULL == rsp_buff) {
        pr2serr("Unable to allocate %d bytes on heap\n", rsp_buff_sz);
        return sg_convert_errno(ENOMEM);
    }
    if (op->inhex_fn) {
        if (op->device_name) {
            pr2serr("Cannot have both a DEVICE and --inhex= option\n");
            ret = SG_LIB_CONTRADICT;
            goto err_out;
        }
        if (op->do_cmddt) {
            pr2serr("Don't support --cmddt with --inhex= option\n");
            ret = SG_LIB_CONTRADICT;
            goto err_out;
        }
        err = sg_f2hex_arr(op->inhex_fn, !!op->do_raw, false, rsp_buff,
                           &inhex_len, rsp_buff_sz);
        if (err) {
            if (err < 0)
                err = sg_convert_errno(-err);
            ret = err;
            goto err_out;
        }
        op->do_raw = 0;         /* don't want raw on output with --inhex= */
        if (-1 == op->page_num) {       /* may be able to deduce VPD page */
            if (op->page_pdt < 0)
                op->page_pdt = 0x1f & rsp_buff[0];
            if ((0x2 == (0xf & rsp_buff[3])) && (rsp_buff[2] > 2)) {
                if (op->verbose)
                    pr2serr("Guessing from --inhex= this is a standard "
                            "INQUIRY\n");
            } else if (rsp_buff[2] <= 2) {
                /*
                 * Removable devices have the RMB bit set, which would
                 * present itself as vpd page 0x80 output if we're not
                 * careful
                 *
                 * Serial number must be right-aligned ASCII data in
                 * bytes 5-7; standard INQUIRY will have flags here.
                 */
                if (rsp_buff[1] == 0x80 &&
                    (rsp_buff[5] < 0x20 || rsp_buff[5] > 0x80 ||
                     rsp_buff[6] < 0x20 || rsp_buff[6] > 0x80 ||
                     rsp_buff[7] < 0x20 || rsp_buff[7] > 0x80)) {
                    if (op->verbose)
                        pr2serr("Guessing from --inhex= this is a "
                                "standard INQUIRY\n");
                } else {
                    if (op->verbose)
                        pr2serr("Guessing from --inhex= this is VPD "
                                "page 0x%x\n", rsp_buff[1]);
                    op->page_num = rsp_buff[1];
                    op->do_vpd = true;
                    if ((1 != op->do_hex) && (0 == op->do_raw))
                        op->do_decode = true;
                }
            } else {
                if (op->verbose)
                    pr2serr("page number unclear from --inhex, hope it's a "
                            "standard INQUIRY\n");
            }
        }
    } else if (0 == op->device_name) {
        pr2serr("No DEVICE argument given\n\n");
        usage_for(op);
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }
    if (VPD_NOPE_WANT_STD_INQ == op->page_num)
        op->page_num = -1;  /* now past guessing, set to normal indication */

    if (op->do_export) {
        if (op->page_num != -1) {
            if (op->page_num != VPD_DEVICE_ID &&
                op->page_num != VPD_UNIT_SERIAL_NUM) {
                pr2serr("Option '--export' only supported for VPD pages 0x80 "
                        "and 0x83\n");
                usage_for(op);
                ret = SG_LIB_CONTRADICT;
                goto err_out;
            }
            op->do_decode = true;
            op->do_vpd = true;
        }
    }

    if ((0 == op->do_cmddt) && (op->page_num >= 0) && op->page_given)
        op->do_vpd = true;

    if (op->do_raw && op->do_hex) {
        pr2serr("Can't do hex and raw at the same time\n");
        usage_for(op);
        ret = SG_LIB_CONTRADICT;
        goto err_out;
    }
    if (op->do_vpd && op->do_cmddt) {
#ifdef SG_SCSI_STRINGS
        if (op->opt_new)
            pr2serr("Can't use '--cmddt' with VPD pages\n");
        else
            pr2serr("Can't have both '-e' and '-c' (or '-cl')\n");
#else
        pr2serr("Can't use '--cmddt' with VPD pages\n");
#endif
        usage_for(op);
        ret = SG_LIB_CONTRADICT;
        goto err_out;
    }
    if (((op->do_vpd || op->do_cmddt)) && (op->page_num < 0))
        op->page_num = 0;
    if (op->num_pages > 1) {
        pr2serr("Can only fetch one page (VPD or Cmd) at a time\n");
        usage_for(op);
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }
    if (op->do_descriptors) {
        if ((op->resp_len > 0) && (op->resp_len < 60)) {
            pr2serr("version descriptors need INQUIRY response "
                    "length >= 60 bytes\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        if (op->do_vpd || op->do_cmddt) {
            pr2serr("version descriptors require standard INQUIRY\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
    }
    if (op->num_pages && op->do_ata) {
        pr2serr("Can't use '-A' with an explicit decode VPD page option\n");
        ret = SG_LIB_CONTRADICT;
        goto err_out;
    }

    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
    }
    if (op->inhex_fn) {
        if (op->do_vpd) {
            if (op->do_decode)
                ret = vpd_decode(-1, op, inhex_len);
            else
                ret = vpd_mainly_hex(-1, op, inhex_len);
            goto err_out;
        }
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS) && \
    defined(HDIO_GET_IDENTITY)
        else if (op->do_ata) {
            prepare_ata_identify(op, inhex_len);
            ret = 0;
            goto err_out;
        }
#endif
        else {
            ret = std_inq_process(-1, op, inhex_len);
            goto err_out;
        }
    }

#if defined(O_NONBLOCK) && defined(O_RDONLY)
    if (op->do_block >= 0) {
        n = O_RDONLY | (op->do_block ? 0 : O_NONBLOCK);
        if ((sg_fd = sg_cmds_open_flags(op->device_name, n,
                                        op->verbose)) < 0) {
            pr2serr("sg_inq: error opening file: %s: %s\n",
                    op->device_name, safe_strerror(-sg_fd));
            ret = sg_convert_errno(-sg_fd);
            if (ret < 0)
                ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }

    } else {
        if ((sg_fd = sg_cmds_open_device(op->device_name, true /* ro */,
                                         op->verbose)) < 0) {
            pr2serr("sg_inq: error opening file: %s: %s\n",
                    op->device_name, safe_strerror(-sg_fd));
            ret = sg_convert_errno(-sg_fd);
            if (ret < 0)
                ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
    }
#else
    if ((sg_fd = sg_cmds_open_device(op->device_name, true /* ro */,
                                     op->verbose)) < 0) {
        pr2serr("sg_inq: error opening file: %s: %s\n",
                op->device_name, safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        if (ret < 0)
            ret = SG_LIB_FILE_ERROR;
        goto err_out;
    }
#endif
    memset(rsp_buff, 0, rsp_buff_sz);

#if (HAVE_NVME && (! IGNORE_NVME))
    n = check_pt_file_handle(sg_fd, op->device_name, op->verbose);
    if (op->verbose > 1)
        pr2serr("check_pt_file_handle()-->%d, page_given=%d\n", n,
                op->page_given);
    if ((3 == n) || (4 == n)) {   /* NVMe char or NVMe block */
        op->possible_nvme = true;
        if (! op->page_given) {
            ret = do_nvme_identify_ctrl(sg_fd, op);
            goto fini2;
        }
    }
#endif

#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS) && \
    defined(HDIO_GET_IDENTITY)
    if (op->do_ata) {
        res = try_ata_identify(sg_fd, op->do_hex, op->do_raw,
                               op->verbose);
        if (0 != res) {
            pr2serr("fetching ATA information failed on %s\n",
                    op->device_name);
            ret = SG_LIB_CAT_OTHER;
        } else
            ret = 0;
        goto fini3;
    }
#endif

    if ((! op->do_cmddt) && (! op->do_vpd)) {
        /* So it's a standard INQUIRY, try ATA IDENTIFY if that fails */
        ret = std_inq_process(sg_fd, op, -1);
        if (ret)
            goto err_out;
    } else if (op->do_cmddt) {
        if (op->page_num < 0)
            op->page_num = 0;
        ret = cmddt_process(sg_fd, op);
        if (ret)
            goto err_out;
    } else if (op->do_vpd) {
        if (op->do_decode) {
            ret = vpd_decode(sg_fd, op, -1);
            if (ret)
                goto err_out;
        } else {
            ret = vpd_mainly_hex(sg_fd, op, -1);
            if (ret)
                goto err_out;
        }
    }

#if (HAVE_NVME && (! IGNORE_NVME))
fini2:
#endif
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS) && \
    defined(HDIO_GET_IDENTITY)
fini3:
#endif

err_out:
    if (free_rsp_buff)
        free(free_rsp_buff);
    if ((0 == op->verbose) && (! op->do_export)) {
        if (! sg_if_can2stderr("sg_inq failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    res = (sg_fd >= 0) ? sg_cmds_close_device(sg_fd) : 0;
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return sg_convert_errno(-res);
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}


#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS) && \
    defined(HDIO_GET_IDENTITY)
/* Following code permits ATA IDENTIFY commands to be performed on
   ATA non "Packet Interface" devices (e.g. ATA disks).
   GPL-ed code borrowed from smartmontools (smartmontools.sf.net).
   Copyright (C) 2002-4 Bruce Allen
                <smartmontools-support@lists.sourceforge.net>
 */
#ifndef ATA_IDENTIFY_DEVICE
#define ATA_IDENTIFY_DEVICE 0xec
#define ATA_IDENTIFY_PACKET_DEVICE 0xa1
#endif
#ifndef HDIO_DRIVE_CMD
#define HDIO_DRIVE_CMD    0x031f
#endif

/* Needed parts of the ATA DRIVE IDENTIFY Structure. Those labeled
 * word* are NOT used.
 */
struct ata_identify_device {
  unsigned short words000_009[10];
  uint8_t  serial_no[20];
  unsigned short words020_022[3];
  uint8_t  fw_rev[8];
  uint8_t  model[40];
  unsigned short words047_079[33];
  unsigned short major_rev_num;
  unsigned short minor_rev_num;
  unsigned short command_set_1;
  unsigned short command_set_2;
  unsigned short command_set_extension;
  unsigned short cfs_enable_1;
  unsigned short word086;
  unsigned short csf_default;
  unsigned short words088_255[168];
};

#define ATA_IDENTIFY_BUFF_SZ  sizeof(struct ata_identify_device)
#define HDIO_DRIVE_CMD_OFFSET 4

static int
ata_command_interface(int device, char *data, bool * atapi_flag, int verbose)
{
    int err;
    uint8_t buff[ATA_IDENTIFY_BUFF_SZ + HDIO_DRIVE_CMD_OFFSET];
    unsigned short get_ident[256];

    if (atapi_flag)
        *atapi_flag = false;
    memset(buff, 0, sizeof(buff));
    if (ioctl(device, HDIO_GET_IDENTITY, &get_ident) < 0) {
        err = errno;
        if (ENOTTY == err) {
            if (verbose > 1)
                pr2serr("HDIO_GET_IDENTITY failed with ENOTTY, "
                        "try HDIO_DRIVE_CMD ioctl ...\n");
            buff[0] = ATA_IDENTIFY_DEVICE;
            buff[3] = 1;
            if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
                if (verbose)
                    pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                            "ioctl failed:\n\t%s [%d]\n",
                            safe_strerror(err), err);
                return sg_convert_errno(err);
            }
            memcpy(data, buff + HDIO_DRIVE_CMD_OFFSET, ATA_IDENTIFY_BUFF_SZ);
            return 0;
        } else {
            if (verbose)
                pr2serr("HDIO_GET_IDENTITY ioctl failed:\n"
                        "\t%s [%d]\n", safe_strerror(err), err);
            return sg_convert_errno(err);
        }
    } else if (verbose > 1)
        pr2serr("HDIO_GET_IDENTITY succeeded\n");
    if (0x2 == ((get_ident[0] >> 14) &0x3)) {   /* ATAPI device */
        if (verbose > 1)
            pr2serr("assume ATAPI device from HDIO_GET_IDENTITY response\n");
        memset(buff, 0, sizeof(buff));
        buff[0] = ATA_IDENTIFY_PACKET_DEVICE;
        buff[3] = 1;
        if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
            err = errno;
            if (verbose)
                pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_PACKET_DEVICE) ioctl "
                        "failed:\n\t%s [%d]\n", safe_strerror(err), err);
            buff[0] = ATA_IDENTIFY_DEVICE;
            buff[3] = 1;
            if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
                err = errno;
                if (verbose)
                    pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) ioctl "
                            "failed:\n\t%s [%d]\n", safe_strerror(err), err);
                return sg_convert_errno(err);
            }
        } else if (atapi_flag) {
            *atapi_flag = true;
            if (verbose > 1)
                pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) succeeded\n");
        }
    } else {    /* assume non-packet device */
        buff[0] = ATA_IDENTIFY_DEVICE;
        buff[3] = 1;
        if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
            err = errno;
            if (verbose)
                pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) ioctl failed:"
                        "\n\t%s [%d]\n", safe_strerror(err), err);
            return sg_convert_errno(err);
        } else if (verbose > 1)
            pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) succeeded\n");
    }
    /* if the command returns data, copy it back */
    memcpy(data, buff + HDIO_DRIVE_CMD_OFFSET, ATA_IDENTIFY_BUFF_SZ);
    return 0;
}

static void
show_ata_identify(const struct ata_identify_device * aidp, bool atapi,
                  int vb)
{
    int res;
    char model[64];
    char serial[64];
    char firm[64];

    printf("%s device: model, serial number and firmware revision:\n",
           (atapi ? "ATAPI" : "ATA"));
    res = sg_ata_get_chars((const unsigned short *)aidp->model,
                           0, 20, sg_is_big_endian(), model);
    model[res] = '\0';
    res = sg_ata_get_chars((const unsigned short *)aidp->serial_no,
                           0, 10, sg_is_big_endian(), serial);
    serial[res] = '\0';
    res = sg_ata_get_chars((const unsigned short *)aidp->fw_rev,
                           0, 4, sg_is_big_endian(), firm);
    firm[res] = '\0';
    printf("  %s %s %s\n", model, serial, firm);
    if (vb) {
        if (atapi)
            printf("ATA IDENTIFY PACKET DEVICE response "
                   "(256 words):\n");
        else
            printf("ATA IDENTIFY DEVICE response (256 words):\n");
        dWordHex((const unsigned short *)aidp, 256, 0,
                 sg_is_big_endian());
    }
}

static void
prepare_ata_identify(const struct opts_t * op, int inhex_len)
{
    int n = inhex_len;
    struct ata_identify_device ata_ident;

    if (n < 16) {
        pr2serr("%s: got only %d bytes, give up\n", __func__, n);
        return;
    } else if (n < 512)
        pr2serr("%s: expect 512 bytes or more, got %d, continue\n", __func__,
                n);
    else if (n > 512)
        n = 512;
    memset(&ata_ident, 0, sizeof(ata_ident));
    memcpy(&ata_ident, rsp_buff, n);
    show_ata_identify(&ata_ident, false, op->verbose);
}

/* Returns 0 if successful, else errno of error */
static int
try_ata_identify(int ata_fd, int do_hex, int do_raw, int verbose)
{
    bool atapi;
    int res;
    struct ata_identify_device ata_ident;

    memset(&ata_ident, 0, sizeof(ata_ident));
    res = ata_command_interface(ata_fd, (char *)&ata_ident, &atapi, verbose);
    if (res)
        return res;
    if ((2 == do_raw) || (3 == do_hex))
        dWordHex((const unsigned short *)&ata_ident, 256, -2,
                 sg_is_big_endian());
    else if (do_raw)
        dStrRaw((const char *)&ata_ident, 512);
    else {
        if (do_hex) {
            if (atapi)
                printf("ATA IDENTIFY PACKET DEVICE response ");
            else
                printf("ATA IDENTIFY DEVICE response ");
            if (do_hex > 1) {
                printf("(512 bytes):\n");
                hex2stdout((const uint8_t *)&ata_ident, 512, 0);
            } else {
                printf("(256 words):\n");
                dWordHex((const unsigned short *)&ata_ident, 256, 0,
                         sg_is_big_endian());
            }
        } else
            show_ata_identify(&ata_ident, atapi, verbose);
    }
    return 0;
}
#endif

/* structure defined in sg_lib_data.h */
extern struct sg_lib_simple_value_name_t sg_version_descriptor_arr[];


static const char *
find_version_descriptor_str(int value)
{
    int k;
    const struct sg_lib_simple_value_name_t * vdp;

    for (k = 0; ((vdp = sg_version_descriptor_arr + k) && vdp->name); ++k) {
        if (value == vdp->value)
            return vdp->name;
        if (value < vdp->value)
            break;
    }
    return NULL;
}

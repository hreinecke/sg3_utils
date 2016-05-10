/* A utility program originally written for the Linux OS SCSI subsystem.
*  Copyright (C) 2000-2016 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI INQUIRY command.
   It is mainly based on the SCSI SPC-4 document at http://www.t10.org .

   Acknowledgment:
      - Martin Schwenke <martin at meltin dot net> added the raw switch and
        other improvements [20020814]
      - Lars Marowsky-Bree <lmb at suse dot de> contributed Unit Path Report
        VPD page decoding for EMC CLARiiON devices [20041016]
*/

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef SG_LIB_LINUX
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/hdreg.h>
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.62 20160510";    /* SPC-5 rev 10 */

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
#define VPD_EXT_INQ  0x86
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
#define VPD_BLOCK_LIMITS 0xb0
#define VPD_BLOCK_DEV_CHARS 0xb1
#define VPD_MAN_ASS_SN 0xb1
#define VPD_LB_PROVISIONING 0xb2
#define VPD_REFERRALS 0xb3
#define VPD_UPR_EMC 0xc0
#define VPD_RDAC_VERS 0xc2
#define VPD_RDAC_VAC 0xc9

/* values for selection one or more associations (2**vpd_assoc),
   except _AS_IS */
#define VPD_DI_SEL_LU 1
#define VPD_DI_SEL_TPORT 2
#define VPD_DI_SEL_TARGET 4
#define VPD_DI_SEL_AS_IS 32

#define DEF_ALLOC_LEN 252
#define SAFE_STD_INQ_RESP_LEN 36
#define MX_ALLOC_LEN (0xc000 + 0x80)
#define VPD_ATA_INFO_LEN  572

#define SENSE_BUFF_LEN  64       /* Arbitrary, could be larger */
#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define DEF_PT_TIMEOUT  60       /* 60 seconds */


static unsigned char rsp_buff[MX_ALLOC_LEN + 1];
static char xtra_buff[MX_ALLOC_LEN + 1];
static char usn_buff[MX_ALLOC_LEN + 1];

static const char * find_version_descriptor_str(int value);
static void decode_dev_ids(const char * leadin, unsigned char * buff,
                           int len, int do_hex, int verbose);

#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
static int try_ata_identify(int ata_fd, int do_hex, int do_raw,
                            int verbose);
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

static struct svpd_values_name_t vpd_pg[] = {
    {VPD_ATA_INFO, 0, -1, 0, "ai", "ATA information (SAT)"},
    {VPD_BLOCK_DEV_CHARS, 0, 0, 0, "bdc",
     "Block device characteristics (SBC)"},
    {VPD_BLOCK_LIMITS, 0, 0, 0, "bl", "Block limits (SBC)"},
    {VPD_DEVICE_ID, 0, -1, 0, "di", "Device identification"},
#if 0
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
    {VPD_SOFTW_INF_ID, 0, -1, 0, "sii", "Software interface identification"},
    {VPD_UNIT_SERIAL_NUM, 0, -1, 0, "sn", "Unit serial number"},
    {VPD_SCSI_PORTS, 0, -1, 0, "sp", "SCSI ports"},
    {VPD_SUPPORTED_VPDS, 0, -1, 0, "sv", "Supported VPD pages"},
    {VPD_3PARTY_COPY, 0, -1, 0, "tpc", "Third party copy"},
    /* Following are vendor specific */
    {VPD_RDAC_VAC, 0, -1, 1, "rdac_vac", "RDAC volume access control (RDAC)"},
    {VPD_RDAC_VERS, 0, -1, 1, "rdac_vers", "RDAC software version (RDAC)"},
    {VPD_UPR_EMC, 0, -1, 1, "upr", "Unit path report (EMC)"},
    {0, 0, 0, 0, NULL, NULL},
};

static struct option long_options[] = {
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
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
        {"maxlen", required_argument, 0, 'm'},
#ifdef SG_SCSI_STRINGS
        {"new", no_argument, 0, 'N'},
        {"old", no_argument, 0, 'O'},
#endif
        {"page", required_argument, 0, 'p'},
        {"raw", no_argument, 0, 'r'},
        {"vendor", no_argument, 0, 's'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"vpd", no_argument, 0, 'e'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_ata;
    int do_block;
    int do_cmddt;
    int do_descriptors;
    int do_export;
    int do_force;
    int do_help;
    int do_hex;
    int do_raw;
    int do_vendor;
    int do_verbose;
    int do_version;
    int do_decode;
    int do_vpd;
    int resp_len;
    int page_num;
    int page_pdt;
    int num_pages;
    int num_opcodes;
    int p_given;
    const char * page_arg;
    const char * device_name;
    const char * inhex_fn;
#ifdef SG_SCSI_STRINGS
    int opt_new;
#endif
};


static void
usage()
{
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
    pr2serr("Usage: sg_inq [--ata] [--block=0|1] [--cmddt] [--descriptors] "
            "[--export]\n"
            "              [--extended] [--help] [--hex] [--id] [--inhex=FN] "
            "[--len=LEN]\n"
            "              [--maxlen=LEN] [--page=PG] [--raw] [--vendor] "
            "[--verbose]\n"
            "              [--version] [--vpd] DEVICE\n"
            "  where:\n"
            "    --ata|-a        treat DEVICE as (directly attached) ATA "
            "device\n");
#else
    pr2serr("Usage: sg_inq [--block=0|1] [--cmddt] [--descriptors] "
            "[--export]\n"
            "              [--extended] [--help] [--hex] [--id] [--inhex=FN] "
            "[--len=LEN]\n"
            "              [--maxlen=LEN] [--page=PG] [--raw] [--verbose] "
            "[--version]\n"
            "              [--vpd] DEVICE\n"
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
            "    --force|-f      skip VPD page 0 checking\n"
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
            "    --maxlen=LEN|-m LEN    same as '--len='\n"
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
            "'--page=PG' option. sg_vpd and\nsdparm decode more VPD pages "
            "than this utility.\n");
}

#ifdef SG_SCSI_STRINGS
static void
usage_old()
{
#ifdef SG_LIB_LINUX
    pr2serr("Usage:  sg_inq [-a] [-A] [-b] [-B=0|1] [-c] [-cl] [-d] [-e] "
            "[-h]\n"
            "               [-H] [-i] [I=FN] [-l=LEN] [-m] [-M] "
            "[-o=OPCODE_PG]\n"
            "               [-p=VPD_PG] [-P] [-r] [-s] [-u] [-U] [-v] [-V] "
            "[-x]\n"
            "               [-36] [-?] DEVICE\n"
            "  where:\n"
            "    -a    decode ATA information VPD page (0x89)\n"
            "    -A    treat <device> as (directly attached) ATA device\n");
#else
    pr2serr("Usage:  sg_inq [-a] [-b] [-B 0|1] [-c] [-cl] [-d] [-e] [-h] "
            "[-H]\n"
            "               [-i] [-l=LEN] [-m] [-M] [-o=OPCODE_PG] "
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
            "    -m    decode management network addresses VPD page "
            "(0x85)\n"
            "    -M    decode mode page policy VPD page (0x87)\n"
            "    -o=OPCODE_PG    opcode or page code in hex (def: 0)\n"
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
cl_new_process(struct opts_t * op, int argc, char * argv[])
{
    int c, n;

    while (1) {
        int option_index = 0;

#ifdef SG_LIB_LINUX
#ifdef SG_SCSI_STRINGS
        c = getopt_long(argc, argv, "aB:cdeEfhHiI:l:m:NOp:rsuvVx",
                        long_options, &option_index);
#else
        c = getopt_long(argc, argv, "B:cdeEfhHiI:l:m:p:rsuvVx", long_options,
                        &option_index);
#endif /* SG_SCSI_STRINGS */
#else  /* SG_LIB_LINUX */
#ifdef SG_SCSI_STRINGS
        c = getopt_long(argc, argv, "B:cdeEhHiI:l:m:NOp:rsuvVx", long_options,
                        &option_index);
#else
        c = getopt_long(argc, argv, "B:cdeEhHiI:l:m:p:rsuvVx", long_options,
                        &option_index);
#endif /* SG_SCSI_STRINGS */
#endif /* SG_LIB_LINUX */
        if (c == -1)
            break;

        switch (c) {
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
        case 'a':
            ++op->do_ata;
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
            ++op->do_descriptors;
            break;
        case 'e':
            ++op->do_vpd;
            break;
        case 'E':
        case 'x':
            ++op->do_decode;
            ++op->do_vpd;
            op->page_num = VPD_EXT_INQ;
            break;
        case 'f':
            ++op->do_force;
            break;
        case 'h':
            ++op->do_help;
            break;
        case '?':
            if (! op->do_help)
                ++op->do_help;
            break;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            ++op->do_decode;
            ++op->do_vpd;
            op->page_num = VPD_DEVICE_ID;
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
#ifdef SG_SCSI_STRINGS
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = 0;
            return 0;
#endif
        case 'p':
            op->page_arg = optarg;
            ++op->p_given;
            break;
        case 'r':
            ++op->do_raw;
            break;
        case 's':
            ++op->do_vendor;
            break;
        case 'u':
            ++op->do_export;
            break;
        case 'v':
            ++op->do_verbose;
            break;
        case 'V':
            ++op->do_version;
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
cl_old_process(struct opts_t * op, int argc, char * argv[])
{
    int k, jmp_out, plen, num, n;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case '3':
                    if ('6' == *(cp + 1)) {
                        op->resp_len = 36;
                        --plen;
                        ++cp;
                    } else
                        jmp_out = 1;
                    break;
                case 'a':
                    op->page_num = VPD_ATA_INFO;
                    ++op->do_vpd;
                    ++op->num_pages;
                    break;
#ifdef SG_LIB_LINUX
                case 'A':
                    ++op->do_ata;
                    break;
#endif
                case 'b':
                    op->page_num = VPD_BLOCK_LIMITS;
                    ++op->do_vpd;
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
                    ++op->do_descriptors;
                    ++op->do_decode;
                    break;
                case 'e':
                    ++op->do_vpd;
                    break;
                case 'f':
                    ++op->do_force;
                    break;
                case 'h':
                case 'H':
                    ++op->do_hex;
                    break;
                case 'i':
                    op->page_num = VPD_DEVICE_ID;
                    ++op->do_vpd;
                    ++op->num_pages;
                    break;
                case 'm':
                    op->page_num = VPD_MAN_NET_ADDR;
                    ++op->do_vpd;
                    ++op->num_pages;
                    break;
                case 'M':
                    op->page_num = VPD_MODE_PG_POLICY;
                    ++op->do_vpd;
                    ++op->num_pages;
                    break;
                case 'N':
                    op->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'P':
                    op->page_num = VPD_UPR_EMC;
                    ++op->do_vpd;
                    ++op->num_pages;
                    break;
                case 'r':
                    ++op->do_raw;
                    break;
                case 's':
                    op->page_num = VPD_SCSI_PORTS;
                    ++op->do_vpd;
                    ++op->num_pages;
                    break;
                case 'u':
                    ++op->do_export;
                    break;
                case 'v':
                    ++op->do_verbose;
                    break;
                case 'V':
                    ++op->do_version;
                    break;
                case 'x':
                    op->page_num = VPD_EXT_INQ;
                    ++op->do_vpd;
                    ++op->num_pages;
                    break;
                case '?':
                    if (! op->do_help)
                        ++op->do_help;
                    break;
                default:
                    jmp_out = 1;
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
            } else if (0 == strncmp("o=", cp, 2)) {
                op->page_arg = cp + 2;
                ++op->num_opcodes;
            } else if (0 == strncmp("p=", cp, 2)) {
                op->page_arg = cp + 2;
                ++op->p_given;
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
cl_process(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opt_new = 0;
        res = cl_old_process(op, argc, argv);
        if ((0 == res) && op->opt_new)
            res = cl_new_process(op, argc, argv);
    } else {
        op->opt_new = 1;
        res = cl_new_process(op, argc, argv);
        if ((0 == res) && (0 == op->opt_new))
            res = cl_old_process(op, argc, argv);
    }
    return res;
}

#else  /* SG_SCSI_STRINGS */

static int
cl_process(struct opts_t * op, int argc, char * argv[])
{
    return cl_new_process(op, argc, argv);
}

#endif  /* SG_SCSI_STRINGS */


/* Read ASCII hex bytes or binary from fname (a file named '-' taken as
 * stdin). If reading ASCII hex then there should be either one entry per
 * line or a comma, space or tab separated list of bytes. If no_space is
 * set then a string of ACSII hex digits is expected, 2 per byte. Everything
 * from and including a '#' on a line is ignored. Returns 0 if ok, or 1 if
 * error. */
static int
f2hex_arr(const char * fname, int as_binary, int no_space,
          unsigned char * mp_arr, int * mp_arr_len, int max_arr_len)
{
    int fn_len, in_len, k, j, m, split_line, fd;
    bool has_stdin;
    unsigned int h;
    const char * lcp;
    FILE * fp;
    char line[512];
    char carry_over[4];
    int off = 0;

    if ((NULL == fname) || (NULL == mp_arr) || (NULL == mp_arr_len))
        return 1;
    fn_len = strlen(fname);
    if (0 == fn_len)
        return 1;
    has_stdin = ((1 == fn_len) && ('-' == fname[0]));  /* read from stdin */
    if (as_binary) {
        if (has_stdin) {
            fd = STDIN_FILENO;
                if (sg_set_binary_mode(STDIN_FILENO) < 0)
                    perror("sg_set_binary_mode");
        } else {
            fd = open(fname, O_RDONLY);
            if (fd < 0) {
                pr2serr("unable to open binary file %s: %s\n", fname,
                         safe_strerror(errno));
                return 1;
            } else if (sg_set_binary_mode(fd) < 0)
                perror("sg_set_binary_mode");
        }
        k = read(fd, mp_arr, max_arr_len);
        if (k <= 0) {
            if (0 == k)
                pr2serr("read 0 bytes from binary file %s\n", fname);
            else
                pr2serr("read from binary file %s: %s\n", fname,
                        safe_strerror(errno));
            if (! has_stdin)
                close(fd);
            return 1;
        }
        *mp_arr_len = k;
        if (! has_stdin)
            close(fd);
        return 0;
    } else {    /* So read the file as ASCII hex */
        if (has_stdin)
            fp = stdin;
        else {
            fp = fopen(fname, "r");
            if (NULL == fp) {
                pr2serr("Unable to open %s for reading\n", fname);
                return 1;
            }
        }
    }

    carry_over[0] = 0;
    for (j = 0; j < 512; ++j) {
        if (NULL == fgets(line, sizeof(line), fp))
            break;
        in_len = strlen(line);
        if (in_len > 0) {
            if ('\n' == line[in_len - 1]) {
                --in_len;
                line[in_len] = '\0';
                split_line = 0;
            } else
                split_line = 1;
        }
        if (in_len < 1) {
            carry_over[0] = 0;
            continue;
        }
        if (carry_over[0]) {
            if (isxdigit(line[0])) {
                carry_over[1] = line[0];
                carry_over[2] = '\0';
                if (1 == sscanf(carry_over, "%x", &h))
                    mp_arr[off - 1] = h;       /* back up and overwrite */
                else {
                    pr2serr("%s: carry_over error ['%s'] around line %d\n",
                            __func__, carry_over, j + 1);
                    goto bad;
                }
                lcp = line + 1;
                --in_len;
            } else
                lcp = line;
            carry_over[0] = 0;
        } else
            lcp = line;

        m = strspn(lcp, " \t");
        if (m == in_len)
            continue;
        lcp += m;
        in_len -= m;
        if ('#' == *lcp)
            continue;
        k = strspn(lcp, "0123456789aAbBcCdDeEfF ,\t");
        if ((k < in_len) && ('#' != lcp[k]) && ('\r' != lcp[k])) {
            pr2serr("%s: syntax error at line %d, pos %d\n", __func__,
                    j + 1, m + k + 1);
            goto bad;
        }
        if (no_space) {
            for (k = 0; isxdigit(*lcp) && isxdigit(*(lcp + 1));
                 ++k, lcp += 2) {
                if (1 != sscanf(lcp, "%2x", &h)) {
                    pr2serr("%s: bad hex number in line %d, pos %d\n",
                            __func__, j + 1, (int)(lcp - line + 1));
                    goto bad;
                }
                if ((off + k) >= max_arr_len) {
                    pr2serr("%s: array length exceeded\n", __func__);
                    goto bad;
                }
                mp_arr[off + k] = h;
            }
            if (isxdigit(*lcp) && (! isxdigit(*(lcp + 1))))
                carry_over[0] = *lcp;
            off += k;
        } else {
            for (k = 0; k < 1024; ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        pr2serr("%s: hex number larger than 0xff in line %d, "
                                "pos %d\n", __func__, j + 1,
                                (int)(lcp - line + 1));
                        goto bad;
                    }
                    if (split_line && (1 == strlen(lcp))) {
                        /* single trailing hex digit might be a split pair */
                        carry_over[0] = *lcp;
                    }
                    if ((off + k) >= max_arr_len) {
                        pr2serr("%s: array length exceeded\n", __func__);
                        goto bad;
                    }
                    mp_arr[off + k] = h;
                    lcp = strpbrk(lcp, " ,\t");
                    if (NULL == lcp)
                        break;
                    lcp += strspn(lcp, " ,\t");
                    if ('\0' == *lcp)
                        break;
                } else {
                    if (('#' == *lcp) || ('\r' == *lcp)) {
                        --k;
                        break;
                    }
                    pr2serr("%s: error in line %d, at pos %d\n", __func__,
                            j + 1, (int)(lcp - line + 1));
                    goto bad;
                }
            }
            off += (k + 1);
        }
    }
    *mp_arr_len = off;
    if (stdin != fp)
        fclose(fp);
    return 0;
bad:
    if (stdin != fp)
        fclose(fp);
    return 1;
}


/* Local version of sg_ll_inquiry() [found in libsgutils] that additionally
 * passes back resid. Same return values as sg_ll_inquiry() (0 is good). */
static int
pt_inquiry(int sg_fd, int evpd, int pg_op, void * resp, int mx_resp_len,
           int * residp, int noisy, int verbose)
{
    int res, ret, k, sense_cat, resid;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    unsigned char * up;
    struct sg_pt_base * ptvp;

    if (evpd)
        inqCmdBlk[1] |= 1;
    inqCmdBlk[2] = (unsigned char)pg_op;
    /* 16 bit allocation length (was 8) is a recent SPC-3 addition */
    sg_put_unaligned_be16((uint16_t)mx_resp_len, inqCmdBlk + 3);
    if (verbose) {
        pr2serr("    inquiry cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            pr2serr("%02x ", inqCmdBlk[k]);
        pr2serr("\n");
    }
    if (resp && (mx_resp_len > 0)) {
        up = (unsigned char *)resp;
        up[0] = 0x7f;   /* defensive prefill */
        if (mx_resp_len > 4)
            up[4] = 0;
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("inquiry: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, inqCmdBlk, sizeof(inqCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "inquiry", res, mx_resp_len, sense_b,
                               noisy, verbose, &sense_cat);
    resid = get_scsi_pt_resid(ptvp);
    if (residp)
        *residp = resid;
    destruct_scsi_pt_obj(ptvp);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else if (ret < 4) {
        if (verbose)
            pr2serr("inquiry: got too few bytes (%d)\n", ret);
        ret = SG_LIB_CAT_MALFORMED;
    } else
        ret = 0;

    if (resid > 0) {
        if (resid > mx_resp_len) {
            pr2serr("INQUIRY resid (%d) should never exceed requested "
                    "len=%d\n", resid, mx_resp_len);
            return ret ? ret : SG_LIB_CAT_MALFORMED;
        }
        /* zero unfilled section of response buffer */
        memset((unsigned char *)resp + (mx_resp_len - resid), 0, resid);
    }
    return ret;
}

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
        if (vnp->name)
            printf("  %-10s 0x%02x      %s\n", vnp->acron, vnp->value,
                   vnp->name);
    }
}

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
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
encode_whitespaces(unsigned char *str, int inlen)
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
encode_unicode(unsigned char *str, int inlen)
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
encode_string(char *out, const unsigned char *in, int inlen)
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
    int vpd_name_arr_sz =
        (int)(sizeof(vpd_name_arr) / sizeof(vpd_name_arr[0]));

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
decode_supported_vpd(unsigned char * buff, int len, int do_hex)
{
    int vpd, k, rlen, pdt;
    const char * cp;

    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
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
vpd_page_is_supported(unsigned char * buff, int len, int pg)
{
    int vpd, k, rlen;
    bool supported = false;

    if (len < 4)
        return false;

    rlen = buff[3] + 4;
    if (rlen > len)
        pr2serr("Supported VPD pages VPD page truncated, indicates %d, got "
                "%d\n", rlen, len);
    else
        len = rlen;

    for (k = 0; k < len - 4; ++k) {
        vpd = buff[4 + k];
        if(vpd == pg) {
            supported = true;
            break;
        }
    }
    return supported;
}

/* ASCII Information VPD pages (page numbers: 0x1 to 0x7f) */
static void
decode_ascii_inf(unsigned char * buff, int len, int do_hex)
{
    int al, k, bump;
    unsigned char * bp;
    unsigned char * p;

    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
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
        p = (unsigned char *)memchr(bp, 0, al - k);
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
        dStrHex((const char *)bp, len - (al + 5), 0);
    }
}

static void
decode_id_vpd(unsigned char * buff, int len, int do_hex, int verbose)
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
decode_net_man_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump, na_len;
    unsigned char * bp;

    if (len < 4) {
        pr2serr("Management network addresses VPD page length too short=%d\n",
                len);
        return;
    }
    if (do_hex > 2) {
        dStrHex((const char *)buff, len, -1);
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
                dStrHex((const char *)(bp + 4), na_len, 0);
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
decode_mode_policy_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump;
    unsigned char * bp;

    if (len < 4) {
        pr2serr("Mode page policy VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex > 2) {
        dStrHex((const char *)buff, len, -1);
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
            dStrHex((const char *)bp, 4, (1 == do_hex) ? 1 : -1);
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
decode_scsi_ports_vpd(unsigned char * buff, int len, int do_hex, int verbose)
{
    int k, bump, rel_port, ip_tid_len, tpd_len;
    unsigned char * bp;

    if (len < 4) {
        pr2serr("SCSI Ports VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex > 2) {
        dStrHex((const char *)buff, len, -1);
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
                dStrHex((const char *)(bp + 8), ip_tid_len,
                        (1 == do_hex) ? 1 : -1);
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
                dStrHex((const char *)(bp + bump + 4), tpd_len,
                        (1 == do_hex) ? 1 : -1);
            else
                decode_dev_ids("SCSI Ports", bp + bump + 4, tpd_len,
                               do_hex, verbose);
        }
        bump += tpd_len + 4;
    }
}

/* These are target port, device server (i.e. target) and LU identifiers */
static void
decode_dev_ids(const char * leadin, unsigned char * buff, int len, int do_hex,
               int verbose)
{
    int u, j, m, id_len, p_id, c_set, piv, assoc, desig_type, i_len;
    int off, ci_off, c_id, d_id, naa, vsi, k;
    uint64_t vsei;
    uint64_t id_ext;
    const unsigned char * bp;
    const unsigned char * ip;
    char b[64];
    const char * cp;

    if (buff[2] != 0) {
        /*
         * Reference the 3rd byte of the first Identification descriptor
         * of a page 83 reply to determine whether the reply is compliant
         * with SCSI-2 or SPC-2/3 specifications.  A zero value in the
         * 3rd byte indicates an SPC-2/3 conformant reply ( the field is
         * reserved ).  This byte will be non-zero for a SCSI-2
         * conformant page 83 reply from these EMC Symmetrix models since
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
            dStrHex((const char *)ip, i_len, 0);
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
                dStrHex((const char *)ip, i_len, -1);
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
                dStrHexErr((const char *)ip, i_len, -1);
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
                dStrHexErr((const char *)ip, i_len, -1);
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
                dStrHexErr((const char *)ip, i_len, -1);
                break;
            }
            switch (naa) {
            case 2:     /* NAA 2: IEEE Extended */
                if (8 != i_len) {
                    pr2serr("      << unexpected NAA 2 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHexErr((const char *)ip, i_len, -1);
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
                    dStrHexErr((const char *)ip, i_len, -1);
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
                    dStrHexErr((const char *)ip, i_len, -1);
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
                    dStrHexErr((const char *)ip, i_len, 0);
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
                dStrHexErr((const char *)ip, i_len, -1);
                break;
            }
            break;
        case 4: /* Relative target port */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                pr2serr("      << expected binary code_set, target "
                        "port association, length 4>>\n");
                dStrHexErr((const char *)ip, i_len, -1);
                break;
            }
            d_id = sg_get_unaligned_be16(ip + 2);
            printf("      Relative target port: 0x%x\n", d_id);
            break;
        case 5: /* (primary) Target port group */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                pr2serr("      << expected binary code_set, target "
                        "port association, length 4>>\n");
                dStrHexErr((const char *)ip, i_len, -1);
                break;
            }
            d_id = sg_get_unaligned_be16(ip + 2);
            printf("      Target port group: 0x%x\n", d_id);
            break;
        case 6: /* Logical unit group */
            if ((1 != c_set) || (0 != assoc) || (4 != i_len)) {
                pr2serr("      << expected binary code_set, logical "
                        "unit association, length 4>>\n");
                dStrHexErr((const char *)ip, i_len, -1);
                break;
            }
            d_id = sg_get_unaligned_be16(ip + 2);
            printf("      Logical unit group: 0x%x\n", d_id);
            break;
        case 7: /* MD5 logical unit identifier */
            if ((1 != c_set) || (0 != assoc)) {
                pr2serr("      << expected binary code_set, logical "
                        "unit association>>\n");
                dStrHexErr((const char *)ip, i_len, -1);
                break;
            }
            printf("      MD5 logical unit identifier:\n");
            dStrHex((const char *)ip, i_len, -1);
            break;
        case 8: /* SCSI name string */
            if (3 != c_set) {
                if (2 == c_set) {
                    if (verbose)
                        pr2serr("      << expected UTF-8, use ASCII>>\n");
                } else {
                    pr2serr("      << expected UTF-8 code_set>>\n");
                    dStrHexErr((const char *)ip, i_len, -1);
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
        case 0xa: /* UUID identifier [spc5r08] */
            if (1 != c_set) {
                pr2serr("      << expected binary code_set >>\n");
                dStrHexErr((const char *)ip, i_len, 0);
                break;
            }
            if ((1 != ((ip[0] >> 4) & 0xf)) || (18 != i_len)) {
                pr2serr("      << expected locally assigned UUID, 16 bytes "
                        "long >>\n");
                dStrHexErr((const char *)ip, i_len, 0);
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
            dStrHexErr((const char *)ip, i_len, -1);
            break;
        }
    }
    if (-2 == u)
        pr2serr("%s VPD page error: around offset=%d\n", leadin, off);
}

static void
export_dev_ids(unsigned char * buff, int len, int verbose)
{
    int u, j, m, id_len, c_set, assoc, desig_type, i_len;
    int off, d_id, naa, k, p_id;
    unsigned char * bp;
    unsigned char * ip;
    const char * assoc_str;

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
                /* udev-conformant character encoding */
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
                /* udev-conformant character encoding */
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
                    dStrHexErr((const char *)ip, i_len, 0);
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
                    dStrHexErr((const char *)ip, i_len, 0);
                }
                break;
            }
            /*
             * Unfortunately, there are some (broken) implementations
             * which return _several_ NAA descriptors.
             * So add a suffix to differentiate between them.
             */
            naa = (ip[0] >> 4) & 0xff;
            if ((naa < 2) || (naa > 6) || (4 == naa)) {
                if (verbose) {
                    pr2serr("      << unexpected naa [0x%x]>>\n", naa);
                    dStrHexErr((const char *)ip, i_len, 0);
                }
                break;
            }
            if (6 != naa) {
                const char *suffix;

                if (8 != i_len) {
                    if (verbose) {
                        pr2serr("      << unexpected NAA %d identifier "
                                "length: 0x%x>>\n", naa, i_len);
                        dStrHexErr((const char *)ip, i_len, 0);
                    }
                    break;
                }
                if (naa != 2 && naa != 3 && naa != 5) {
                    if (verbose) {
                        pr2serr("      << unexpected NAA format %d>>\n", naa);
                        dStrHexErr((const char *)ip, i_len, 0);
                    }
                    break;
                }
                switch (naa) {
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
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            } else {      /* NAA IEEE Registered extended */
                if (16 != i_len) {
                    if (verbose) {
                        pr2serr("      << unexpected NAA 6 identifier "
                                "length: 0x%x>>\n", i_len);
                        dStrHexErr((const char *)ip, i_len, 0);
                    }
                    break;
                }
                printf("SCSI_IDENT_%s_NAA_REGEXT=", assoc_str);
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            }
            break;
        case 4: /* Relative target port */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                if (verbose) {
                    pr2serr("      << expected binary code_set, target "
                            "port association, length 4>>\n");
                    dStrHexErr((const char *)ip, i_len, 0);
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
                    dStrHexErr((const char *)ip, i_len, 0);
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
                    dStrHexErr((const char *)ip, i_len, 0);
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
                    dStrHexErr((const char *)ip, i_len, 0);
                }
                break;
            }
            printf("SCSI_IDENT_%s_MD5=", assoc_str);
            dStrHex((const char *)ip, i_len, -1);
            break;
        case 8: /* SCSI name string */
            if (3 != c_set) {
                if (verbose) {
                    pr2serr("      << expected UTF-8 code_set>>\n");
                    dStrHexErr((const char *)ip, i_len, -1);
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
                    dStrHexErr((const char *)ip, i_len, -1);
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
                        dStrHexErr((const char *)ip, i_len, 0);
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
                        dStrHexErr((const char *)ip, i_len, 0);
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
                    dStrHexErr((const char *)ip, i_len, 0);
                }
                break;
            }
            if (i_len < 18) {
                if (verbose) {
                    pr2serr("      << short UUID field expected 18 or more, "
                            "got %d >>\n", i_len);
                    dStrHexErr((const char *)ip, i_len, 0);
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
                dStrHexErr((const char *)ip, i_len, -1);
            }
            break;
        }
    }
    if (-2 == u && verbose)
        pr2serr("Device identification VPD page error: "
                "around offset=%d\n", off);
}

/* VPD_EXT_INQ   Extended Inquiry */
static void
decode_x_inq_vpd(unsigned char * buff, int len, int do_hex)
{
    if (len < 7) {
        pr2serr("Extended INQUIRY data VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
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
    /* LU_COLL_TYPE in spc5r09, CBCS obsolete in spc5r01 */
    printf("LU_COLL_TYPE=%d R_SUP=%d HSSRELEF=%d [CBCS=%d]\n",
           (buff[8] >> 5) & 0x7, !!(buff[8] & 0x10), !!(buff[8] & 0x2),
           !!(buff[8] & 0x1));
    printf("  Multi I_T nexus microcode download=%d\n", buff[9] & 0xf);
    printf("  Extended self-test completion minutes=%d\n",
           sg_get_unaligned_be16(buff + 10));     /* spc4r27 */
    printf("  POA_SUP=%d HRA_SUP=%d VSA_SUP=%d\n",      /* spc4r32 */
           !!(buff[12] & 0x80), !!(buff[12] & 0x40), !!(buff[12] & 0x20));
    printf("  Maximum supported sense data length=%d\n",
           buff[13]); /* spc4r34 */
    /* All byte 14 bits added in spc5r09 */
    printf("  IBS=%d IAS=%d SAC=%d NRD1=%d NRD0=%d\n",
           !!(buff[14] & 0x80), !!(buff[14] & 0x40), !!(buff[14] & 0x4),
           !!(buff[14] & 0x2), !!(buff[14] & 0x1));
}

/* VPD_SOFTW_INF_ID */
static void
decode_softw_inf_id(unsigned char * buff, int len, int do_hex)
{
    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    len -= 4;
    buff += 4;
    for ( ; len > 5; len -= 6, buff += 6)
        printf("    IEEE Company_id: 0x%06x, vendor specific extension "
               "id: 0x%06x\n", sg_get_unaligned_be24(buff + 0),
               sg_get_unaligned_be24(buff + 3));
}

/* VPD_ATA_INFO */
static void
decode_ata_info_vpd(unsigned char * buff, int len, int do_hex)
{
    char b[80];
    int is_be, num;

    if (len < 36) {
        pr2serr("ATA information VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex && (2 != do_hex)) {
        dStrHex((const char *)buff, len, (3 == do_hex) ? 0 : -1);
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
    dStrHex((const char *)buff + 36, 20, 1);
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
        dStrHex((const char *)(buff + 60), 512, 0);
    else
        dWordHex((const unsigned short *)(buff + 60), 256, 0,
                 sg_is_big_endian());
}

/* VPD_POWER_CONDITION */
static void
decode_power_condition(unsigned char * buff, int len, int do_hex)
{
    if (len < 18) {
        pr2serr("Power condition VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
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

/* VPD_BLOCK_LIMITS sbc */
/* Sequential access device characteristics,  ssc+smc */
/* OSD information, osd */
static void
decode_b0_vpd(unsigned char * buff, int len, int do_hex)
{
    int pdt;
    unsigned int u;

    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    pdt = 0x1f & buff[0];
    switch (pdt) {
        case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
            if (len < 16) {
                pr2serr("Block limits VPD page length too short=%d\n", len);
                return;
            }
            printf("  Maximum compare and write length: %u blocks\n",
                   buff[5]);
            u = sg_get_unaligned_be16(buff + 6);
            printf("  Optimal transfer length granularity: %u blocks\n", u);
            u = sg_get_unaligned_be32(buff + 8);
             printf("  Maximum transfer length: %u blocks\n", u);
            u = sg_get_unaligned_be32(buff + 12);
            printf("  Optimal transfer length: %u blocks\n", u);
            if (len > 19) {     /* added in sbc3r09 */
                u = sg_get_unaligned_be32(buff + 16);
                printf("  Maximum prefetch transfer length: %u blocks\n", u);
            }
            if (len > 27) {     /* added in sbc3r18 */
                u = sg_get_unaligned_be32(buff + 20);
                printf("  Maximum unmap LBA count: %u\n", u);
                u = sg_get_unaligned_be32(buff + 24);
                printf("  Maximum unmap block descriptor count: %u\n", u);
            }
            if (len > 35) {     /* added in sbc3r19 */
                u = sg_get_unaligned_be32(buff + 28);
                printf("  Optimal unmap granularity: %u\n", u);
                printf("  Unmap granularity alignment valid: %u\n",
                       !!(buff[32] & 0x80));
                u = 0x7fffffff & sg_get_unaligned_be32(buff + 32);
                printf("  Unmap granularity alignment: %u\n", u);
            }
            if (len > 43) {     /* added in sbc3r26 */
                printf("  Maximum write same length: 0x%" PRIx64 " blocks\n",
                       sg_get_unaligned_be64(buff + 36));
            }
            if (len > 44) {     /* added in sbc4r02 */
                u = sg_get_unaligned_be32(buff + 44);
                printf("  Maximum atomic transfer length: %u\n", u);
                u = sg_get_unaligned_be32(buff + 48);
                printf("  Atomic alignment: %u\n", u);
                u = sg_get_unaligned_be32(buff + 52);
                printf("  Atomic transfer length granularity: %u\n", u);
            }
            break;
        case PDT_TAPE: case PDT_MCHANGER:
            printf("  WORM=%d\n", !!(buff[4] & 0x1));
            break;
        case PDT_OSD:
        default:
            printf("  Unable to decode pdt=0x%x, in hex:\n", pdt);
            dStrHex((const char *)buff, len, 0);
            break;
    }
}

/* VPD_BLOCK_DEV_CHARS sbc */
/* VPD_MAN_ASS_SN ssc */
static void
decode_b1_vpd(unsigned char * buff, int len, int do_hex)
{
    int pdt;
    unsigned int u;

    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
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
            break;
        case PDT_TAPE: case PDT_MCHANGER: case PDT_ADC:
            printf("  Manufacturer-assigned serial number: %.*s\n",
                   len - 4, buff + 4);
            break;
        default:
            printf("  Unable to decode pdt=0x%x, in hex:\n", pdt);
            dStrHex((const char *)buff, len, 0);
            break;
    }
}

/* VPD_REFERRALS sbc */
static void
decode_b3_vpd(unsigned char * buff, int len, int do_hex)
{
    int pdt;
    unsigned int s, m;

    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
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
            dStrHex((const char *)buff, len, 0);
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
decode_upr_vpd_c0_emc(unsigned char * buff, int len, int do_hex)
{
    int k, ip_mgmt, vpp80, lun_z;

    if (len < 3) {
        pr2serr("EMC upr VPD page [0xc0]: length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 1 : -1);
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
decode_rdac_vpd_c2(unsigned char * buff, int len, int do_hex)
{
    if (len < 3) {
        pr2serr("Software Version VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 1 : -1);
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
decode_rdac_vpd_c9_rtpg_data(unsigned char aas, unsigned char vendor)
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
decode_rdac_vpd_c9(unsigned char * buff, int len, int do_hex)
{
    if (len < 3) {
        pr2serr("Volume Access Control VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 1 : -1);
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

static int
std_inq_response(const struct opts_t * op, int act_len)
{
    int len, pqual, peri_type, ansi_version, k, j;
    const char * cp;
    int vdesc_arr[8];
    char buff[48];
    const unsigned char * rp;

    rp = rsp_buff;
    memset(vdesc_arr, 0, sizeof(vdesc_arr));
    if (op->do_raw) {
        dStrRaw((const char *)rp, act_len);
        return 0;
    } else if (op->do_hex) {
        /* with -H, print with address, -HH without */
        dStrHex((const char *)rp, act_len, ((1 == op->do_hex) ? 0 : -1));
        return 0;
    }
    pqual = (rp[0] & 0xe0) >> 5;
    if (! op->do_raw && ! op->do_export) {
        if (0 == pqual)
            printf("standard INQUIRY:\n");
        else if (1 == pqual)
            printf("standard INQUIRY: [qualifier indicates no connected "
                   "LU]\n");
        else if (3 == pqual)
            printf("standard INQUIRY: [qualifier indicates not capable "
                   "of supporting LU]\n");
        else
            printf("standard INQUIRY: [reserved or vendor specific "
                   "qualifier [%d]]\n", pqual);
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
            len = encode_whitespaces((unsigned char *)xtra_buff, 8);
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
                len = encode_whitespaces((unsigned char *)xtra_buff, 16);
                if (len > 0) {
                    printf("SCSI_MODEL=%s\n", xtra_buff);
                    encode_string(xtra_buff, &rp[16], 16);
                    printf("SCSI_MODEL_ENC=%s\n", xtra_buff);
                }
            } else
                printf(" Product identification: %s\n", xtra_buff);
        }
        if (act_len <= 32) {
            if (!op->do_export)
                printf(" Product revision level: <none>\n");
        } else {
            memcpy(xtra_buff, &rp[32], 4);
            xtra_buff[4] = '\0';
            if (op->do_export) {
                len = encode_whitespaces((unsigned char *)xtra_buff, 4);
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
                len = encode_whitespaces((unsigned char *)xtra_buff, 20);
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
                len = encode_whitespaces((unsigned char *)xtra_buff,
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
    return 0;
}

/* When sg_fd >= 0 fetch VPD page from device; mxlen is command line
 * --maxlen=LEN option (def: 0) or -1 for a VPD page with a short length
 * (1 byte). When sg_fd < 0 then mxlen bytes have been read from
 * --inhex=FN file. Returns 0 for success. */
static int
vpd_fetch_page_from_dev(int sg_fd, unsigned char * rp, int page,
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
    res = pt_inquiry(sg_fd, 1, page, rp, n, &resid, 1, vb);
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
        res = pt_inquiry(sg_fd, 1, page, rp, len, &resid, 1, vb);
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
 * sg_ll_inquiry() return values */
static int
fetch_unit_serial_num(int sg_fd, char * obuff, int obuff_len, int verbose)
{
    int len, k, res;
    unsigned char b[DEF_ALLOC_LEN];

    memset(b, 0xff, 4); /* guard against empty response */
    res = vpd_fetch_page_from_dev(sg_fd, b, VPD_UNIT_SERIAL_NUM, -1, verbose,
                                  &len);
    if ((0 == res) && (len > 3)) {
        len -= 4;
        len = (len < (obuff_len - 1)) ? len : (obuff_len - 1);
        if (len > 0) {
            /* replace non-printable ASCII characters with space */
            for (k = 0; k < len; ++k)
                obuff[k] = isprint(b[4 + k]) ? b[4 + k] : ' ';
            obuff[len] = '\0';
            return 0;
        } else {
            if (verbose > 2)
                pr2serr("fetch_unit_serial_num: bad sn VPD page\n");
            return SG_LIB_CAT_MALFORMED;
        }
    } else {
        if (verbose > 2)
            pr2serr("fetch_unit_serial_num: no supported VPDs page\n");
        return SG_LIB_CAT_MALFORMED;
    }
    return res;
}


/* Process a standard INQUIRY response. Returns 0 if successful */
static int
std_inq_process(int sg_fd, const struct opts_t * op, int inhex_len)
{
    int res, len, rlen, act_len;
    char buff[48];
    int verb, resid;

    if (sg_fd < 0)
        return std_inq_response(op, inhex_len);
    rlen = (op->resp_len > 0) ? op->resp_len : SAFE_STD_INQ_RESP_LEN;
    verb = op->do_verbose;
    res = pt_inquiry(sg_fd, 0, 0, rsp_buff, rlen, &resid, 0, verb);
    if (0 == res) {
        len = rsp_buff[4] + 5;
        if ((len > SAFE_STD_INQ_RESP_LEN) && (len < 256) &&
            (0 == op->resp_len)) {
            rlen = len;
            memset(rsp_buff, 0, rlen);
            if (pt_inquiry(sg_fd, 0, 0, rsp_buff, rlen, &resid, 1, verb)) {
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
        if ((! op->do_export) && (0 == op->resp_len)) {
            if (fetch_unit_serial_num(sg_fd, usn_buff, sizeof(usn_buff),
                                      op->do_verbose))
                usn_buff[0] = '\0';
        }
        return std_inq_response(op, act_len);
    } else if (res < 0) { /* could be an ATA device */
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
        /* Try an ATA Identify Device command */
        res = try_ata_identify(sg_fd, op->do_hex, op->do_raw,
                               op->do_verbose);
        if (0 != res) {
            pr2serr("Both SCSI INQUIRY and fetching ATA information "
                    "failed on %s\n", op->device_name);
            return SG_LIB_CAT_OTHER;
        }
#else
        pr2serr("SCSI INQUIRY failed on %s, res=%d\n",
                op->device_name, res);
        return res;
#endif
    } else {
        char b[80];

        pr2serr("    inquiry: failed requesting %d byte response: ", rlen);
        if (resid && verb)
            snprintf(buff, sizeof(buff), " [resid=%d]", resid);
        else
            buff[0] = '\0';
        sg_get_category_sense_str(res, sizeof(b), b, verb);
        pr2serr("%s%s\n", b, buff);
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

    memset(rsp_buff, 0, DEF_ALLOC_LEN);
    if (op->do_cmddt > 1) {
        printf("Supported command list:\n");
        for (k = 0; k < 256; ++k) {
            res = sg_ll_inquiry(sg_fd, 1, 0, k, rsp_buff, DEF_ALLOC_LEN,
                                1, op->do_verbose);
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
                    sg_get_opcode_name((unsigned char)k, peri_type,
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
        res = sg_ll_inquiry(sg_fd, 1, 0, op->page_num, rsp_buff,
                            DEF_ALLOC_LEN, 1, op->do_verbose);
        if (0 == res) {
            peri_type = rsp_buff[0] & 0x1f;
            if (! op->do_raw) {
                printf("CmdDt INQUIRY, opcode=0x%.2x:  [", op->page_num);
                sg_get_opcode_name((unsigned char)op->page_num, peri_type,
                                   sizeof(op_name) - 1, op_name);
                op_name[sizeof(op_name) - 1] = '\0';
                printf("%s]\n", op_name);
            }
            len = rsp_buff[5] + 6;
            reserved_cmddt = rsp_buff[4];
            if (op->do_hex)
                dStrHex((const char *)rsp_buff, len,
                        (1 == op->do_hex) ? 0 : -1);
            else if (op->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else {
                const char * desc_p;
                int prnt_cmd = 0;

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
                        prnt_cmd = 1;
                        break;
                case 4: desc_p = "vendor specific (4)"; break;
                case 5: desc_p = "supported in vendor specific way";
                        prnt_cmd = 1;
                        break;
                case 6: desc_p = "vendor specific (6)"; break;
                case 7: desc_p = "reserved (7)"; break;
                default: desc_p = "impossible value > 7"; break;
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
                sg_get_opcode_name((unsigned char)op->page_num, 0,
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
    unsigned char * rp;

    rp = rsp_buff;
    if ((! op->do_raw) && (op->do_hex < 2))
        printf("VPD INQUIRY, page code=0x%.2x:\n", op->page_num);
    if (sg_fd < 0) {
        len = sg_get_unaligned_be16(rp + 2) + 4;
        if (op->do_verbose && (len > inhex_len))
            pr2serr("warning: VPD page's length (%d) > bytes in --inhex=FN "
                    "file (%d)\n",  len , inhex_len);
        res = 0;
    } else {
        memset(rp, 0, DEF_ALLOC_LEN);
        res = vpd_fetch_page_from_dev(sg_fd, rp, op->page_num, op->resp_len,
                                      op->do_verbose, &len);
    }
    if (0 == res) {
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else {
            if (0 == op->page_num)
                decode_supported_vpd(rp, len, op->do_hex);
            else {
                if (op->do_verbose) {
                    cp = sg_get_pdt_str(rp[0] & 0x1f, sizeof(b), b);
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5, cp);
                }
                dStrHex((const char *)rp, len, ((1 == op->do_hex) ? 0 : -1));
            }
        }
    } else {
        if (SG_LIB_CAT_ILLEGAL_REQ == res)
            pr2serr("    inquiry: field in cdb illegal (page not "
                    "supported)\n");
        else {
            sg_get_category_sense_str(res, sizeof(b), b, op->do_verbose);
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
    unsigned char * rp;

    pn = op->page_num;
    rp = rsp_buff;
    vb = op->do_verbose;
    if (sg_fd >= 0)
        mxlen = op->resp_len;
    else
        mxlen = inhex_len;
    if (sg_fd != -1 && !op->do_force && pn != VPD_SUPPORTED_VPDS) {
        res = vpd_fetch_page_from_dev(sg_fd, rp, VPD_SUPPORTED_VPDS, mxlen,
                                      vb, &len);
        if (res)
            goto out;
        if (!vpd_page_is_supported(rp, len, pn)) {
            res = SG_LIB_CAT_ILLEGAL_REQ;
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
            dStrHex((const char *)rp, len,
                    (1 == op->do_hex) ? 0 : -1);
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
            dStrHex((const char *)rp, len,
                    (1 == op->do_hex) ? 0 : -1);
        else {
            char obuff[DEF_ALLOC_LEN];
            int k, m;

            memset(obuff, 0, sizeof(obuff));
            len -= 4;
            if (len >= (int)sizeof(obuff))
                len = sizeof(obuff) - 1;
            memcpy(obuff, rp + 4, len);
            if (op->do_export) {
                k = encode_whitespaces((unsigned char *)obuff, len);
                if (k > 0) {
                    printf("SCSI_IDENT_SERIAL=");
                    /* udev-conformant character encoding */
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
                k = encode_unicode((unsigned char *)obuff, len);
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
            dStrHex((const char *)rp, len, -1);
        else if (op->do_export)
            export_dev_ids(rp + 4, len - 4, op->do_verbose);
        else
            decode_id_vpd(rp, len, op->do_hex, op->do_verbose);
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
            pr2serr(" Only hex output supported. sg_vpd decodes the B2h "
                    "page.\n");
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
            decode_scsi_ports_vpd(rp, len, op->do_hex, op->do_verbose);
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
                pr2serr(" Only hex output supported. sg_vpd and sdparm "
                        "decode more VPD pages.\n");
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


int
main(int argc, char * argv[])
{
    int sg_fd, res, n;
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
    res = cl_process(op, argc, argv);
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
    if (op->do_version) {
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }
    if (op->page_arg) {
        if (op->page_num >= 0) {
            pr2serr("Given '-p' option and another option that "
                    "implies a page\n");
            return SG_LIB_SYNTAX_ERROR;
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
                ++op->do_decode;
            op->page_num = vnp->value;
            op->page_pdt = vnp->pdt;
        } else if ('-' == op->page_arg[0]) {
            op->page_num = -2;  /* request standard INQUIRY response */
        } else {
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
                    ++op->do_decode;
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
                ++op->do_decode;
#endif /* SG_SCSI_STRINGS */
            op->page_num = n;
        }
    }
    if (op->inhex_fn) {
        if (op->device_name) {
            pr2serr("Cannot have both a DEVICE and --inhex= option\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (op->do_cmddt) {
            pr2serr("Don't support --cmddt with --inhex= option\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (f2hex_arr(op->inhex_fn, op->do_raw, 0, rsp_buff, &inhex_len,
                      sizeof(rsp_buff)))
            return SG_LIB_FILE_ERROR;
        op->do_raw = 0;         /* don't want raw on output with --inhex= */
        if (-1 == op->page_num) {       /* may be able to deduce VPD page */
            if (op->page_pdt < 0)
                op->page_pdt = 0x1f & rsp_buff[0];
            if ((0x2 == (0xf & rsp_buff[3])) && (rsp_buff[2] > 2)) {
                if (op->do_verbose)
                    pr2serr("Guessing from --inhex= this is a standard "
                            "INQUIRY\n");
            } else if (rsp_buff[2] <= 2) {
                if (op->do_verbose)
                    pr2serr("Guessing from --inhex this is VPD page 0x%x\n",
                            rsp_buff[1]);
                op->page_num = rsp_buff[1];
                ++op->do_vpd;
                if ((1 != op->do_hex) && (0 == op->do_raw))
                    ++op->do_decode;
            } else {
                if (op->do_verbose)
                    pr2serr("page number unclear from --inhex, hope it's a "
                            "standard INQUIRY\n");
            }
        }
    } else if (0 == op->device_name) {
        pr2serr("No DEVICE argument given\n");
        usage_for(op);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (-2 == op->page_num) /* from --page=-<num> to force standard INQUIRY */
        op->page_num = -1;  /* now past guessing, set to normal indication */

    if (op->do_export) {
        if (op->page_num != -1) {
            if (op->page_num != VPD_DEVICE_ID &&
                op->page_num != VPD_UNIT_SERIAL_NUM) {
                pr2serr("Option '--export' only supported "
                        "for VPD pages 0x80 and 0x83\n");
                usage_for(op);
                return SG_LIB_SYNTAX_ERROR;
            }
            ++op->do_decode;
            ++op->do_vpd;
        }
    }

    if ((0 == op->do_cmddt) && (op->page_num >= 0) && op->p_given)
        ++op->do_vpd;

    if (op->do_raw && op->do_hex) {
        pr2serr("Can't do hex and raw at the same time\n");
        usage_for(op);
        return SG_LIB_SYNTAX_ERROR;
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
        return SG_LIB_SYNTAX_ERROR;
    }
    if (((op->do_vpd || op->do_cmddt)) && (op->page_num < 0))
        op->page_num = 0;
    if (op->num_pages > 1) {
        pr2serr("Can only fetch one page (VPD or Cmd) at a time\n");
        usage_for(op);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->do_descriptors) {
        if ((op->resp_len > 0) && (op->resp_len < 60)) {
            pr2serr("version descriptors need INQUIRY response "
                    "length >= 60 bytes\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (op->do_vpd || op->do_cmddt) {
            pr2serr("version descriptors require standard INQUIRY\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (op->num_pages && op->do_ata) {
        pr2serr("Can't use '-A' with an explicit decode VPD page option\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }
    if (op->inhex_fn) {
        if (op->do_vpd) {
            if (op->do_decode)
                return vpd_decode(-1, op, inhex_len);
            else
                return vpd_mainly_hex(-1, op, inhex_len);
        } else
            return std_inq_process(-1, op, inhex_len);
    }

#if defined(O_NONBLOCK) && defined(O_RDONLY)
    if (op->do_block >= 0) {
        n = O_RDONLY | (op->do_block ? 0 : O_NONBLOCK);
        if ((sg_fd = sg_cmds_open_flags(op->device_name, n,
                                        op->do_verbose)) < 0) {
            pr2serr("sg_inq: error opening file: %s: %s\n",
                    op->device_name, safe_strerror(-sg_fd));
            return SG_LIB_FILE_ERROR;
        }

    } else {
        if ((sg_fd = sg_cmds_open_device(op->device_name, 1 /* ro */,
                                         op->do_verbose)) < 0) {
            pr2serr("sg_inq: error opening file: %s: %s\n",
                    op->device_name, safe_strerror(-sg_fd));
            return SG_LIB_FILE_ERROR;
        }
    }
#else
    if ((sg_fd = sg_cmds_open_device(op->device_name, 1 /* ro */,
                                     op->do_verbose)) < 0) {
        pr2serr("sg_inq: error opening file: %s: %s\n",
                op->device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
#endif
    memset(rsp_buff, 0, sizeof(rsp_buff));

#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
    if (op->do_ata) {
        res = try_ata_identify(sg_fd, op->do_hex, op->do_raw,
                               op->do_verbose);
        if (0 != res) {
            pr2serr("fetching ATA information failed on %s\n",
                    op->device_name);
            ret = SG_LIB_CAT_OTHER;
        } else
            ret = 0;
        goto err_out;
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

err_out:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}


#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
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
  unsigned char  serial_no[20];
  unsigned short words020_022[3];
  unsigned char  fw_rev[8];
  unsigned char  model[40];
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
ata_command_interface(int device, char *data, int * atapi_flag, int verbose)
{
    unsigned char buff[ATA_IDENTIFY_BUFF_SZ + HDIO_DRIVE_CMD_OFFSET];
    unsigned short get_ident[256];

    if (atapi_flag)
        *atapi_flag = 0;
    memset(buff, 0, sizeof(buff));
    if (ioctl(device, HDIO_GET_IDENTITY, &get_ident) < 0) {
        if (ENOTTY == errno) {
            if (verbose > 1)
                pr2serr("HDIO_GET_IDENTITY failed with ENOTTY, "
                        "try HDIO_DRIVE_CMD ioctl ...\n");
            buff[0] = ATA_IDENTIFY_DEVICE;
            buff[3] = 1;
            if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
                if (verbose)
                    pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                            "ioctl failed:\n\t%s [%d]\n",
                            safe_strerror(errno), errno);
                return errno;
            }
            memcpy(data, buff + HDIO_DRIVE_CMD_OFFSET, ATA_IDENTIFY_BUFF_SZ);
            return 0;
        } else {
            if (verbose)
                pr2serr("HDIO_GET_IDENTITY ioctl failed:\n"
                        "\t%s [%d]\n", safe_strerror(errno), errno);
            return errno;
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
            if (verbose)
                pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_PACKET_DEVICE) "
                        "ioctl failed:\n\t%s [%d]\n", safe_strerror(errno),
                        errno);
            buff[0] = ATA_IDENTIFY_DEVICE;
            buff[3] = 1;
            if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
                if (verbose)
                    pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                            "ioctl failed:\n\t%s [%d]\n", safe_strerror(errno),
                            errno);
                return errno;
            }
        } else if (atapi_flag) {
            *atapi_flag = 1;
            if (verbose > 1)
                pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) succeeded\n");
        }
    } else {    /* assume non-packet device */
        buff[0] = ATA_IDENTIFY_DEVICE;
        buff[3] = 1;
        if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
            if (verbose)
                pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) ioctl failed:"
                        "\n\t%s [%d]\n", safe_strerror(errno), errno);
            return errno;
        } else if (verbose > 1)
            pr2serr("HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) succeeded\n");
    }
    /* if the command returns data, copy it back */
    memcpy(data, buff + HDIO_DRIVE_CMD_OFFSET, ATA_IDENTIFY_BUFF_SZ);
    return 0;
}

/* Returns 0 if successful, else errno of error */
static int
try_ata_identify(int ata_fd, int do_hex, int do_raw, int verbose)
{
    struct ata_identify_device ata_ident;
    char model[64];
    char serial[64];
    char firm[64];
    int res, atapi;

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
                dStrHex((const char *)&ata_ident, 512, 0);
            } else {
                printf("(256 words):\n");
                dWordHex((const unsigned short *)&ata_ident, 256, 0,
                         sg_is_big_endian());
            }
        } else {
            printf("%s device: model, serial number and firmware revision:\n",
                   (atapi ? "ATAPI" : "ATA"));
            res = sg_ata_get_chars((const unsigned short *)ata_ident.model,
                                   0, 20, sg_is_big_endian(), model);
            model[res] = '\0';
            res = sg_ata_get_chars((const unsigned short *)ata_ident.serial_no,
                                   0, 10, sg_is_big_endian(), serial);
            serial[res] = '\0';
            res = sg_ata_get_chars((const unsigned short *)ata_ident.fw_rev,
                                   0, 4, sg_is_big_endian(), firm);
            firm[res] = '\0';
            printf("  %s %s %s\n", model, serial, firm);
            if (verbose) {
                if (atapi)
                    printf("ATA IDENTIFY PACKET DEVICE response "
                           "(256 words):\n");
                else
                    printf("ATA IDENTIFY DEVICE response (256 words):\n");
                dWordHex((const unsigned short *)&ata_ident, 256, 0,
                         sg_is_big_endian());
            }
        }
    }
    return 0;
}
#endif

/* If this structure is changed then the structure of the same name in
 * sg_inq_data,c should also be changed
 */
struct sg_version_descriptor {
    int value;
    const char * name;
};

extern struct sg_version_descriptor sg_version_descriptor_arr[];


static const char *
find_version_descriptor_str(int value)
{
    int k;
    const struct sg_version_descriptor * vdp;

    for (k = 0; ((vdp = sg_version_descriptor_arr + k) && vdp->name); ++k) {
        if (value == vdp->value)
            return vdp->name;
        if (value < vdp->value)
            break;
    }
    return NULL;
}

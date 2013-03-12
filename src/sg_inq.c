/* A utility program originally written for the Linux OS SCSI subsystem.
*  Copyright (C) 2000-2013 D. Gilbert
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
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef SG_LIB_LINUX
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/hdreg.h>
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"

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

static char * version_str = "1.12 20130312";    /* SPC-4 rev 36 */


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

static const char * find_version_descriptor_str(int value);
static void decode_dev_ids(const char * leadin, unsigned char * buff,
                           int len, int do_hex);
static void decode_transport_id(const char * leadin, unsigned char * ucp,
                                int len);

#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
static int try_ata_identify(int ata_fd, int do_hex, int do_raw,
                            int do_verbose);
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
        {"ata", 0, 0, 'a'},
#endif
        {"cmddt", 0, 0, 'c'},
        {"descriptors", 0, 0, 'd'},
        {"export", 0, 0, 'u'},
        {"extended", 0, 0, 'x'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"id", 0, 0, 'i'},
        {"len", 1, 0, 'l'},
        {"maxlen", 1, 0, 'm'},
#ifdef SG_SCSI_STRINGS
        {"new", 0, 0, 'N'},
        {"old", 0, 0, 'O'},
#endif
        {"page", 1, 0, 'p'},
        {"raw", 0, 0, 'r'},
        {"vendor", 0, 0, 's'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {"vpd", 0, 0, 'e'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_ata;
    int do_cmddt;
    int do_descriptors;
    int do_export;
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
    int num_pages;
    int num_opcodes;
    int p_given;
    const char * page_arg;
    const char * device_name;
#ifdef SG_SCSI_STRINGS
    int opt_new;
#endif
};

static void
usage()
{
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
    fprintf(stderr,
            "Usage: sg_inq [--ata] [--cmddt] [--descriptors] [--export] "
            "[--extended]\n"
            "              [--help] [--hex] [--id] [--len=LEN] "
            "[--maxlen=LEN]\n"
            "              [--page=PG] [--raw] [--vendor] [--verbose] "
            "[--version]\n"
            "              [--vpd] DEVICE\n"
            "  where:\n"
            "    --ata|-a        treat DEVICE as (directly attached) ATA "
            "device\n");
#else
    fprintf(stderr,
            "Usage: sg_inq [--cmddt] [--descriptors] [--export] [--extended] "
            "[--help]\n"
            "              [--hex] [--id] [--len=LEN] [--maxlen=LEN] "
            "[--page=PG]\n"
            "              [--raw] [--verbose] [--version] [--vpd] DEVICE\n"
            "  where:\n");
#endif
    fprintf(stderr,
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
            "    --help|-h       print usage message then exit\n"
            "    --hex|-H        output response in hex\n"
            "    --id|-i         decode device identification VPD page "
            "(0x83)\n"
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
            "Performs a SCSI INQUIRY command. "
            "If no options given then does a\n'standard' INQUIRY. Can list "
            "VPD pages with '--vpd' or '--page=PG'\noption. The sg_vpd "
            "utility has a more up to date list of VPD pages.\n");
}

#ifdef SG_SCSI_STRINGS
static void
usage_old()
{
#ifdef SG_LIB_LINUX
    fprintf(stderr,
            "Usage:  sg_inq [-a] [-A] [-b] [-c] [-cl] [-d] [-e] [-h] [-H] "
            "[-i]\n"
            "               [-l=LEN] [-m] [-M] [-o=OPCODE_PG] "
            "[-p=VPD_PG]\n"
            "               [-P] [-r] [-s] [-v] [-V] [-x] [-36] [-?] "
            "DEVICE\n"
            "  where:\n"
            "    -a    decode ATA information VPD page (0x89)\n"
            "    -A    treat <device> as (directly attached) ATA device\n");
#else
    fprintf(stderr,
            "Usage:  sg_inq [-a] [-b] [-c] [-cl] [-d] [-e] [-h] [-H] "
            "[-i]\n"
            "               [-l=LEN] [-m] [-M] [-o=OPCODE_PG] "
            "[-p=VPD_PG]\n"
            "               [-P] [-r] [-s] [-v] [-V] [-x] [-36] [-?] "
            "DEVICE\n"
            "  where:\n"
            "    -a    decode ATA information VPD page (0x89)\n");

#endif  /* SG_LIB_LINUX */
    fprintf(stderr,
            "    -b    decode Block limits VPD page (0xb0) (SBC)\n"
            "    -c    set CmdDt mode (use -o for opcode) [obsolete]\n"
            "    -cl   list supported commands using CmdDt mode [obsolete]\n"
            "    -d    decode: version descriptors or VPD page\n"
            "    -e    set VPD mode (use -p for page code)\n"
            "    -h    output in hex (ASCII to the right)\n"
            "    -H    output in hex (ASCII to the right) [same as '-h']\n"
            "    -i    decode device identification VPD page (0x83)\n"
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
            "    -v    verbose (output cdb and, if non-zero, resid)\n"
            "    -V    output version string\n"
            "    -x    decode extended INQUIRY data VPD page (0x86)\n"
            "    -36   perform standard INQUIRY with a 36 byte response\n"
            "    -?    output this usage message\n\n"
            "If no options given then does a standard SCSI INQUIRY\n");
}

static void
usage_for(const struct opts_t * optsp)
{
    if (optsp->opt_new)
        usage();
    else
        usage_old();
}

#else  /* SG_SCSI_STRINGS */

static void
usage_for(const struct opts_t * optsp)
{
    optsp = optsp;
    usage();
}

#endif /* SG_SCSI_STRINGS */

/* Processes command line options according to new option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
process_cl_new(struct opts_t * optsp, int argc, char * argv[])
{
    int c, n;

    while (1) {
        int option_index = 0;

#ifdef SG_LIB_LINUX
#ifdef SG_SCSI_STRINGS
        c = getopt_long(argc, argv, "acdeEhHil:m:NOp:rsuvVx", long_options,
                        &option_index);
#else
        c = getopt_long(argc, argv, "cdeEhHil:m:p:rsuvVx", long_options,
                        &option_index);
#endif /* SG_SCSI_STRINGS */
#else  /* SG_LIB_LINUX */
#ifdef SG_SCSI_STRINGS
        c = getopt_long(argc, argv, "cdeEhHil:m:NOp:rsuvVx", long_options,
                        &option_index);
#else
        c = getopt_long(argc, argv, "cdeEhHil:m:p:rsuvVx", long_options,
                        &option_index);
#endif /* SG_SCSI_STRINGS */
#endif /* SG_LIB_LINUX */
        if (c == -1)
            break;

        switch (c) {
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
        case 'a':
            ++optsp->do_ata;
            break;
#endif
        case 'c':
            ++optsp->do_cmddt;
            break;
        case 'd':
            ++optsp->do_descriptors;
            break;
        case 'e':
            ++optsp->do_vpd;
            break;
        case 'E':
        case 'x':
            ++optsp->do_decode;
            ++optsp->do_vpd;
            optsp->page_num = VPD_EXT_INQ;
            break;
        case 'h':
            ++optsp->do_help;
            break;
        case '?':
            if (! optsp->do_help)
                ++optsp->do_help;
            break;
        case 'H':
            ++optsp->do_hex;
            break;
        case 'i':
            ++optsp->do_decode;
            ++optsp->do_vpd;
            optsp->page_num = VPD_DEVICE_ID;
            break;
        case 'l':
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 65532)) {
                fprintf(stderr, "bad argument to '--len='\n");
                usage_for(optsp);
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->resp_len = n;
#ifdef SG_SCSI_STRINGS
        case 'N':
            break;      /* ignore */
        case 'O':
            optsp->opt_new = 0;
            return 0;
#endif
        case 'p':
            optsp->page_arg = optarg;
            ++optsp->p_given;
            break;
        case 'r':
            ++optsp->do_raw;
            break;
        case 's':
            ++optsp->do_vendor;
            break;
        case 'u':
            ++optsp->do_export;
            break;
        case 'v':
            ++optsp->do_verbose;
            break;
        case 'V':
            ++optsp->do_version;
            break;
        default:
            fprintf(stderr, "unrecognised option code %c [0x%x]\n", c, c);
            if (optsp->do_help)
                break;
            usage_for(optsp);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == optsp->device_name) {
            optsp->device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage_for(optsp);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

#ifdef SG_SCSI_STRINGS
/* Processes command line options according to old option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
process_cl_old(struct opts_t * optsp, int argc, char * argv[])
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
                        optsp->resp_len = 36;
                        --plen;
                        ++cp;
                    } else
                        jmp_out = 1;
                    break;
                case 'a':
                    optsp->page_num = VPD_ATA_INFO;
                    ++optsp->do_vpd;
                    ++optsp->num_pages;
                    break;
#ifdef SG_LIB_LINUX
                case 'A':
                    ++optsp->do_ata;
                    break;
#endif
                case 'b':
                    optsp->page_num = VPD_BLOCK_LIMITS;
                    ++optsp->do_vpd;
                    ++optsp->num_pages;
                    break;
                case 'c':
                    ++optsp->do_cmddt;
                    if ('l' == *(cp + 1)) {
                        ++optsp->do_cmddt;
                        --plen;
                        ++cp;
                    }
                    break;
                case 'd':
                    ++optsp->do_descriptors;
                    ++optsp->do_decode;
                    break;
                case 'e':
                    ++optsp->do_vpd;
                    break;
                case 'h':
                case 'H':
                    ++optsp->do_hex;
                    break;
                case 'i':
                    optsp->page_num = VPD_DEVICE_ID;
                    ++optsp->do_vpd;
                    ++optsp->num_pages;
                    break;
                case 'm':
                    optsp->page_num = VPD_MAN_NET_ADDR;
                    ++optsp->do_vpd;
                    ++optsp->num_pages;
                    break;
                case 'M':
                    optsp->page_num = VPD_MODE_PG_POLICY;
                    ++optsp->do_vpd;
                    ++optsp->num_pages;
                    break;
                case 'N':
                    optsp->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'P':
                    optsp->page_num = VPD_UPR_EMC;
                    ++optsp->do_vpd;
                    ++optsp->num_pages;
                    break;
                case 'r':
                    ++optsp->do_raw;
                    break;
                case 's':
                    optsp->page_num = VPD_SCSI_PORTS;
                    ++optsp->do_vpd;
                    ++optsp->num_pages;
                    break;
                case 'u':
                    ++optsp->do_export;
                    break;
                case 'v':
                    ++optsp->do_verbose;
                    break;
                case 'V':
                    ++optsp->do_version;
                    break;
                case 'x':
                    optsp->page_num = VPD_EXT_INQ;
                    ++optsp->do_vpd;
                    ++optsp->num_pages;
                    break;
                case '?':
                    if (! optsp->do_help)
                        ++optsp->do_help;
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
            else if (0 == strncmp("l=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n < 1)) {
                    fprintf(stderr, "Inappropriate value after 'l=' "
                            "option\n");
                    usage_for(optsp);
                    return SG_LIB_SYNTAX_ERROR;
                } else if (n > MX_ALLOC_LEN) {
                    fprintf(stderr, "value after 'l=' "
                            "option too large\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->resp_len = n;
            } else if (0 == strncmp("o=", cp, 2)) {
                optsp->page_arg = cp + 2;
                ++optsp->num_opcodes;
            } else if (0 == strncmp("p=", cp, 2)) {
                optsp->page_arg = cp + 2;
                ++optsp->p_given;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage_for(optsp);
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == optsp->device_name)
            optsp->device_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", optsp->device_name, cp);
            usage_for(optsp);
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
process_cl(struct opts_t * optsp, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        optsp->opt_new = 0;
        res = process_cl_old(optsp, argc, argv);
        if ((0 == res) && optsp->opt_new)
            res = process_cl_new(optsp, argc, argv);
    } else {
        optsp->opt_new = 1;
        res = process_cl_new(optsp, argc, argv);
        if ((0 == res) && (0 == optsp->opt_new))
            res = process_cl_old(optsp, argc, argv);
    }
    return res;
}

#else  /* SG_SCSI_STRINGS */

static int
process_cl(struct opts_t * optsp, int argc, char * argv[])
{
    return process_cl_new(optsp, argc, argv);
}

#endif  /* SG_SCSI_STRINGS */


/* Local version of sg_ll_inquiry() [found in libsgutils] that additionally
 * passes back resid. Same return values as sg_ll_inquiry() (0 is good). */
static int
ll_inquiry(int sg_fd, int cmddt, int evpd, int pg_op, void * resp,
           int mx_resp_len, int * residp, int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    unsigned char * up;
    struct sg_pt_base * ptvp;

    if (cmddt)
        inqCmdBlk[1] |= 2;
    if (evpd)
        inqCmdBlk[1] |= 1;
    inqCmdBlk[2] = (unsigned char)pg_op;
    /* 16 bit allocation length (was 8) is a recent SPC-3 addition */
    inqCmdBlk[3] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    inqCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
    if (verbose) {
        fprintf(stderr, "    inquiry cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            fprintf(stderr, "%02x ", inqCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    if (resp && (mx_resp_len > 0)) {
        up = (unsigned char *)resp;
        up[0] = 0x7f;   /* defensive prefill */
        if (mx_resp_len > 4)
            up[4] = 0;
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(stderr, "inquiry: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, inqCmdBlk, sizeof(inqCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "inquiry", res, mx_resp_len, sense_b,
                               noisy, verbose, &sense_cat);
    if (residp)
        *residp = get_scsi_pt_resid(ptvp);
    destruct_scsi_pt_obj(ptvp);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else if (ret < 4) {
        if (verbose)
            fprintf(stderr, "inquiry: got too few bytes (%d)\n", ret);
        ret = SG_LIB_CAT_MALFORMED;
    } else
        ret = 0;

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
 * length of the output, excluding the trailing '\0'.
 */
static int
encode_whitespaces(unsigned char *str, int inlen)
{
    int k, res;
    int j = 0;
    int valid = 0;
    int outlen = inlen;

    /* Skip initial whitespaces */
    while (isblank(str[j]))
        j++;
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
                valid++;
            }
        } else if (! isprint(str[k]))
            str[res++] = '.';
        else {
            str[res++] = str[k];
            valid++;
        }
    }
    if (! valid)
        res = 0;
    str[res] = '\0';
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
    char * name;
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
        /* peripheral device type relevent for 0xb0..0xbf range */
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
decode_id_vpd(unsigned char * buff, int len, int do_hex)
{
    if (len < 4) {
        fprintf(stderr, "Device identification VPD page length too "
                "short=%d\n", len);
        return;
    }
    decode_dev_ids("Device identification", buff + 4, len - 4, do_hex);
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
    "administrative configuration service",
    "[0x7]", "[0x8]", "[0x9]", "[0xa]", "[0xb]", "[0xc]", "[0xd]",
    "[0xe]", "[0xf]", "[0x10]", "[0x11]", "[0x12]", "[0x13]", "[0x14]",
    "[0x15]", "[0x16]", "[0x17]", "[0x18]", "[0x19]", "[0x1a]",
    "[0x1b]", "[0x1c]", "[0x1d]", "[0x1e]", "[0x1f]",
};

/* VPD_MAN_NET_ADDR */
static void
decode_net_man_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump, na_len;
    unsigned char * ucp;

    if (len < 4) {
        fprintf(stderr, "Management network addresses VPD page length too "
                "short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        printf("  %s, Service type: %s\n",
               assoc_arr[(ucp[0] >> 5) & 0x3],
               network_service_type_arr[ucp[0] & 0x1f]);
        na_len = (ucp[2] << 8) + ucp[3];
        bump = 4 + na_len;
        if ((k + bump) > len) {
            fprintf(stderr, "Management network addresses VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (na_len > 0) {
            if (do_hex) {
                printf("    Network address:\n");
                dStrHex((const char *)(ucp + 4), na_len, 0);
            } else
                printf("    %s\n", ucp + 4);
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
    unsigned char * ucp;

    if (len < 4) {
        fprintf(stderr, "Mode page policy VPD page length too short=%d\n",
                len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            fprintf(stderr, "Mode page policy VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (do_hex)
            dStrHex((const char *)ucp, 4, 1);
        else {
            printf("  Policy page code: 0x%x", (ucp[0] & 0x3f));
            if (ucp[1])
                printf(",  subpage code: 0x%x\n", ucp[1]);
            else
                printf("\n");
            printf("    MLUS=%d,  Policy: %s\n", !!(ucp[2] & 0x80),
                   mode_page_policy_arr[ucp[2] & 0x3]);
        }
    }
}

/* VPD_SCSI_PORTS */
static void
decode_scsi_ports_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump, rel_port, ip_tid_len, tpd_len;
    unsigned char * ucp;

    if (len < 4) {
        fprintf(stderr, "SCSI Ports VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        rel_port = (ucp[2] << 8) + ucp[3];
        printf("Relative port=%d\n", rel_port);
        ip_tid_len = (ucp[6] << 8) + ucp[7];
        bump = 8 + ip_tid_len;
        if ((k + bump) > len) {
            fprintf(stderr, "SCSI Ports VPD page, short descriptor "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (ip_tid_len > 0) {
            if (do_hex) {
                printf(" Initiator port transport id:\n");
                dStrHex((const char *)(ucp + 8), ip_tid_len, 1);
            } else
                decode_transport_id(" ", ucp + 8, ip_tid_len);
        }
        tpd_len = (ucp[bump + 2] << 8) + ucp[bump + 3];
        if ((k + bump + tpd_len + 4) > len) {
            fprintf(stderr, "SCSI Ports VPD page, short descriptor(tgt) "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (tpd_len > 0) {
            printf(" Target port descriptor(s):\n");
            if (do_hex)
                dStrHex((const char *)(ucp + bump + 4), tpd_len, 1);
            else
                decode_dev_ids("SCSI Ports", ucp + bump + 4, tpd_len,
                               do_hex);
        }
        bump += tpd_len + 4;
    }
}

static const char * code_set_arr[] =
{
    "Reserved [0x0]",
    "Binary",
    "ASCII",
    "UTF-8",
    "[0x4]", "[0x5]", "[0x6]", "[0x7]", "[0x8]", "[0x9]", "[0xa]", "[0xb]",
    "[0xc]", "[0xd]", "[0xe]", "[0xf]",
};

static const char * desig_type_arr[] =
{
    "vendor specific [0x0]", /* SCSI_IDENT_DEVICE_VENDOR */
    "T10 vendor identification", /* SCSI_IDENT_DEVICE_T10 */
    "EUI-64 based", /* SCSI_IDENT_DEVICE_EUI64 */
    "NAA", /* SCSI_IDENT_DEVICE_NAA */
    "Relative target port", /* SCSI_IDENT_PORT_RELATIVE */
    "Target port group", /* SCSI_IDENT_PORT_TP_GROUP */
    "Logical unit group", /* SCSI_IDENT_PORT_LU_GROUP */
    "MD5 logical unit identifier", /* SCSI_IDENT_DEVICE_MD5 */
    "SCSI name string", /* SCSI_IDENT_DEVICE_SCSINAME */
    "Protocol specific port identifier",        /* spc4r36 */
    "[0xa]", "[0xb]", "[0xc]", "[0xd]", "[0xe]", "[0xf]",
};

/* These are target port, device server (i.e. target) and LU identifiers */
static void
decode_dev_ids(const char * leadin, unsigned char * buff, int len, int do_hex)
{
    int u, j, m, id_len, p_id, c_set, piv, assoc, desig_type, i_len;
    int off, ci_off, c_id, d_id, naa, vsi, k;
    uint64_t vsei;
    uint64_t id_ext;
    const unsigned char * ucp;
    const unsigned char * ip;
    char b[64];

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
        ip = ucp = buff;
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
        ucp = buff + off;
        i_len = ucp[3];
        id_len = i_len + 4;
        printf("  Designation descriptor number %d, "
               "descriptor length: %d\n", j, id_len);
        if ((off + id_len) > len) {
            fprintf(stderr, "%s VPD page error: designator length longer "
                    "than\n     remaining response length=%d\n", leadin,
                    (len - off));
            return;
        }
        ip = ucp + 4;
        p_id = ((ucp[0] >> 4) & 0xf);   /* protocol identifier */
        c_set = (ucp[0] & 0xf);         /* code set */
        piv = ((ucp[1] & 0x80) ? 1 : 0); /* protocol identifier valid */
        assoc = ((ucp[1] >> 4) & 0x3);
        desig_type = (ucp[1] & 0xf);
  decode:
        if (piv && ((1 == assoc) || (2 == assoc)))
            printf("    transport: %s\n",
                   sg_get_trans_proto_str(p_id, sizeof(b), b));
        printf("    designator_type: %s,  code_set: %s\n",
               desig_type_arr[desig_type], code_set_arr[c_set]);
        printf("    associated with the %s\n", assoc_arr[assoc]);
        if (do_hex) {
            printf("    designator header(hex): %.2x %.2x %.2x %.2x\n",
                   ucp[0], ucp[1], ucp[2], ucp[3]);
            printf("    designator:\n");
            dStrHex((const char *)ip, i_len, 0);
            continue;
        }
        switch (desig_type) {
        case 0: /* vendor specific */
            k = 0;
            if ((1 == c_set) || (2 == c_set)) { /* ASCII or UTF-8 */
                for (k = 0; (k < i_len) && isprint(ip[k]); ++k)
                    ;
                if (k >= i_len)
                    k = 1;
            }
            if (k)
                printf("      vendor specific: %.*s\n", i_len, ip);
            else
                dStrHex((const char *)ip, i_len, -1);
            break;
        case 1: /* T10 vendor identification */
            printf("      vendor id: %.8s\n", ip);
            if (i_len > 8)
                printf("      vendor specific: %.*s\n", i_len - 8, ip + 8);
            break;
        case 2: /* EUI-64 based */
            printf("      EUI-64 based %d byte identifier\n", i_len);
            if (1 != c_set) {
                fprintf(stderr, "      << expected binary code_set (1)>>\n");
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            ci_off = 0;
            if (16 == i_len) {
                ci_off = 8;
                id_ext = 0;
                for (m = 0; m < 8; ++m) {
                    if (m > 0)
                        id_ext <<= 8;
                    id_ext |= ip[m];
                }
                printf("      Identifier extension: 0x%" PRIx64 "\n", id_ext);
            } else if ((8 != i_len) && (12 != i_len)) {
                fprintf(stderr, "      << can only decode 8, 12 and 16 "
                        "byte ids>>\n");
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            c_id = ((ip[ci_off] << 16) | (ip[ci_off + 1] << 8) |
                    ip[ci_off + 2]);
            printf("      IEEE Company_id: 0x%x\n", c_id);
            vsei = 0;
            for (m = 0; m < 5; ++m) {
                if (m > 0)
                    vsei <<= 8;
                vsei |= ip[ci_off + 3 + m];
            }
            printf("      Vendor Specific Extension Identifier: 0x%" PRIx64
                   "\n", vsei);
            if (12 == i_len) {
                d_id = ((ip[8] << 24) | (ip[9] << 16) | (ip[10] << 8) |
                        ip[11]);
                printf("      Directory ID: 0x%x\n", d_id);
            }
            printf("      [0x");
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("]\n");
            break;
        case 3: /* NAA */
            if (1 != c_set) {
                fprintf(stderr, "      << expected binary code_set (1)>>\n");
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            naa = (ip[0] >> 4) & 0xff;
            if ((naa < 2) || (naa > 6) || (4 == naa)) {
                fprintf(stderr, "      << unexpected naa [0x%x]>>\n", naa);
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            if (2 == naa) {             /* NAA IEEE Extended */
                if (8 != i_len) {
                    fprintf(stderr, "      << unexpected NAA 2 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, -1);
                    break;
                }
                d_id = (((ip[0] & 0xf) << 8) | ip[1]);
                c_id = ((ip[2] << 16) | (ip[3] << 8) | ip[4]);
                vsi = ((ip[5] << 16) | (ip[6] << 8) | ip[7]);
                printf("      NAA 2, vendor specific identifier A: 0x%x\n",
                       d_id);
                printf("      IEEE Company_id: 0x%x\n", c_id);
                printf("      vendor specific identifier B: 0x%x\n", vsi);
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            } else if (3 == naa) {      /* NAA Locally assigned */
                if (8 != i_len) {
                    fprintf(stderr, "      << unexpected NAA 3 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, -1);
                    break;
                }
                printf("      NAA 3, Locally assigned:\n");
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            } else if (5 == naa) {      /* NAA IEEE Registered */
                if (8 != i_len) {
                    fprintf(stderr, "      << unexpected NAA 5 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, -1);
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
            } else if (6 == naa) {      /* NAA IEEE Registered extended */
                if (16 != i_len) {
                    fprintf(stderr, "      << unexpected NAA 6 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, 0);
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
                vsei = 0;
                for (m = 0; m < 8; ++m) {
                    if (m > 0)
                        vsei <<= 8;
                    vsei |= ip[8 + m];
                }
                printf("      Vendor Specific Identifier Extension: "
                       "0x%" PRIx64 "\n", vsei);
                printf("      [0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            }
            break;
        case 4: /* Relative target port */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                fprintf(stderr, "      << expected binary code_set, target "
                        "port association, length 4>>\n");
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            d_id = ((ip[2] << 8) | ip[3]);
            printf("      Relative target port: 0x%x\n", d_id);
            break;
        case 5: /* (primary) Target port group */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                fprintf(stderr, "      << expected binary code_set, target "
                        "port association, length 4>>\n");
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            d_id = ((ip[2] << 8) | ip[3]);
            printf("      Target port group: 0x%x\n", d_id);
            break;
        case 6: /* Logical unit group */
            if ((1 != c_set) || (0 != assoc) || (4 != i_len)) {
                fprintf(stderr, "      << expected binary code_set, logical "
                        "unit association, length 4>>\n");
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            d_id = ((ip[2] << 8) | ip[3]);
            printf("      Logical unit group: 0x%x\n", d_id);
            break;
        case 7: /* MD5 logical unit identifier */
            if ((1 != c_set) || (0 != assoc)) {
                fprintf(stderr, "      << expected binary code_set, logical "
                        "unit association>>\n");
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            printf("      MD5 logical unit identifier:\n");
            dStrHex((const char *)ip, i_len, -1);
            break;
        case 8: /* SCSI name string */
            if (3 != c_set) {
                fprintf(stderr, "      << expected UTF-8 code_set>>\n");
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            printf("      SCSI name string:\n");
            /* does %s print out UTF-8 ok??
             * Seems to depend on the locale. Looks ok here with my
             * locale setting: en_AU.UTF-8
             */
            printf("      %s\n", (const char *)ip);
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
        default: /* reserved */
            dStrHex((const char *)ip, i_len, -1);
            break;
        }
    }
    if (-2 == u)
        fprintf(stderr, "%s VPD page error: around offset=%d\n", leadin, off);
}

static void
export_dev_ids(unsigned char * buff, int len)
{
    int u, j, m, id_len, c_set, assoc, desig_type, i_len;
    int off, d_id, naa, k;
    unsigned char * ucp;
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
        desig_type = 3;
        j = 1;
        off = 16;
        goto decode;
    }

    for (j = 1, off = -1;
         (u = sg_vpd_dev_id_iter(buff, len, &off, -1, -1, -1)) == 0;
         ++j) {
        ucp = buff + off;
        i_len = ucp[3];
        id_len = i_len + 4;
        if ((off + id_len) > len) {
            fprintf(stderr, "Device Identification VPD page error: designator "
                    "length longer than\n     remaining response length=%d\n",
                    (len - off));
            return;
        }
        ip = ucp + 4;
        c_set = (ucp[0] & 0xf);
        assoc = ((ucp[1] >> 4) & 0x3);
        desig_type = (ucp[1] & 0xf);
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
                fprintf(stderr, "    Invalid association %d\n", assoc);
                return;
        }
        switch (desig_type) {
        case 0: /* vendor specific */
            k = 0;
            if ((1 == c_set) || (2 == c_set)) { /* ASCII or UTF-8 */
                k = encode_whitespaces(ip, i_len);
                if (k >= i_len)
                    k = 1;
            }
            if (k)
                printf("SCSI_IDENT_%s_VENDOR=%.*s\n", assoc_str, k, ip);
            break;
        case 1: /* T10 vendor identification */
            k = encode_whitespaces(ip, i_len);
            printf("SCSI_IDENT_%s_T10=%.*s\n", assoc_str, k, ip);
            break;
        case 2: /* EUI-64 based */
            if (1 != c_set) {
                fprintf(stderr, "      << expected binary code_set (1)>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            printf("SCSI_IDENT_%s_EUI64=", assoc_str);
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        case 3: /* NAA */
            if (1 != c_set) {
                fprintf(stderr, "      << expected binary code_set (1)>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            naa = (ip[0] >> 4) & 0xff;
            if ((naa < 2) || (naa > 6) || (4 == naa)) {
                fprintf(stderr, "      << unexpected naa [0x%x]>>\n", naa);
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            if (6 != naa) {
                if (8 != i_len) {
                    fprintf(stderr, "      << unexpected NAA 2 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, 0);
                    break;
                }
                printf("SCSI_IDENT_%s_NAA=", assoc_str);
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            } else {      /* NAA IEEE Registered extended */
                if (16 != i_len) {
                    fprintf(stderr, "      << unexpected NAA 6 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHex((const char *)ip, i_len, 0);
                    break;
                }
                printf("SCSI_IDENT_%s_NAA=", assoc_str);
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            }
            break;
        case 4: /* Relative target port */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                fprintf(stderr, "      << expected binary code_set, target "
                        "port association, length 4>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            d_id = ((ip[2] << 8) | ip[3]);
            printf("SCSI_IDENT_%s_RELATIVE=%d\n", assoc_str, d_id);
            break;
        case 5: /* (primary) Target port group */
            if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
                fprintf(stderr, "      << expected binary code_set, target "
                        "port association, length 4>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            d_id = ((ip[2] << 8) | ip[3]);
            printf("SCSI_IDENT_%s_TARGET_PORT_GROUP=0x%x\n", assoc_str, d_id);
            break;
        case 6: /* Logical unit group */
            if ((1 != c_set) || (0 != assoc) || (4 != i_len)) {
                fprintf(stderr, "      << expected binary code_set, logical "
                        "unit association, length 4>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            d_id = ((ip[2] << 8) | ip[3]);
            printf("SCSI_IDENT_%s_LOGICAL_UNIT_GROUP=0x%x\n", assoc_str, d_id);
            break;
        case 7: /* MD5 logical unit identifier */
            if ((1 != c_set) || (0 != assoc)) {
                fprintf(stderr, "      << expected binary code_set, logical "
                        "unit association>>\n");
                dStrHex((const char *)ip, i_len, 0);
                break;
            }
            printf("SCSI_IDENT_%s_MD5=", assoc_str);
            dStrHex((const char *)ip, i_len, -1);
            break;
        case 8: /* SCSI name string */
            if (3 != c_set) {
                fprintf(stderr, "      << expected UTF-8 code_set>>\n");
                dStrHex((const char *)ip, i_len, -1);
                break;
            }
            printf("SCSI_IDENT_%s_NAME=%.*s\n", assoc_str, i_len,
                   (const char *)ip);
            break;
        case 9: /* PCIe Routing ID */
            /* new in spc4r34, looks under-specified, drop through now */
        default: /* reserved */
            dStrHex((const char *)ip, i_len, -1);
            break;
        }
    }
    if (-2 == u)
        fprintf(stderr, "Device identification VPD page error: "
                "around offset=%d\n", off);
}

/* Transport IDs are initiator port identifiers, typically other than the
   initiator port issuing a SCSI command. */
static void
decode_transport_id(const char * leadin, unsigned char * ucp, int len)
{
    int format_code, proto_id, num, j, k;
    uint64_t ull;
    int bump;

    for (k = 0, bump = 24; k < len; k += bump, ucp += bump) {
        if ((len < 24) || (0 != (len % 4)))
            printf("%sTransport Id short or not multiple of 4 "
                   "[length=%d]:\n", leadin, len);
        else
            printf("%sTransport Id of initiator:\n", leadin);
        format_code = ((ucp[0] >> 6) & 0x3);
        proto_id = (ucp[0] & 0xf);
        switch (proto_id) {
        case TPROTO_FCP:
            printf("%s  FCP-2 World Wide Name:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, -1);
            bump = 24;
            break;
        case TPROTO_SPI:
            printf("%s  Parallel SCSI initiator SCSI address: 0x%x\n",
                   leadin, ((ucp[2] << 8) | ucp[3]));
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            printf("%s  relative port number (of corresponding target): "
                   "0x%x\n", leadin, ((ucp[6] << 8) | ucp[7]));
            bump = 24;
            break;
        case TPROTO_SSA: /* SSA */
            printf("%s  SSA (transport id not defined):\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), -1);
            bump = 24;
            break;
        case TPROTO_1394:
            printf("%s  IEEE 1394 EUI-64 name:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, -1);
            bump = 24;
            break;
        case TPROTO_SRP:
            printf("%s  RDMA initiator port identifier:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 16, -1);
            bump = 24;
            break;
        case TPROTO_ISCSI:
            printf("%s  iSCSI ", leadin);
            num = ((ucp[2] << 8) | ucp[3]);
            if (0 == format_code)
                printf("name: %.*s\n", num, &ucp[4]);
            else if (1 == format_code)
                printf("world wide unique port id: %.*s\n", num, &ucp[4]);
            else {
                printf("  [Unexpected format code: %d]\n", format_code);
                dStrHex((const char *)ucp, num + 4, -1);
            }
            bump = (((num + 4) < 24) ? 24 : num + 4);
            break;
        case TPROTO_SAS:
            ull = 0;
            for (j = 0; j < 8; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= ucp[4 + j];
            }
            printf("%s  SAS address: 0x%" PRIx64 "\n", leadin, ull);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            bump = 24;
            break;
        case TPROTO_ADT:
            printf("%s  ADT:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), -1);
            bump = 24;
            break;
        case TPROTO_ATA:
            printf("%s  ATAPI:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), -1);
            bump = 24;
            break;
        case TPROTO_UAS:
            printf("%s  UAS:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), -1);
            bump = 24;
            break;
        case TPROTO_SOP:
            printf("%s  SOP ", leadin);
            num = ((ucp[2] << 8) | ucp[3]);
            if (0 == format_code)
                printf("Routing ID: 0x%x\n", num);
            else {
                printf("  [Unexpected format code: %d]\n", format_code);
                dStrHex((const char *)ucp, 24, -1);
            }
            bump = 24;
            break;
        case TPROTO_NONE:
            fprintf(stderr, "%s  No specified protocol\n", leadin);
            /* dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0); */
            bump = 24;
            break;
        default:
            fprintf(stderr, "%s  unknown protocol id=0x%x  "
                    "format_code=%d\n", leadin, proto_id, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        }
    }
}

/* VPD_EXT_INQ   Extended Inquiry */
static void
decode_x_inq_vpd(unsigned char * buff, int len, int do_hex)
{
    if (len < 7) {
        fprintf(stderr, "Extended INQUIRY data VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    printf("  SPT=%d GRD_CHK=%d APP_CHK=%d REF_CHK=%d\n",
           ((buff[4] >> 3) & 0x7), !!(buff[4] & 0x4), !!(buff[4] & 0x2),
           !!(buff[4] & 0x1));
    printf("  UASK_SUP=%d GROUP_SUP=%d PRIOR_SUP=%d HEADSUP=%d ORDSUP=%d "
           "SIMPSUP=%d\n", !!(buff[5] & 0x20), !!(buff[5] & 0x10),
           !!(buff[5] & 0x8), !!(buff[5] & 0x4), !!(buff[5] & 0x2),
           !!(buff[5] & 0x1));
    printf("  WU_SUP=%d CRD_SUP=%d NV_SUP=%d V_SUP=%d\n",
           !!(buff[6] & 0x8), !!(buff[6] & 0x4), !!(buff[6] & 0x2),
           !!(buff[6] & 0x1));
    printf("  P_I_I_SUP=%d LUICLR=%d CBCS=%d R_SUP=%d\n",
           !!(buff[7] & 0x10), !!(buff[7] & 0x1), !!(buff[8] & 0x1),
           !!(buff[8] & 0x10));
    printf("  Multi I_T nexus microcode download=%d\n", buff[9] & 0xf);
    printf("  Extended self-test completion minutes=%d\n",
           (buff[10] << 8) + buff[11]);     /* spc4r27 */
    printf("  POA_SUP=%d HRA_SUP=%d VSA_SUP=%d\n",      /* spc4r32 */
           !!(buff[12] & 0x80), !!(buff[12] & 0x40), !!(buff[12] & 0x20));
    printf("  Maximum supported sense data length=%d\n",
           buff[13]); /* spc4r34 */
}

/* VPD_SOFTW_INF_ID */
static void
decode_softw_inf_id(unsigned char * buff, int len, int do_hex)
{
    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    len -= 4;
    buff += 4;
    for ( ; len > 5; len -= 6, buff += 6)
        printf("    IEEE Company_id: 0x%06x, vendor specific extension "
               "id: 0x%06x\n", (buff[0] << 16) | (buff[1] << 8) | buff[2],
               (buff[3] << 16) | (buff[4] << 8) | buff[5]);
}

/* VPD_ATA_INFO */
static void
decode_ata_info_vpd(unsigned char * buff, int len, int do_hex)
{
    char b[80];
    int is_be, num;

    if (len < 36) {
        fprintf(stderr, "ATA information VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (do_hex && (2 != do_hex)) {
        dStrHex((const char *)buff, len, 0);
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
        fprintf(stderr, "Power condition VPD page length too short=%d\n",
                len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    printf("  Standby_y=%d Standby_z=%d Idle_c=%d Idle_b=%d Idle_a=%d\n",
           !!(buff[4] & 0x2), !!(buff[4] & 0x1),
           !!(buff[5] & 0x4), !!(buff[5] & 0x2), !!(buff[5] & 0x1));
    printf("  Stopped condition recovery time (ms) %d\n",
            (buff[6] << 8) + buff[7]);
    printf("  Standby_z condition recovery time (ms) %d\n",
            (buff[8] << 8) + buff[9]);
    printf("  Standby_y condition recovery time (ms) %d\n",
            (buff[10] << 8) + buff[11]);
    printf("  Idle_a condition recovery time (ms) %d\n",
            (buff[12] << 8) + buff[13]);
    printf("  Idle_b condition recovery time (ms) %d\n",
            (buff[14] << 8) + buff[15]);
    printf("  Idle_c condition recovery time (ms) %d\n",
            (buff[16] << 8) + buff[17]);
}

static void
decode_b0_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    unsigned int u;

    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    switch (pdt) {
        case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
            if (len < 16) {
                fprintf(stderr, "Block limits VPD page length too "
                        "short=%d\n", len);
                return;
            }
            printf("  Maximum compare and write length: %u blocks\n",
                   buff[5]);
            u = (buff[6] << 8) | buff[7];
            printf("  Optimal transfer length granularity: %u blocks\n", u);
            u = (buff[8] << 24) | (buff[9] << 16) | (buff[10] << 8) |
                buff[11];
             printf("  Maximum transfer length: %u blocks\n", u);
            u = (buff[12] << 24) | (buff[13] << 16) | (buff[14] << 8) |
                buff[15];
            printf("  Optimal transfer length: %u blocks\n", u);
            if (len > 19) {     /* added in sbc3r09 */
                u = (buff[16] << 24) | (buff[17] << 16) | (buff[18] << 8) |
                    buff[19];
                printf("  Maximum prefetch, xdread, xdwrite transfer length: "
                       "%u blocks\n", u);
            }
            if (len > 27) {     /* added in sbc3r18 */
                u = ((unsigned int)buff[20] << 24) | (buff[21] << 16) |
                    (buff[22] << 8) | buff[23];
                printf("  Maximum unmap LBA count: %u\n", u);
                u = ((unsigned int)buff[24] << 24) | (buff[25] << 16) |
                    (buff[26] << 8) | buff[27];
                printf("  Maximum unmap block descriptor count: %u\n", u);
            }
            if (len > 35) {     /* added in sbc3r19 */
                u = ((unsigned int)buff[28] << 24) | (buff[29] << 16) |
                    (buff[30] << 8) | buff[31];
                printf("  Optimal unmap granularity: %u\n", u);
                printf("  Unmap granularity alignment valid: %u\n",
                       !!(buff[32] & 0x80));
                u = ((unsigned int)(buff[32] & 0x7f) << 24) |
                    (buff[33] << 16) | (buff[34] << 8) | buff[35];
                printf("  Unmap granularity alignment: %u\n", u);
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
decode_b1_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    unsigned int u;

    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    switch (pdt) {
        case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
            if (len < 64) {
                fprintf(stderr, "Block device characteristics VPD page length "
                        "too short=%d\n", len);
                return;
            }
            u = (buff[4] << 8) | buff[5];
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
decode_b3_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    unsigned int s, m;

    if (do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    switch (pdt) {
        case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
            if (len < 0xc0) {
                fprintf(stderr, "Referrals VPD page length too short=%d\n",
                        len);
                return;
            }
            s = (buff[8] << 24) | (buff[9] << 16) | (buff[10] << 8) | buff[11];
            m = (buff[12] << 24) | (buff[13] << 16) | (buff[14] << 8) |
                buff[15];
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
decode_upr_vpd_c0_emc(unsigned char * buff, int len)
{
    int k, ip_mgmt, vpp80, lun_z;

    if (len < 3) {
        fprintf(stderr, "EMC upr VPD page [0xc0]: length too short=%d\n",
                len);
        return;
    }
    if (buff[9] != 0x00) {
        fprintf(stderr, "Unsupported page revision %d, decoding not "
                "possible.\n" , buff[9]);
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
decode_rdac_vpd_c2(unsigned char * buff, int len)
{
    if (len < 3) {
        fprintf(stderr, "Software Version VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[4] != 's' && buff[5] != 'w' && buff[6] != 'r') {
        fprintf(stderr, "Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    printf("  Software Version: %d.%d.%d\n", buff[8], buff[9], buff[10]);
    printf("  Software Date: %02x/%02x/%02x\n", buff[11], buff[12], buff[13]);
    printf("  Features:");
    if (buff[14] & 0x01)
        printf(" Dual Active,");
    if (buff[14] & 0x02)
        printf(" Series 3,");
    if (buff[14] & 0x04)
        printf(" Multiple Sub-enclosures,");
    if (buff[14] & 0x08)
        printf(" DCE/DRM,");
    if (buff[14] & 0x10)
        printf(" AVT,");
    printf("\n");
    printf("  Max. #of LUNS: %d\n", buff[15]);
    return;
}

static void
decode_rdac_vpd_c9(unsigned char * buff, int len)
{
    if (len < 3) {
        fprintf(stderr, "Volume Access Control VPD page length too "
                "short=%d\n", len);
        return;
    }
    if (buff[4] != 'v' && buff[5] != 'a' && buff[6] != 'c') {
        fprintf(stderr, "Invalid page identifier %c%c%c%c, decoding "
                "not possible.\n" , buff[4], buff[5], buff[6], buff[7]);
        return;
    }
    if (buff[7] != '1') {
        fprintf(stderr, "Invalid page version '%c' (should be 1)\n",
                buff[7]);
    }
    printf("  AVT:");
    if (buff[8] & 0x80) {
        printf(" Enabled");
        if (buff[8] & 0x40)
            printf(" (Allow reads on sector 0)");
        printf("\n");
    } else {
        printf(" Disabled\n");
    }
    printf("  Volume Access via: ");
    if (buff[8] & 0x01)
        printf("primary controller\n");
    else
        printf("alternate controller\n");

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

    return;
}

/* Returns 0 if Unit Serial Number VPD page contents found, else see
   sg_ll_inquiry() return values */
static int
fetch_unit_serial_num(int sg_fd, char * obuff, int obuff_len, int verbose)
{
    int sz, len, k, res;
    unsigned char b[DEF_ALLOC_LEN];

    res = 0;
    sz = sizeof(b);
    memset(b, 0xff, 4); /* guard against empty response */
    /* first check if unit serial number VPD page is supported */
    res = sg_ll_inquiry(sg_fd, 0, 1, VPD_SUPPORTED_VPDS, b, sz, 0, verbose);
    if (0 == res) {
        if ((VPD_SUPPORTED_VPDS != b[1]) || (0x0 != b[2])) {
            if (verbose > 2)
                fprintf(stderr, "fetch_unit_serial_num: bad supported VPDs "
                        "page\n");
            return SG_LIB_CAT_MALFORMED;
        }
        len = (b[2] << 8) + b[3];       /* spc4r25 */
        for (k = 0; k < len; ++k) {
            if (VPD_UNIT_SERIAL_NUM == b[k + 4])
                break;
        }
        if (k < len) {
            res = sg_ll_inquiry(sg_fd, 0, 1, VPD_UNIT_SERIAL_NUM,
                                b, sz, 0, verbose);
            if (0 == res) {
                len = (b[2] << 8) + b[3];       /* spc4r25 */
                len = (len < (obuff_len - 1)) ? len : (obuff_len - 1);
                if ((VPD_UNIT_SERIAL_NUM == b[1]) && (len > 0)) {
                    memcpy(obuff, b + 4, len);
                    obuff[len] = '\0';
                    return 0;
                } else {
                    if (verbose > 2)
                        fprintf(stderr, "fetch_unit_serial_num: bad sn VPD "
                                "page\n");
                    return SG_LIB_CAT_MALFORMED;
                }
            }
        } else {
            if (verbose > 2)
                fprintf(stderr, "fetch_unit_serial_num: no supported VPDs "
                        "page\n");
            return SG_LIB_CAT_MALFORMED;
        }
    } else if (verbose > 2)
        fprintf(stderr, "fetch_unit_serial_num: fetch supported VPDs "
                "failed\n");
    return res;
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


/* Process a standard INQUIRY response. Returns 0 if successful */
static int
process_std_inq(int sg_fd, const struct opts_t * optsp)
{
    int res, len, rlen, act_len, pqual, peri_type, ansi_version, k, j;
    const char * cp;
    int vdesc_arr[8];
    char buff[48];
    int verb, resid;

    memset(vdesc_arr, 0, sizeof(vdesc_arr));
    rlen = (optsp->resp_len > 0) ? optsp->resp_len : SAFE_STD_INQ_RESP_LEN;
    verb = optsp->do_verbose;
    res = ll_inquiry(sg_fd, 0, 0, 0, rsp_buff, rlen, &resid, 0, verb);
    if (0 == res) {
        pqual = (rsp_buff[0] & 0xe0) >> 5;
        if (! optsp->do_raw && ! optsp->do_export) {
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
        len = rsp_buff[4] + 5;
        /* N.B. rsp_buff[2] full byte is 'version' in SPC-2,3,4 but in SPC
         * [spc-r11a (1997)] bits 6,7: ISO/IEC version; bits 3-5: ECMA
         * version; bits 0-2: SCSI version */
        ansi_version = rsp_buff[2] & 0x7;       /* Only take SCSI version */
        peri_type = rsp_buff[0] & 0x1f;
        if ((len > SAFE_STD_INQ_RESP_LEN) && (len < 256) &&
            (0 == optsp->resp_len)) {
            rlen = len;
            memset(rsp_buff, 0, rlen);
            if (ll_inquiry(sg_fd, 0, 0, 0, rsp_buff, rlen, &resid, 1, verb)) {
                fprintf(stderr, "second INQUIRY (%d byte) failed\n", len);
                return SG_LIB_CAT_OTHER;
            }
            if (len != (rsp_buff[4] + 5)) {
                fprintf(stderr, "strange, consecutive INQUIRYs yield "
                        "different 'additional lengths'\n");
                res = SG_LIB_CAT_MALFORMED;
                len = rsp_buff[4] + 5;
            }
        }
        if (optsp->resp_len > 0)
            act_len = rlen;
        else
            act_len = (rlen < len) ? rlen : len;
        /* don't use more than HBA's resid says was transferred from LU */
        if (act_len < (rlen - resid))
            act_len = rlen - resid;
        if (optsp->do_raw)
            dStrRaw((const char *)rsp_buff, act_len);
        else if (optsp->do_hex)
            dStrHex((const char *)rsp_buff, act_len, 0);
        else if (!optsp->do_export) {
            printf("  PQual=%d  Device_type=%d  RMB=%d  version=0x%02x ",
                   pqual, peri_type, !!(rsp_buff[1] & 0x80),
                   (unsigned int)rsp_buff[2]);
            printf(" [%s]\n", get_ansi_version_str(ansi_version, buff,
                                                   sizeof(buff)));
            printf("  [AERC=%d]  [TrmTsk=%d]  NormACA=%d  HiSUP=%d "
                   " Resp_data_format=%d\n  SCCS=%d  ",
                   !!(rsp_buff[3] & 0x80), !!(rsp_buff[3] & 0x40),
                   !!(rsp_buff[3] & 0x20), !!(rsp_buff[3] & 0x10),
                   rsp_buff[3] & 0x0f, !!(rsp_buff[5] & 0x80));
            printf("ACC=%d  TPGS=%d  3PC=%d  Protect=%d ",
                   !!(rsp_buff[5] & 0x40), ((rsp_buff[5] & 0x30) >> 4),
                   !!(rsp_buff[5] & 0x08), !!(rsp_buff[5] & 0x01));
            printf(" [BQue=%d]\n  EncServ=%d  ", !!(rsp_buff[6] & 0x80),
                   !!(rsp_buff[6] & 0x40));
            if (rsp_buff[6] & 0x10)
                printf("MultiP=1 (VS=%d)  ", !!(rsp_buff[6] & 0x20));
            else
                printf("MultiP=0  ");
            printf("[MChngr=%d]  [ACKREQQ=%d]  Addr16=%d\n  [RelAdr=%d]  ",
                   !!(rsp_buff[6] & 0x08), !!(rsp_buff[6] & 0x04),
                   !!(rsp_buff[6] & 0x01), !!(rsp_buff[7] & 0x80));
            printf("WBus16=%d  Sync=%d  Linked=%d  [TranDis=%d]  ",
                   !!(rsp_buff[7] & 0x20), !!(rsp_buff[7] & 0x10),
                   !!(rsp_buff[7] & 0x08), !!(rsp_buff[7] & 0x04));
            printf("CmdQue=%d\n", !!(rsp_buff[7] & 0x02));
            if (act_len > 56)
                printf("  [SPI: Clocking=0x%x  QAS=%d  IUS=%d]\n",
                       (rsp_buff[56] & 0x0c) >> 2, !!(rsp_buff[56] & 0x2),
                       !!(rsp_buff[56] & 0x1));
            if (act_len >= len)
                printf("    length=%d (0x%x)", len, len);
            else
                printf("    length=%d (0x%x), but only fetched %d bytes",
                       len, len, act_len);
            if ((ansi_version >= 2) && (len < SAFE_STD_INQ_RESP_LEN))
                printf("  [for SCSI>=2, len>=36 is expected]");
            cp = sg_get_pdt_str(peri_type, sizeof(buff), buff);
            if (strlen(cp) > 0)
                printf("   Peripheral device type: %s\n", cp);
        }
        if (act_len <= 8) {
            if (! optsp->do_export)
                printf(" Inquiry response length=%d, no vendor, "
                       "product or revision data\n", act_len);
        } else {
            int i;

            if (act_len < SAFE_STD_INQ_RESP_LEN)
                rsp_buff[act_len] = '\0';
            memcpy(xtra_buff, &rsp_buff[8], 8);
            xtra_buff[8] = '\0';
            /* Fixup any tab characters */
            for (i = 0; i < 8; ++i)
                if (xtra_buff[i] == 0x09)
                    xtra_buff[i] = ' ';
            if (optsp->do_export) {
                len = encode_whitespaces((unsigned char *)xtra_buff, 8);
                printf("SCSI_VENDOR=%s\n", xtra_buff);
                encode_string(xtra_buff, &rsp_buff[8], 8);
                printf("SCSI_VENDOR_ENC=%s\n", xtra_buff);
            } else
                printf(" Vendor identification: %s\n", xtra_buff);
            if (act_len <= 16) {
                if (! optsp->do_export)
                    printf(" Product identification: <none>\n");
            } else {
                memcpy(xtra_buff, &rsp_buff[16], 16);
                xtra_buff[16] = '\0';
                if (optsp->do_export) {
                    len = encode_whitespaces((unsigned char *)xtra_buff, 16);
                    printf("SCSI_MODEL=%s\n", xtra_buff);
                    encode_string(xtra_buff, &rsp_buff[16], 16);
                    printf("SCSI_MODEL_ENC=%s\n", xtra_buff);
                } else
                    printf(" Product identification: %s\n", xtra_buff);
            }
            if (act_len <= 32) {
                if (!optsp->do_export)
                    printf(" Product revision level: <none>\n");
            } else {
                memcpy(xtra_buff, &rsp_buff[32], 4);
                xtra_buff[4] = '\0';
                if (optsp->do_export) {
                    len = encode_whitespaces((unsigned char *)xtra_buff, 4);
                    printf("SCSI_REVISION=%s\n", xtra_buff);
                } else
                    printf(" Product revision level: %s\n", xtra_buff);
            }
            if (optsp->do_vendor && (act_len > 36) && ('\0' != rsp_buff[36]) &&
                (' ' != rsp_buff[36])) {
                memcpy(xtra_buff, &rsp_buff[36], act_len < 56 ? act_len - 36 :
                       20);
                if (optsp->do_export) {
                    len = encode_whitespaces((unsigned char *)xtra_buff, 20);
                    printf("VENDOR_SPECIFIC=%s\n", xtra_buff);
                } else
                    printf(" Vendor specific: %s\n", xtra_buff);
            }
            if (optsp->do_descriptors) {
                for (j = 0, k = 58; ((j < 8) && ((k + 1) < act_len));
                     k +=2, ++j)
                    vdesc_arr[j] = ((rsp_buff[k] << 8) +
                                    rsp_buff[k + 1]);
            }
            if ((optsp->do_vendor > 1) && (act_len > 96)) {
                memcpy(xtra_buff, &rsp_buff[96], act_len - 96);
                if (optsp->do_export) {
                    len = encode_whitespaces((unsigned char *)xtra_buff,
                                             act_len - 96);
                    printf("VENDOR_SPECIFIC=%s\n", xtra_buff);
                } else
                    printf(" Vendor specific: %s\n", xtra_buff);
            }
        }
        if (! (optsp->do_raw || optsp->do_hex || optsp->do_export)) {
            if (0 == optsp->resp_len) {
                if (0 == fetch_unit_serial_num(sg_fd, xtra_buff,
                                   sizeof(xtra_buff), optsp->do_verbose))
                    printf(" Unit serial number: %s\n", xtra_buff);
            }
            if (optsp->do_descriptors) {
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
    } else if (res < 0) { /* could be an ATA device */
#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
        /* Try an ATA Identify Device command */
        res = try_ata_identify(sg_fd, optsp->do_hex, optsp->do_raw,
                               optsp->do_verbose);
        if (0 != res) {
            fprintf(stderr, "Both SCSI INQUIRY and fetching ATA information "
                    "failed on %s\n", optsp->device_name);
            return SG_LIB_CAT_OTHER;
        }
#else
        fprintf(stderr, "SCSI INQUIRY failed on %s, res=%d\n",
                optsp->device_name, res);
        return res;
#endif
    } else {
        fprintf(stderr, "    inquiry: failed requesting %d byte response: ",
                rlen);
        if (resid && verb)
            snprintf(buff, sizeof(buff), " [resid=%d]", resid);
        else
            buff[0] = '\0';
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "not supported (?)%s\n", buff);
        else if (SG_LIB_CAT_NOT_READY == res)
            fprintf(stderr, "device not ready (?)%s\n", buff);
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "field in cdb illegal%s\n", buff);
        else if (SG_LIB_CAT_UNIT_ATTENTION == res)
            fprintf(stderr, "unit attention (?)%s\n", buff);
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "aborted command%s\n", buff);
        else
            fprintf(stderr, "res=%d%s\n", res, buff);
        return res;
    }
    return 0;
}

#ifdef SG_SCSI_STRINGS
/* Returns 0 if successful */
static int
process_cmddt(int sg_fd, const struct opts_t * optsp)
{
    int k, j, num, len, peri_type, reserved_cmddt, support_num, res;
    char op_name[128];

    memset(rsp_buff, 0, DEF_ALLOC_LEN);
    if (optsp->do_cmddt > 1) {
        printf("Supported command list:\n");
        for (k = 0; k < 256; ++k) {
            res = sg_ll_inquiry(sg_fd, 1, 0, k, rsp_buff, DEF_ALLOC_LEN,
                                1, optsp->do_verbose);
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
            }
            else {
                fprintf(stderr,
                        "CmdDt INQUIRY on opcode=0x%.2x: failed\n", k);
                break;
            }
        }
    }
    else {
        res = sg_ll_inquiry(sg_fd, 1, 0, optsp->page_num, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            peri_type = rsp_buff[0] & 0x1f;
            if (! optsp->do_raw) {
                printf("CmdDt INQUIRY, opcode=0x%.2x:  [", optsp->page_num);
                sg_get_opcode_name((unsigned char)optsp->page_num, peri_type,
                                   sizeof(op_name) - 1, op_name);
                op_name[sizeof(op_name) - 1] = '\0';
                printf("%s]\n", op_name);
            }
            len = rsp_buff[5] + 6;
            reserved_cmddt = rsp_buff[4];
            if (optsp->do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else if (optsp->do_raw)
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
        }
        else {
            if (! optsp->do_raw) {
                printf("CmdDt INQUIRY, opcode=0x%.2x:  [", optsp->page_num);
                sg_get_opcode_name((unsigned char)optsp->page_num, 0,
                                   sizeof(op_name) - 1, op_name);
                op_name[sizeof(op_name) - 1] = '\0';
                printf("%s]\n", op_name);
            }
            fprintf(stderr, "CmdDt INQUIRY on opcode=0x%.2x: failed\n",
                    optsp->page_num);
        }
    }
    return res;
}

#else /* SG_SCSI_STRINGS */

/* Returns 0. */
static int
process_cmddt(int sg_fd, const struct opts_t * optsp)
{
    sg_fd = sg_fd;
    optsp = optsp;
    fprintf(stderr, "'--cmddt' not implemented, use sg_opcodes\n");
    return 0;
}

#endif /* SG_SCSI_STRINGS */


/* Returns 0 if successful */
static int
process_vpd(int sg_fd, const struct opts_t * optsp)
{
    int res, len, num, k, peri_type, vpd;
    const char * cp;
    char buff[48];

    memset(rsp_buff, 0, DEF_ALLOC_LEN);
    if (! optsp->do_raw)
        printf("VPD INQUIRY, page code=0x%.2x:\n", optsp->page_num);
    res = sg_ll_inquiry(sg_fd, 0, 1, optsp->page_num, rsp_buff,
                        DEF_ALLOC_LEN, 1, optsp->do_verbose);
    if (0 == res) {
        len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
        if (optsp->page_num != rsp_buff[1]) {
            fprintf(stderr, "invalid VPD response; probably a STANDARD "
                    "INQUIRY response\n");
            return SG_LIB_CAT_MALFORMED;
        }
        if (len > MX_ALLOC_LEN) {
            fprintf(stderr, "response length too long: %d > %d\n", len,
                   MX_ALLOC_LEN);
            return SG_LIB_CAT_MALFORMED;
        } else if (len > DEF_ALLOC_LEN) {
            if (sg_ll_inquiry(sg_fd, 0, 1, optsp->page_num, rsp_buff, len, 1,
                              optsp->do_verbose))
                return SG_LIB_CAT_OTHER;
        }
        if (optsp->do_raw)
            dStrRaw((const char *)rsp_buff, len);
        else {
            if (optsp->do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else if (0 == optsp->page_num) { /* decode this mandatory page */
                peri_type = rsp_buff[0] & 0x1f;
                printf("   [PQual=%d  Peripheral device type: %s]\n",
                       (rsp_buff[0] & 0xe0) >> 5,
                       sg_get_pdt_str(peri_type, sizeof(buff), buff));
                printf("   Supported VPD pages:\n");
                num = rsp_buff[3];
                for (k = 0; k < num; ++k) {
                    vpd = rsp_buff[4 + k];
                    cp = get_vpd_page_str(vpd, peri_type);
                    if (cp)
                        printf("     0x%x\t%s\n", vpd, cp);
                    else
                        printf("     0x%x\n", vpd);
                }
            } else
                dStrHex((const char *)rsp_buff, len, 0);
        }
    } else {
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "    inquiry: not supported (?)\n");
        else if (SG_LIB_CAT_NOT_READY == res)
            fprintf(stderr, "    inquiry: device not ready (?)\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "    inquiry: field in cdb illegal (page not "
                    "supported)\n");
        else if (SG_LIB_CAT_UNIT_ATTENTION == res)
            fprintf(stderr, "    inquiry: unit attention (?)\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "    inquiry: aborted command\n");
        else
            fprintf(stderr, "    inquiry: failed, res=%d\n", res);
    }
    return res;
}

/* Returns 0 if successful */
static int
decode_vpd(int sg_fd, const struct opts_t * optsp)
{
    int len, pdt;
    int res = 0;

    switch (optsp->page_num) {
    case VPD_UNIT_SERIAL_NUM:
        if (! optsp->do_raw && ! optsp->do_export)
            printf("VPD INQUIRY: Unit serial number page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_UNIT_SERIAL_NUM, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4; /* spc4r25 */
            if (VPD_UNIT_SERIAL_NUM != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (optsp->do_hex)
                dStrHex((const char *)rsp_buff, len, 0);
            else {
                char obuff[DEF_ALLOC_LEN];

                memset(obuff, 0, sizeof(obuff));
                len -= 4;
                if (len >= (int)sizeof(obuff))
                    len = sizeof(obuff) - 1;
                memcpy(obuff, rsp_buff + 4, len);
                if (optsp->do_export) {
                    len = encode_whitespaces((unsigned char *)obuff, len);
                    printf("SCSI_IDENT_SERIAL=%s\n", obuff);
                } else {
                    printf("  Unit serial number: %s\n", obuff);
                }
            }
        }
        break;
    case VPD_DEVICE_ID:
        if (! optsp->do_raw && ! optsp->do_export)
            printf("VPD INQUIRY: Device Identification page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_DEVICE_ID, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (VPD_DEVICE_ID != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_DEVICE_ID, rsp_buff, len,
                                  1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (optsp->do_export) {
                if (len < 4) {
                    fprintf(stderr, "Device identification page length too "
                            "short=%d\n", len);
                } else {
                    export_dev_ids(rsp_buff + 4, len - 4);
                }
            } else
                decode_id_vpd(rsp_buff, len, optsp->do_hex);
        }
        break;
    case VPD_SOFTW_INF_ID:
        if (! optsp->do_raw)
            printf("VPD INQUIRY: Software interface identification page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_SOFTW_INF_ID, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4; /* spc4r25 */
            if (VPD_SOFTW_INF_ID != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_softw_inf_id(rsp_buff, len, optsp->do_hex);
        }
        break;
    case VPD_MAN_NET_ADDR:
        if (!optsp->do_raw)
            printf("VPD INQUIRY: Management network addresses page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_MAN_NET_ADDR, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (VPD_MAN_NET_ADDR != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_MAN_NET_ADDR, rsp_buff,
                                  len, 1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_net_man_vpd(rsp_buff, len, optsp->do_hex);
        }
        break;
    case VPD_MODE_PG_POLICY:
        if (!optsp->do_raw)
            printf("VPD INQUIRY: Mode page policy\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_MODE_PG_POLICY, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (VPD_MODE_PG_POLICY != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_MODE_PG_POLICY, rsp_buff,
                                  len, 1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_mode_policy_vpd(rsp_buff, len, optsp->do_hex);
        }
        break;
    case VPD_EXT_INQ:
        if (!optsp->do_raw)
            printf("VPD INQUIRY: extended INQUIRY data page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_EXT_INQ, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (VPD_EXT_INQ != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_EXT_INQ, rsp_buff, len,
                                  1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_x_inq_vpd(rsp_buff, len, optsp->do_hex);
        }
        break;
    case VPD_ATA_INFO:
        if (!optsp->do_raw)
            printf("VPD INQUIRY: ATA information page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_ATA_INFO, rsp_buff,
                            VPD_ATA_INFO_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (VPD_ATA_INFO != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > VPD_ATA_INFO_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_ATA_INFO, rsp_buff, len,
                                  1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            /* format output for 'hdparm --Istdin' with '-rr' or '-HHH' */
            if ((2 == optsp->do_raw) || (3 == optsp->do_hex))
                dWordHex((const unsigned short *)(rsp_buff + 60),
                         256, -2, sg_is_big_endian());
            else if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_ata_info_vpd(rsp_buff, len, optsp->do_hex);
        }
        break;
    case VPD_POWER_CONDITION:
        if (!optsp->do_raw)
            printf("VPD INQUIRY: Power condition page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_POWER_CONDITION, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (VPD_POWER_CONDITION != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_POWER_CONDITION, rsp_buff,
                                  len, 1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_power_condition(rsp_buff, len, optsp->do_hex);
        }
        break;
    case 0xb0:  /* VPD pages in B0h to BFh range depend on pdt */
        res = sg_ll_inquiry(sg_fd, 0, 1, 0xb0, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            pdt = rsp_buff[0] & 0x1f;
            if (! optsp->do_raw) {
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
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (0xb0 != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, 0xb0, rsp_buff,
                                  len, 1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_b0_vpd(rsp_buff, len, optsp->do_hex, pdt);
        } else if (! optsp->do_raw)
            printf("VPD INQUIRY: page=0xb0\n");
        break;
    case 0xb1:  /* VPD pages in B0h to BFh range depend on pdt */
        res = sg_ll_inquiry(sg_fd, 0, 1, 0xb1, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            pdt = rsp_buff[0] & 0x1f;
            if (! optsp->do_raw) {
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
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (0xb1 != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, 0xb1, rsp_buff,
                                  len, 1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_b1_vpd(rsp_buff, len, optsp->do_hex, pdt);
        } else if (! optsp->do_raw)
            printf("VPD INQUIRY: page=0xb1\n");
        break;
    case 0xb2:  /* VPD pages in B0h to BFh range depend on pdt */
        printf(" Only hex output supported. sg_vpd decodes the B2h page.\n");
        return process_vpd(sg_fd, optsp);
    case 0xb3:  /* VPD pages in B0h to BFh range depend on pdt */
        res = sg_ll_inquiry(sg_fd, 0, 1, 0xb3, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            pdt = rsp_buff[0] & 0x1f;
            if (! optsp->do_raw) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL:
                    printf("VPD INQUIRY: Referrals VPD page (SBC)\n");
                    break;
                default:
                    printf("VPD INQUIRY: page=0x%x, pdt=0x%x\n", 0xb3, pdt);
                    break;
                }
            }
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (0xb3 != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, 0xb3, rsp_buff,
                                  len, 1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_b3_vpd(rsp_buff, len, optsp->do_hex, pdt);
        } else if (! optsp->do_raw)
            printf("VPD INQUIRY: page=0xb3\n");
        break;
    case VPD_UPR_EMC:   /* 0xc0 */
        if (!optsp->do_raw)
            printf("VPD INQUIRY: Unit Path Report Page (EMC)\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_UPR_EMC, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (VPD_UPR_EMC != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_UPR_EMC, rsp_buff, len, 1,
                           optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (optsp->do_hex)
                dStrHex((const char *)rsp_buff, len, 1);
            else
                decode_upr_vpd_c0_emc(rsp_buff, len);
        }
        break;
    case VPD_RDAC_VERS:         /* 0xc2 */
        if (!optsp->do_raw)
            printf("VPD INQUIRY: Software Version (RDAC)\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_RDAC_VERS, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (VPD_RDAC_VERS != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_RDAC_VERS, rsp_buff, len, 1,
                           optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (optsp->do_hex)
                dStrHex((const char *)rsp_buff, len, 1);
            else
                decode_rdac_vpd_c2(rsp_buff, len);
        }
        break;
    case VPD_RDAC_VAC:          /* 0xc9 */
        if (!optsp->do_raw)
            printf("VPD INQUIRY: Volume Access Control (RDAC)\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_RDAC_VAC, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = rsp_buff[3] + 4;
            if (VPD_RDAC_VAC != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably not "
                        "supported\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_RDAC_VAC, rsp_buff, len, 1,
                           optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else if (optsp->do_hex)
                dStrHex((const char *)rsp_buff, len, 1);
            else
                decode_rdac_vpd_c9(rsp_buff, len);
        }
        break;
    case VPD_SCSI_PORTS:
        if (!optsp->do_raw)
            printf("VPD INQUIRY: SCSI Ports page\n");
        res = sg_ll_inquiry(sg_fd, 0, 1, VPD_SCSI_PORTS, rsp_buff,
                            DEF_ALLOC_LEN, 1, optsp->do_verbose);
        if (0 == res) {
            len = ((rsp_buff[2] << 8) + rsp_buff[3]) + 4;
            if (VPD_SCSI_PORTS != rsp_buff[1]) {
                fprintf(stderr, "invalid VPD response; probably a STANDARD "
                        "INQUIRY response\n");
                return SG_LIB_CAT_MALFORMED;
            }
            if (len > MX_ALLOC_LEN) {
                fprintf(stderr, "response length too long: %d > %d\n", len,
                       MX_ALLOC_LEN);
                return SG_LIB_CAT_MALFORMED;
            } else if (len > DEF_ALLOC_LEN) {
                if (sg_ll_inquiry(sg_fd, 0, 1, VPD_SCSI_PORTS, rsp_buff, len,
                                  1, optsp->do_verbose))
                    return SG_LIB_CAT_OTHER;
            }
            if (optsp->do_raw)
                dStrRaw((const char *)rsp_buff, len);
            else
                decode_scsi_ports_vpd(rsp_buff, len, optsp->do_hex);
        }
        break;
    default:
        printf(" Only hex output supported. sg_vpd decodes more pages.\n");
        return process_vpd(sg_fd, optsp);
    }
    if (res) {
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, "    inquiry: not supported (?)\n");
        else if (SG_LIB_CAT_NOT_READY == res)
            fprintf(stderr, "    inquiry: device not ready (?)\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
            fprintf(stderr, "    inquiry: field in cdb illegal (page not "
                    "supported)\n");
        else if (SG_LIB_CAT_UNIT_ATTENTION == res)
            fprintf(stderr, "    inquiry: unit attention (?)\n");
        else if (SG_LIB_CAT_ABORTED_COMMAND == res)
            fprintf(stderr, "    inquiry: aborted command\n");
        else
            fprintf(stderr, "    inquiry: failed, res=%d\n", res);
    }
    return res;
}


int
main(int argc, char * argv[])
{
    int sg_fd, res, n;
    int ret = 0;
    const struct svpd_values_name_t * vnp;
    struct opts_t opts;

    memset(&opts, 0, sizeof(opts));
    opts.page_num = -1;
    res = process_cl(&opts, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (opts.do_help) {
        usage_for(&opts);
        if (opts.do_help > 1) {
            fprintf(stderr, "\n>>> Available VPD page abbreviations:\n");
            enumerate_vpds();
        }
        return 0;
    }
    if (opts.do_version) {
        fprintf(stderr, "Version string: %s\n", version_str);
        return 0;
    }
    if (opts.page_arg) {
        if (opts.page_num >= 0) {
            fprintf(stderr, "Given '-p' option and another option that "
                    "implies a page\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (isalpha(*opts.page_arg)) {
            vnp = sdp_find_vpd_by_acron(opts.page_arg);
            if (NULL == vnp) {
#ifdef SG_SCSI_STRINGS
                if (opts.opt_new)
                    fprintf(stderr, "abbreviation %s given to '--page=' "
                            "not recognized\n", opts.page_arg);
                else
                    fprintf(stderr, "abbreviation %s given to '-p=' "
                            "not recognized\n", opts.page_arg);
#else
                fprintf(stderr, "abbreviation %s given to '--page=' "
                        "not recognized\n", opts.page_arg);
#endif
                fprintf(stderr, ">>> Available abbreviations:\n");
                enumerate_vpds();
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((1 != opts.do_hex) && (0 == opts.do_raw))
                ++opts.do_decode;
            opts.page_num = vnp->value;
        } else {
#ifdef SG_SCSI_STRINGS
            if (opts.opt_new) {
                n = sg_get_num(opts.page_arg);
                if ((n < 0) || (n > 255)) {
                    fprintf(stderr, "Bad argument to '--page=', "
                            "expecting 0 to 255 inclusive\n");
                    usage_for(&opts);
                    return SG_LIB_SYNTAX_ERROR;
                }
                if ((1 != opts.do_hex) && (0 == opts.do_raw))
                    ++opts.do_decode;
            } else {
                int num;
                unsigned int u;

                num = sscanf(opts.page_arg, "%x", &u);
                if ((1 != num) || (u > 255)) {
                    fprintf(stderr, "Inappropriate value after '-o=' "
                            "or '-p=' option\n");
                    usage_for(&opts);
                    return SG_LIB_SYNTAX_ERROR;
                }
                n = u;
            }
#else
            n = sg_get_num(opts.page_arg);
            if ((n < 0) || (n > 255)) {
                fprintf(stderr, "Bad argument to '--page=', "
                        "expecting 0 to 255 inclusive\n");
                usage_for(&opts);
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((1 != opts.do_hex) && (0 == opts.do_raw))
                ++opts.do_decode;
#endif /* SG_SCSI_STRINGS */
            opts.page_num = n;
        }
    }
    if (opts.do_export) {
        if (opts.page_num != -1) {
            if (opts.page_num != VPD_DEVICE_ID &&
                opts.page_num != VPD_UNIT_SERIAL_NUM) {
                fprintf(stderr, "Option '--export' only supported "
                        "for VPD pages 0x80 and 0x83\n");
                usage_for(&opts);
                return SG_LIB_SYNTAX_ERROR;
            }
            ++opts.do_decode;
            ++opts.do_vpd;
        }
    }

    if ((0 == opts.do_cmddt) && (opts.page_num >= 0) && opts.p_given)
        ++opts.do_vpd;

    if (opts.do_raw && opts.do_hex) {
        fprintf(stderr, "Can't do hex and raw at the same time\n");
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.do_vpd && opts.do_cmddt) {
#ifdef SG_SCSI_STRINGS
        if (opts.opt_new)
            fprintf(stderr, "Can't use '--cmddt' with VPD pages\n");
        else
            fprintf(stderr, "Can't have both '-e' and '-c' (or '-cl')\n");
#else
        fprintf(stderr, "Can't use '--cmddt' with VPD pages\n");
#endif
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (((opts.do_vpd || opts.do_cmddt)) && (opts.page_num < 0))
        opts.page_num = 0;
    if (opts.num_pages > 1) {
        fprintf(stderr, "Can only fetch one page (VPD or Cmd) at a time\n");
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.do_descriptors) {
        if ((opts.resp_len > 0) && (opts.resp_len < 60)) {
            fprintf(stderr, "version descriptors need INQUIRY response "
                    "length >= 60 bytes\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (opts.do_vpd || opts.do_cmddt) {
            fprintf(stderr, "version descriptors require standard INQUIRY\n");
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (opts.num_pages && opts.do_ata) {
        fprintf(stderr, "Can't use '-A' with an explicit decode VPD "
                "page option\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    if (0 == opts.device_name) {
        fprintf(stderr, "No DEVICE argument given\n");
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if ((sg_fd = sg_cmds_open_device(opts.device_name, 1 /* ro */,
                                     opts.do_verbose)) < 0) {
        fprintf(stderr, "sg_inq: error opening file: %s: %s\n",
                opts.device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    memset(rsp_buff, 0, sizeof(rsp_buff));

#if defined(SG_LIB_LINUX) && defined(SG_SCSI_STRINGS)
    if (opts.do_ata) {
        res = try_ata_identify(sg_fd, opts.do_hex, opts.do_raw,
                               opts.do_verbose);
        if (0 != res) {
            fprintf(stderr, "fetching ATA information failed on %s\n",
                    opts.device_name);
            ret = SG_LIB_CAT_OTHER;
        } else
            ret = 0;
        goto err_out;
    }
#endif

    if ((! opts.do_cmddt) && (! opts.do_vpd)) {
        /* So it's a Standard INQUIRY, try ATA IDENTIFY if that fails */
        ret = process_std_inq(sg_fd, &opts);
        if (ret)
            goto err_out;
    } else if (opts.do_cmddt) {
        if (opts.page_num < 0)
            opts.page_num = 0;
        ret = process_cmddt(sg_fd, &opts);
        if (ret)
            goto err_out;
    } else if (opts.do_vpd) {
        if (opts.do_decode) {
            ret = decode_vpd(sg_fd, &opts);
            if (ret)
                goto err_out;
        } else {
            ret = process_vpd(sg_fd, &opts);
            if (ret)
                goto err_out;
        }
    }

err_out:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
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
                fprintf(stderr, "HDIO_GET_IDENTITY failed with ENOTTY, "
                        "try HDIO_DRIVE_CMD ioctl ...\n");
            buff[0] = ATA_IDENTIFY_DEVICE;
            buff[3] = 1;
            if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
                if (verbose)
                    fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                            "ioctl failed:\n\t%s [%d]\n",
                            safe_strerror(errno), errno);
                return errno;
            }
            memcpy(data, buff + HDIO_DRIVE_CMD_OFFSET, ATA_IDENTIFY_BUFF_SZ);
            return 0;
        } else {
            if (verbose)
                fprintf(stderr, "HDIO_GET_IDENTITY ioctl failed:\n"
                        "\t%s [%d]\n", safe_strerror(errno), errno);
            return errno;
        }
    } else if (verbose > 1)
        fprintf(stderr, "HDIO_GET_IDENTITY succeeded\n");
    if (0x2 == ((get_ident[0] >> 14) &0x3)) {   /* ATAPI device */
        if (verbose > 1)
            fprintf(stderr, "assume ATAPI device from HDIO_GET_IDENTITY "
                    "response\n");
        memset(buff, 0, sizeof(buff));
        buff[0] = ATA_IDENTIFY_PACKET_DEVICE;
        buff[3] = 1;
        if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
            if (verbose)
                fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_PACKET_DEVICE) "
                        "ioctl failed:\n\t%s [%d]\n", safe_strerror(errno),
                        errno);
            buff[0] = ATA_IDENTIFY_DEVICE;
            buff[3] = 1;
            if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
                if (verbose)
                    fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                            "ioctl failed:\n\t%s [%d]\n", safe_strerror(errno),
                            errno);
                return errno;
            }
        } else if (atapi_flag) {
            *atapi_flag = 1;
            if (verbose > 1)
                fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                        "succeeded\n");
        }
    } else {    /* assume non-packet device */
        buff[0] = ATA_IDENTIFY_DEVICE;
        buff[3] = 1;
        if (ioctl(device, HDIO_DRIVE_CMD, buff) < 0) {
            if (verbose)
                fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) "
                        "ioctl failed:\n\t%s [%d]\n", safe_strerror(errno),
                        errno);
            return errno;
        } else if (verbose > 1)
            fprintf(stderr, "HDIO_DRIVE_CMD(ATA_IDENTIFY_DEVICE) succeeded\n");
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

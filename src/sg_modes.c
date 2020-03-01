/*
 *  Copyright (C) 2000-2020 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *  This program outputs information provided by a SCSI MODE SENSE command.
 *  Does 10 byte MODE SENSE commands by default, Trent Piepho added a "-6"
 *  switch for force 6 byte mode sense commands.
 *  This utility cannot modify mode pages. See the sdparm utility for that.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.71 20200121";

#define DEF_ALLOC_LEN (1024 * 4)
#define DEF_6_ALLOC_LEN 252
#define UNLIKELY_ABOVE_LEN 512
#define PG_CODE_ALL 0x3f
#define PG_CODE_MASK 0x3f
#define PG_CODE_MAX 0x3f
#define SPG_CODE_ALL 0xff
#define PROTO_SPECIFIC_1 0x18
#define PROTO_SPECIFIC_2 0x19

#define EBUFF_SZ 256


struct opts_t {
    bool do_dbd;
    bool do_dbout;
    bool do_examine;
    bool do_flexible;
    bool do_list;
    bool do_llbaa;
    bool do_six;
    bool o_readwrite;
    bool subpg_code_given;
    bool opt_new;
    bool verbose_given;
    bool version_given;
    int do_all;
    int do_help;
    int do_hex;
    int maxlen;
    int do_raw;
    int verbose;
    int page_control;
    int pg_code;
    int subpg_code;
    const char * device_name;
    const char * page_acron;
};

struct page_code_desc {
    int page_code;
    int subpage_code;
    const char * acron;
    const char * desc;
};

struct pc_desc_group {
    struct page_code_desc * pcdp;
    const char * group_name;
};

static struct option long_options[] = {
        {"all", no_argument, 0, 'a'},
        {"control", required_argument, 0, 'c'},
        {"dbd", no_argument, 0, 'd'},
        {"dbout", no_argument, 0, 'D'},
        {"examine", no_argument, 0, 'e'},
        {"flexible", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"list", no_argument, 0, 'l'},
        {"llbaa", no_argument, 0, 'L'},
        {"maxlen", required_argument, 0, 'm'},
        {"new", no_argument, 0, 'N'},
        {"old", no_argument, 0, 'O'},
        {"page", required_argument, 0, 'p'},
        {"raw", no_argument, 0, 'r'},
        {"read-write", no_argument, 0, 'w'},
        {"read_write", no_argument, 0, 'w'},
        {"readwrite", no_argument, 0, 'w'},
        {"six", no_argument, 0, '6'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static struct page_code_desc pc_desc_common[] = {
    {0x0, 0x0, "ua", "Unit Attention condition [vendor specific format]"},
    {0x2, 0x0, "dr", "Disconnect-Reconnect"},
    {0x9, 0x0, "pd", "Peripheral device (obsolete)"},
    {0xa, 0x0, "co", "Control"},
    {0xa, 0x1, "coe", "Control extension"},
    {0xa, 0x3, "cdla", "Command duration limit A"},
    {0xa, 0x4, "cdlb", "Command duration limit B"},
    {0xa, 0x7, "cdt2a", "Command duration limit T2A"},  /* spc6r01 */
    {0xa, 0x8, "cdt2b", "Command duration limit T2B"},  /* spc6r01 */
    {0x15, 0x0, "ext_", "Extended"},
    {0x16, 0x0, "edts", "Extended device-type specific"},
    {0x18, 0x0, "pslu", "Protocol specific lu"},
    {0x19, 0x0, "pspo", "Protocol specific port"},
    {0x1a, 0x0, "po", "Power condition"},
    {0x1a, 0x1, "ps", "Power consumption"},
    {0x1c, 0x0, "ie", "Informational exceptions control"},
    {PG_CODE_ALL, 0x0, "asmp", "[yields all supported pages]"},
    {PG_CODE_ALL, SPG_CODE_ALL,"asmsp",
        "[yields all supported pages and subpages]"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_disk[] = {
    {0x1, 0x0, "rw", "Read-Write error recovery"},
    {0x3, 0x0, "fo", "Format (obsolete)"},
    {0x4, 0x0, "rd", "Rigid disk geometry (obsolete)"},
    {0x5, 0x0, "fd", "Flexible disk (obsolete)"},
    {0x7, 0x0, "ve", "Verify error recovery"},
    {0x8, 0x0, "ca", "Caching"},
    {0xa, 0x2, "atag", "Application tag"},
    {0xa, 0x5, "ioad", "IO advice hints grouping"}, /* added sbc4r06 */
    {0xa, 0x6, "bop", "Background operation control"}, /* added sbc4r07 */
    {0xa, 0xf1, "pat", "Parallel ATA control (SAT)"},
    {0xb, 0x0, "mts", "Medium types supported (obsolete)"},
    {0xc, 0x0, "not", "Notch and partition (obsolete)"},
    {0xd, 0x0, "pco", "Power condition (obsolete, moved to 0x1a)"},
    {0x10, 0x0, "xo", "XOR control"}, /* obsolete in sbc3r32 */
    {0x1a, 0xf1, "apo", "ATA Power condition"},
    {0x1c, 0x1, "bc", "Background control"},
    {0x1c, 0x2, "lbp", "Logical block provisioning"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_tape[] = {
    {0x1, 0x0, "rw", "Read-Write error recovery"},
    {0xa, 0xf0, "cdp", "Control data protection"},
    {0xf, 0x0, "dac", "Data Compression"},
    {0x10, 0x0, "dc", "Device configuration"},
    {0x10, 0x1, "dcs", "Device configuration extension"},
    {0x11, 0x0, "mpa", "Medium Partition [1]"},
    {0x12, 0x0, "mpa2", "Medium Partition [2]"},
    {0x13, 0x0, "mpa3", "Medium Partition [3]"},
    {0x14, 0x0, "mpar", "Medium Partition [4]"},
    {0x1c, 0x0, "ie", "Informational exceptions control (tape version)"},
    {0x1d, 0x0, "mco", "Medium configuration"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_cddvd[] = {
    {0x1, 0x0, "rw", "Read-Write error recovery"},
    {0x3, 0x0, "mrw", "Mount Rainer rewritable"},
    {0x5, 0x0, "wp", "Write parameters"},
    {0x7, 0x0, "ve", "Verify error recovery"},
    {0x8, 0x0, "ca", "Caching"},
    {0xd, 0x0, "cddp", "CD device parameters (obsolete)"},
    {0xe, 0x0, "cda", "CD audio"},
    {0x1a, 0x0, "po", "Power condition (mmc)"},
    {0x1c, 0x0, "ffrc", "Fault/failure reporting control (mmc)"},
    {0x1d, 0x0, "tp", "Timeout and protect"},
    {0x2a, 0x0, "cms", "MM capabilities and mechanical status (obsolete)"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_smc[] = {
    {0x1d, 0x0, "eaa", "Element address assignment"},
    {0x1e, 0x0, "tgp", "Transport geometry parameters"},
    {0x1f, 0x0, "dcs", "Device capabilities"},
    {0x1f, 0x41, "edc", "Extended device capabilities"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_scc[] = {
    {0x1b, 0x0, "sslm", "LUN mapping"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_ses[] = {
    {0x14, 0x0, "esm", "Enclosure services management"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_rbc[] = {
    {0x6, 0x0, "rbc", "RBC device parameters"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_adc[] = {
    /* {0xe, 0x0, "ADC device configuration"}, */
    {0xe, 0x1, "adtd", "Target device"},
    {0xe, 0x2, "addp", "DT device primary port"},
    {0xe, 0x3, "adlu", "Logical unit"},
    {0xe, 0x4, "adts", "Target device serial number"},
    {0x0, 0x0, NULL, NULL},
};


/* Transport reated mode pages */
static struct page_code_desc pc_desc_t_fcp[] = {
    {0x18, 0x0, "pl", "LU control"},
    {0x19, 0x0, "pp", "Port control"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_t_spi4[] = {
    {0x18, 0x0, "luc", "LU control"},
    {0x19, 0x0, "pp", "Port control short format"},
    {0x19, 0x1, "mc", "Margin control"},
    {0x19, 0x2, "stc", "Saved training configuration value"},
    {0x19, 0x3, "ns", "Negotiated settings"},
    {0x19, 0x4, "rtc", "Report transfer capabilities"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_t_sas[] = {
    {0x18, 0x0, "pslu", "Protocol specific logical unit (SAS)"},
    {0x19, 0x0, "pspo", "Protocol specific port (SAS)"},
    {0x19, 0x1, "pcd", "Phy control and discover (SAS)"},
    {0x19, 0x2, "spc", "Shared port control (SAS)"},
    {0x19, 0x3, "sep", "Enhanced phy control (SAS)"},
    {0x19, 0x4, "oobm", "Out of band management control (SAS)"}, /* spl5r01 */
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_t_adc[] = {
    {0xe, 0x1, "addt", "Target device"},
    {0xe, 0x2, "addp", "DT device primary port"},
    {0xe, 0x3, "adlu", "Logical unit"},
    {0x18, 0x0, "pslu", "Protocol specific lu"},
    {0x19, 0x0, "pspo", "Protocol specific port"},
    {0x0, 0x0, NULL, NULL},
};

static struct page_code_desc pc_desc_zbc[] = {
    {0x1, 0x0, "rw", "Read-Write error recovery"},
    {0x7, 0x0, "ve", "Verify error recovery"},
    {0x8, 0x0, "ca", "Caching"},
    {0xa, 0x2, "atag", "Application tag"},
    {0xa, 0xf, "zbdct", "Zoned block device control"},  /* zbc2r04a */
    {0x1c, 0x1, "bc", "Background control"},
    {0x0, 0x0, NULL, NULL},
};

struct pc_desc_group pcd_gr_arr[] = {
    {pc_desc_common, "common"},
    {pc_desc_disk, "disk"},
    {pc_desc_tape, "tape"},
    {pc_desc_cddvd, "cd/dvd"},
    {pc_desc_smc, "media changer"},
    {pc_desc_scc, "scsi controller"},
    {pc_desc_ses, "enclosure"},
    {pc_desc_rbc, "reduced block"},
    {pc_desc_adc, "adc"},
    {pc_desc_zbc, "zbc"},
    {pc_desc_t_fcp, "transport: FCP"},
    {pc_desc_t_spi4, "transport: SPI"},
    {pc_desc_t_sas, "transport: SAS"},
    {pc_desc_t_adc, "transport: ADC"},

    {NULL, NULL},
};



static void
usage()
{
    printf("Usage: sg_modes [--all] [--control=PC] [--dbd] [--dbout] "
           "[--examine]\n"
           "                [--flexible] [--help] [--hex] [--list] "
           "[--llbaa]\n"
           "                [--maxlen=LEN] [--page=PG[,SPG]] [--raw] [-R] "
           "[--readwrite]\n"
           "                [--six] [--verbose] [--version] [DEVICE]\n"
           "  where:\n"
           "    --all|-a        get all mode pages supported by device\n"
           "                    use twice to get all mode pages and subpages\n"
           "    --control=PC|-c PC    page control (default: 0)\n"
           "                       0: current, 1: changeable,\n"
           "                       2: (manufacturer's) defaults, 3: saved\n"
           "    --dbd|-d        disable block descriptors (DBD field in cdb)\n"
           "    --dbout|-D      disable block descriptor output\n"
           "    --examine|-e    examine pages # 0 through to 0x3e, note if "
           "found\n"
           "    --flexible|-f    be flexible, cope with MODE SENSE 6/10 "
           "response mixup\n");
    printf("    --help|-h       print usage message then exit\n"
           "    --hex|-H        output full response in hex\n"
           "                    use twice to output page number and header "
           "in hex\n"
           "    --list|-l       list common page codes for device peripheral "
           "type,\n"
           "                    if no device given then assume disk type\n"
           "    --llbaa|-L      set Long LBA Accepted (LLBAA field in mode "
           "sense (10) cdb)\n"
           "    --maxlen=LEN|-m LEN    max response length (allocation "
           "length in cdb)\n"
           "                           (def: 0 -> 4096 or 252 (for MODE "
           "SENSE 6) bytes)\n"
           "    --page=PG|-p PG    page code to fetch (def: 63). May be "
           "acronym\n"
           "    --page=PG,SPG|-p PG,SPG\n"
           "                       page code and subpage code to fetch "
           "(defs: 63,0)\n"
           "    --raw|-r        output response in binary to stdout\n"
           "    -R              mode page response to stdout, a byte per "
           "line in ASCII\n"
           "                    hex (same result as '--raw --raw')\n"
           "    --readwrite|-w    open DEVICE read-write (def: open "
           "read-only)\n"
           "    --six|-6        use MODE SENSE(6), by default uses MODE "
           "SENSE(10)\n"
           "    --verbose|-v    increase verbosity\n"
           "    --old|-O        use old interface (use as first option)\n"
           "    --version|-V    output version string then exit\n\n"
           "Performs a SCSI MODE SENSE (10 or 6) command. To access and "
           "possibly change\nmode page fields see the sdparm utility.\n");
}

static void
usage_old()
{
    printf("Usage:  sg_modes [-a] [-A] [-c=PC] [-d] [-D] [-e] [-f] [-h] "
           "[-H] [-l] [-L]\n"
           "                 [-m=LEN] [-p=PG[,SPG]] [-r] [-subp=SPG] [-v] "
           "[-V] [-6]\n"
           "                 [DEVICE]\n"
           " where:\n"
           "   -a    get all mode pages supported by device\n"
           "   -A    get all mode pages and subpages supported by device\n"
           "   -c=PC    page control (def: 0 [current],"
           " 1 [changeable],\n"
           "                               2 [default], 3 [saved])\n"
           "   -d    disable block descriptors (DBD field in cdb)\n"
           "   -D    disable block descriptor output\n"
           "   -e    examine pages # 0 through to 0x3e, note if found\n"
           "   -f    be flexible, cope with MODE SENSE 6/10 response "
           "mixup\n");
    printf("   -h    output page number and header in hex\n"
           "   -H    output page number and header in hex (same as '-h')\n"
           "   -l    list common page codes for device peripheral type,\n"
           "         if no device given then assume disk type\n"
           "   -L    set Long LBA Accepted (LLBAA field in mode sense "
           "10 cdb)\n"
           "   -m=LEN    max response length (allocation length in cdb)\n"
           "             (def: 0 -> 4096 or 252 (for MODE SENSE 6) bytes)\n"
           "   -p=PG     page code in hex (def: 3f). No acronym allowed\n"
           "   -p=PG,SPG    both in hex, (defs: 3f,0)\n"
           "   -r    mode page output to stdout, a byte per line in "
           "ASCII hex\n"
           "   -subp=SPG    sub page code in hex (def: 0)\n"
           "   -v    verbose\n"
           "   -V    output version string\n"
           "   -6    Use MODE SENSE(6), by default uses MODE SENSE(10)\n"
           "   -N|--new     use new interface\n"
           "   -?    output this usage message\n\n"
           "Performs a SCSI MODE SENSE (10 or 6) command\n");
}

static void
enum_pc_desc(void)
{
    bool first = true;
    const struct pc_desc_group * pcd_grp = pcd_gr_arr;
    char b[128];

    for ( ; pcd_grp->pcdp; ++pcd_grp) {
        const struct page_code_desc * pcdp = pcd_grp->pcdp;

        if (first)
            first = false;
        else
            printf("\n");
        printf("Mode pages group: %s:\n", pcd_grp->group_name);
        for ( ; pcdp->acron; ++pcdp) {
            if (pcdp->subpage_code > 0)
                snprintf(b, sizeof(b), "[0x%x,0x%x]", pcdp->page_code,
                         pcdp->subpage_code);
            else
                snprintf(b, sizeof(b), "[0x%x]", pcdp->page_code);
            printf("  %s: %s  %s\n", pcdp->acron, pcdp->desc, b);
        }
    }
}

static const struct page_code_desc *
find_pc_desc(const char * acron)
{
    const struct pc_desc_group * pcd_grp = pcd_gr_arr;

    for ( ; pcd_grp->pcdp; ++pcd_grp) {
        const struct page_code_desc * pcdp = pcd_grp->pcdp;

        for ( ; pcdp->acron; ++pcdp) {
            if (0 == strcmp(acron, pcdp->acron))
                return pcdp;
        }
    }
    return NULL;
}

static void
usage_for(const struct opts_t * op)
{
    if (op->opt_new)
        usage();
    else
        usage_old();
}

/* Processes command line options according to new option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
new_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int c, n, nn;
    char * cp;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "6aAc:dDefhHlLm:NOp:rRsvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case '6':
            op->do_six = true;
            break;
        case 'a':
            ++op->do_all;
            break;
        case 'A':
            op->do_all += 2;
            break;
        case 'c':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 3)) {
                pr2serr("bad argument to '--control='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->page_control = n;
            break;
        case 'd':
            op->do_dbd = true;
            break;
        case 'D':
            op->do_dbout = true;
            break;
        case 'e':
            op->do_examine = true;
            break;
        case 'f':
            op->do_flexible = true;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            break;
        case 'H':
            ++op->do_hex;
            break;
        case 'l':
            op->do_list = true;
            break;
        case 'L':
            op->do_llbaa = true;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 65535)) {
                pr2serr("bad argument to '--maxlen='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->maxlen = n;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = false;
            return 0;
        case 'p':
            if (isalpha(optarg[0])) {
                const struct page_code_desc * pcdp;

                op->page_acron = optarg;
                if (0 == memcmp("xxx", optarg, 3)) {
                    enum_pc_desc();
                    return SG_LIB_OK_FALSE;     /* for quick exit */
                }
                pcdp = find_pc_desc(optarg);
                if (pcdp) {
                    if (pcdp->subpage_code > 0) {
                        op->subpg_code = pcdp->subpage_code;
                        op->subpg_code_given = true;
                    }
                    op->pg_code = pcdp->page_code;
                } else {
                    pr2serr(" Couldn't match acronym '%s', try '-p xxx' for "
                            "list\n", optarg);
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                cp = strchr(optarg, ',');
                n = sg_get_num_nomult(optarg);
                if ((n < 0) || (n > 63)) {
                    pr2serr("Bad argument to '--page='\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                if (cp) {
                    nn = sg_get_num_nomult(cp + 1);
                    if ((nn < 0) || (nn > 255)) {
                        pr2serr("Bad second value in argument to "
                                "'--page='\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    op->subpg_code = nn;
                    op->subpg_code_given = true;
                }
                op->pg_code = n;
            }
            break;
        case 'r':
            ++op->do_raw;
            break;
        case 'R':
            op->do_raw += 2;
            break;
        case 's':
            op->do_six = true;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'w':
            op->o_readwrite = true;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x]\n", c, c);
            if (op->do_help)
                break;
            usage();
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
                pr2serr("Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

/* Processes command line options according to old option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
old_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    bool jmp_out;
    int k, plen, num, n;
    char pc1;
    unsigned int u, uu;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case '6':
                    op->do_six = true;
                    break;
                case 'a':
                    ++op->do_all;
                    break;
                case 'A':
                    op->do_all += 2;
                    break;
                case 'd':
                    op->do_dbd = true;
                    break;
                case 'D':
                    op->do_dbout = true;
                    break;
                case 'e':
                    op->do_examine = true;
                    break;
                case 'f':
                    op->do_flexible = true;
                    break;
                case 'h':
                case 'H':
                    op->do_hex += 2;
                    break;
                case 'l':
                    op->do_list = true;
                    break;
                case 'L':
                    op->do_llbaa = true;
                    break;
                case 'N':
                    op->opt_new = true;
                    return 0;
                case 'O':
                    break;
                case 'r':
                    op->do_raw += 2;
                    break;
                case 'v':
                    op->verbose_given = true;
                    ++op->verbose;
                    break;
                case 'V':
                    op->version_given = true;
                    break;
                case '?':
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
            if (0 == strncmp("c=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 3)) {
                    pr2serr("Bad page control after 'c=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->page_control = u;
            } else if (0 == strncmp("m=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n < 0) || (n > 65535)) {
                    pr2serr("Bad argument after 'm=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->maxlen = n;
            } else if (0 == strncmp("p=", cp, 2)) {
                pc1 = *(cp + 2);
                if (isalpha(pc1) && ((islower(pc1) && (pc1 > 'f')) ||
                                     (isupper(pc1) && (pc1 > 'F')))) {
                    pr2serr("Old format doesn't accept mode page acronyms: "
                            "%s\n", cp + 2);
                    return SG_LIB_SYNTAX_ERROR;
                }
                if (NULL == strchr(cp + 2, ',')) {
                    num = sscanf(cp + 2, "%x", &u);
                    if ((1 != num) || (u > 63)) {
                        pr2serr("Bad page code value after 'p=' option\n");
                        usage_old();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    op->pg_code = u;
                } else if (2 == sscanf(cp + 2, "%x,%x", &u, &uu)) {
                    if (uu > 255) {
                        pr2serr("Bad subpage code value after 'p=' option\n");
                        usage_old();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    op->pg_code = u;
                    op->subpg_code = uu;
                    op->subpg_code_given = true;
                } else {
                    pr2serr("Bad page code, subpage code sequence after 'p=' "
                            "option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else if (0 == strncmp("subp=", cp, 5)) {
                num = sscanf(cp + 5, "%x", &u);
                if ((1 != num) || (u > 255)) {
                    pr2serr("Bad sub page code after 'subp=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->subpg_code = u;
                op->subpg_code_given = true;
                if (-1 == op->pg_code)
                    op->pg_code = 0;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == op->device_name)
            op->device_name = cp;
        else {
            pr2serr("too many arguments, got: %s, not expecting: %s\n",
                    op->device_name, cp);
            usage_old();
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

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

static int
count_desc_elems(const struct page_code_desc * pcdp)
{
    int k;

    for (k = 0; k < 1024; ++k, ++pcdp) {
        if (NULL == pcdp->acron)
            return k;
    }
    pr2serr("%s: sanity check trip, invalid pc_desc table\n", __func__);
    return k;
}

/* Returns pointer to base of table for scsi_ptype or pointer to common
 * table if scsi_ptype is -1. Yields numbers of elements in returned
 * table via pointer sizep. If scsi_ptype not known then returns NULL
 * with *sizep set to zero. */
static struct page_code_desc *
get_mpage_tbl_size(int scsi_ptype, int * sizep)
{
    switch (scsi_ptype)
    {
        case -1:        /* common list */
            *sizep = count_desc_elems(pc_desc_common);
            return &pc_desc_common[0];
        case PDT_DISK:         /* disk (direct access) type devices */
        case PDT_WO:
        case PDT_OPTICAL:
            *sizep = count_desc_elems(pc_desc_disk);
            return &pc_desc_disk[0];
        case PDT_TAPE:         /* tape devices */
        case PDT_PRINTER:
            *sizep = count_desc_elems(pc_desc_tape);
            return &pc_desc_tape[0];
        case PDT_MMC:         /* cd/dvd/bd devices */
            *sizep = count_desc_elems(pc_desc_cddvd);
            return &pc_desc_cddvd[0];
        case PDT_MCHANGER:         /* medium changer devices */
            *sizep = count_desc_elems(pc_desc_smc);
            return &pc_desc_smc[0];
        case PDT_SAC:       /* storage array devices */
            *sizep = count_desc_elems(pc_desc_scc);
            return &pc_desc_scc[0];
        case PDT_SES:       /* enclosure services devices */
            *sizep = count_desc_elems(pc_desc_ses);
            return &pc_desc_ses[0];
        case PDT_RBC:       /* simplified direct access device */
            *sizep = count_desc_elems(pc_desc_rbc);
            return &pc_desc_rbc[0];
        case PDT_ADC:       /* automation device/interface */
            *sizep = count_desc_elems(pc_desc_adc);
            return &pc_desc_adc[0];
        case PDT_ZBC:
            *sizep = count_desc_elems(pc_desc_zbc);
            return &pc_desc_zbc[0];
    }
    *sizep = 0;
    return NULL;
}


static struct page_code_desc *
get_mpage_trans_tbl_size(int t_proto, int * sizep)
{
    switch (t_proto)
    {
        case TPROTO_FCP:
            *sizep = count_desc_elems(pc_desc_t_fcp);
            return &pc_desc_t_fcp[0];
        case TPROTO_SPI:
            *sizep = count_desc_elems(pc_desc_t_spi4);
            return &pc_desc_t_spi4[0];
        case TPROTO_SAS:
            *sizep = count_desc_elems(pc_desc_t_sas);
            return &pc_desc_t_sas[0];
        case TPROTO_ADT:
            *sizep = count_desc_elems(pc_desc_t_adc);
            return &pc_desc_t_adc[0];
    }
    *sizep = 0;
    return NULL;
}

static const char *
find_page_code_desc(int page_num, int subpage_num, int scsi_ptype,
                    bool encserv, bool mchngr, int t_proto)
{
    int k;
    int num;
    const struct page_code_desc * pcdp;

    if (t_proto >= 0) {
        pcdp = get_mpage_trans_tbl_size(t_proto, &num);
        if (pcdp) {
            for (k = 0; k < num; ++k, ++pcdp) {
                if ((page_num == pcdp->page_code) &&
                    (subpage_num == pcdp->subpage_code))
                    return pcdp->desc;
                else if (page_num < pcdp->page_code)
                    break;
            }
        }
    }
    pcdp = get_mpage_tbl_size(scsi_ptype, &num);
    if (pcdp) {
        for (k = 0; k < num; ++k, ++pcdp) {
            if ((page_num == pcdp->page_code) &&
                (subpage_num == pcdp->subpage_code))
                return pcdp->desc;
            else if (page_num < pcdp->page_code)
                break;
        }
    }
    if ((0xd != scsi_ptype) && encserv) {
        /* check for attached enclosure services processor */
        pcdp = get_mpage_tbl_size(0xd, &num);
        if (pcdp) {
            for (k = 0; k < num; ++k, ++pcdp) {
                if ((page_num == pcdp->page_code) &&
                    (subpage_num == pcdp->subpage_code))
                    return pcdp->desc;
                else if (page_num < pcdp->page_code)
                    break;
            }
        }
    }
    if ((0x8 != scsi_ptype) && mchngr) {
        /* check for attached medium changer device */
        pcdp = get_mpage_tbl_size(0x8, &num);
        if (pcdp) {
            for (k = 0; k < num; ++k, ++pcdp) {
                if ((page_num == pcdp->page_code) &&
                    (subpage_num == pcdp->subpage_code))
                    return pcdp->desc;
                else if (page_num < pcdp->page_code)
                    break;
            }
        }
    }
    pcdp = get_mpage_tbl_size(-1, &num);
    for (k = 0; k < num; ++k, ++pcdp) {
        if ((page_num == pcdp->page_code) &&
            (subpage_num == pcdp->subpage_code))
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            break;
    }
    return NULL;
}

static void
list_page_codes(int scsi_ptype, bool encserv, bool mchngr, int t_proto)
{
    int num, num_ptype, pg, spg, c, d;
    bool valid_transport;
    const struct page_code_desc * dp;
    const struct page_code_desc * pe_dp;
    char b[64];

    valid_transport = ((t_proto >= 0) && (t_proto <= 0xf));
    printf("Page[,subpage]   Name\n");
    printf("=====================\n");
    dp = get_mpage_tbl_size(-1, &num);
    pe_dp = get_mpage_tbl_size(scsi_ptype, &num_ptype);
    while (1) {
        pg = dp ? dp->page_code : PG_CODE_ALL + 1;
        spg = dp ? dp->subpage_code : SPG_CODE_ALL;
        c = (pg << 8) + spg;
        pg = pe_dp ? pe_dp->page_code : PG_CODE_ALL + 1;
        spg = pe_dp ? pe_dp->subpage_code : SPG_CODE_ALL;
        d = (pg << 8) + spg;
        if (valid_transport &&
            ((PROTO_SPECIFIC_1 == c) || (PROTO_SPECIFIC_2 == c)))
            dp = (--num <= 0) ? NULL : (dp + 1); /* skip protocol specific */
        else if (c == d) {
            if (pe_dp) {
                if (pe_dp->subpage_code)
                    printf(" 0x%02x,0x%02x    *  %s\n", pe_dp->page_code,
                           pe_dp->subpage_code, pe_dp->desc);
                else
                    printf(" 0x%02x         *  %s\n", pe_dp->page_code,
                           pe_dp->desc);
                pe_dp = (--num_ptype <= 0) ? NULL : (pe_dp + 1);
            }
            if (dp)
                dp = (--num <= 0) ? NULL : (dp + 1);
        } else if (c < d) {
            if (dp) {
                if (dp->subpage_code)
                    printf(" 0x%02x,0x%02x       %s\n", dp->page_code,
                           dp->subpage_code, dp->desc);
                else
                    printf(" 0x%02x            %s\n", dp->page_code,
                           dp->desc);
                dp = (--num <= 0) ? NULL : (dp + 1);
            }
        } else {
            if (pe_dp) {
                if (pe_dp->subpage_code)
                    printf(" 0x%02x,0x%02x       %s\n", pe_dp->page_code,
                           pe_dp->subpage_code, pe_dp->desc);
                else
                    printf(" 0x%02x            %s\n", pe_dp->page_code,
                           pe_dp->desc);
                pe_dp = (--num_ptype <= 0) ? NULL : (pe_dp + 1);
            }
        }
        if ((NULL == dp) && (NULL == pe_dp))
            break;
    }
    if ((0xd != scsi_ptype) && encserv) {
        /* check for attached enclosure services processor */
        printf("\n    Attached enclosure services processor\n");
        dp = get_mpage_tbl_size(0xd, &num);
        while (dp) {
            if (dp->subpage_code)
                printf(" 0x%02x,0x%02x       %s\n", dp->page_code,
                       dp->subpage_code, dp->desc);
            else
                printf(" 0x%02x            %s\n", dp->page_code,
                       dp->desc);
            dp = (--num <= 0) ? NULL : (dp + 1);
        }
    }
    if ((0x8 != scsi_ptype) && mchngr) {
        /* check for attached medium changer device */
        printf("\n    Attached medium changer device\n");
        dp = get_mpage_tbl_size(0x8, &num);
        while (dp) {
            if (dp->subpage_code)
                printf(" 0x%02x,0x%02x       %s\n", dp->page_code,
                       dp->subpage_code, dp->desc);
            else
                printf(" 0x%02x            %s\n", dp->page_code,
                       dp->desc);
            dp = (--num <= 0) ? NULL : (dp + 1);
        }
    }
    if (valid_transport) {
        printf("\n    Transport protocol: %s\n",
               sg_get_trans_proto_str(t_proto, sizeof(b), b));
        dp = get_mpage_trans_tbl_size(t_proto, &num);
        while (dp) {
            if (dp->subpage_code)
                printf(" 0x%02x,0x%02x       %s\n", dp->page_code,
                       dp->subpage_code, dp->desc);
            else
                printf(" 0x%02x            %s\n", dp->page_code,
                       dp->desc);
            dp = (--num <= 0) ? NULL : (dp + 1);
        }
    }
}

/* Returns 0 for ok, else error value */
static int
examine_pages(int sg_fd, int inq_pdt, bool encserv, bool mchngr,
              const struct opts_t * op)
{
    bool header_printed;
    int k, mresp_len, len, resid;
    int res = 0;
    const int mx_len = op->do_six ? DEF_6_ALLOC_LEN : DEF_ALLOC_LEN;
    const char * cp;
    uint8_t * rbuf;
    uint8_t * free_rbuf = NULL;

    rbuf = sg_memalign(mx_len, 0, &free_rbuf, false);
    if (NULL == rbuf) {
        pr2serr("%s: out of heap\n", __func__);
        return sg_convert_errno(ENOMEM);
    }
    mresp_len = (op->do_raw || op->do_hex) ? mx_len : 4;
    for (header_printed = false, k = 0; k < PG_CODE_MAX; ++k) {
        resid = 0;
        if (op->do_six) {
            res = sg_ll_mode_sense6(sg_fd, 0, 0, k, 0, rbuf, mresp_len,
                                    true, op->verbose);
            if (SG_LIB_CAT_INVALID_OP == res) {
                pr2serr(">>>>>> try again without the '-6' switch for a 10 "
                        "byte MODE SENSE command\n");
                goto out;
            } else if (SG_LIB_CAT_NOT_READY == res) {
                pr2serr("MODE SENSE (6) failed, device not ready\n");
                goto out;
            }
        } else {
            res = sg_ll_mode_sense10_v2(sg_fd, 0, 0, 0, k, 0, rbuf, mresp_len,
                                        0, &resid, true, op->verbose);
            if (SG_LIB_CAT_INVALID_OP == res) {
                pr2serr(">>>>>> try again with a '-6' switch for a 6 byte "
                        "MODE SENSE command\n");
                goto out;
            } else if (SG_LIB_CAT_NOT_READY == res) {
                pr2serr("MODE SENSE (10) failed, device not ready\n");
                goto out;
            }
        }
        if (0 == res) {
            len = sg_msense_calc_length(rbuf, mresp_len, op->do_six, NULL);
            if (resid > 0) {
                mresp_len -= resid;
                if (mresp_len < 0) {
                    pr2serr("%s: MS(10) resid=%d implies negative response "
                            "length (%d)\n", __func__, resid, mresp_len);
                    res = SG_LIB_WILD_RESID;
                    goto out;
                }
            }
            if (len > mresp_len)
                len = mresp_len;
            if (op->do_raw) {
                dStrRaw(rbuf, len);
                continue;
            }
            if (op->do_hex > 2) {
                hex2stdout(rbuf, len, -1);
                continue;
            }
            if (! header_printed) {
                printf("Discovered mode pages:\n");
                header_printed = true;
            }
            cp = find_page_code_desc(k, 0, inq_pdt, encserv, mchngr, -1);
            if (cp)
                printf("    %s\n", cp);
            else
                printf("    [0x%x]\n", k);
            if (op->do_hex)
                hex2stdout(rbuf, len, 1);
        } else if (op->verbose) {
            char b[80];

            sg_get_category_sense_str(res, sizeof(b), b, op->verbose - 1);
            pr2serr("MODE SENSE (%s) failed: %s\n", (op->do_six ? "6" : "10"),
                    b);
        }
    }
out:
    if (free_rbuf)
        free(free_rbuf);
    return res;
}

static const char * pg_control_str_arr[] = {
    "current",
    "changeable",
    "default",
    "saved",
};


int
main(int argc, char * argv[])
{
    bool resp_mode6, longlba, spf;
    bool encserv = false;
    bool mchngr = false;
    uint8_t uc;
    int k, num, len, res, md_len, bd_len, page_num, resid;
    int density_code_off, t_proto, inq_pdt, num_ua_pages, vb;
    int sg_fd = -1;
    int ret = 0;
    int rsp_buff_sz = DEF_ALLOC_LEN;
    const char * descp;
    struct opts_t * op;
    uint8_t * rsp_buff = NULL;
    uint8_t * free_rsp_buff = NULL;
    uint8_t * bp;
    const char * cdbLenStr;
    struct sg_simple_inquiry_resp inq_out;
    struct opts_t opts;
    char b[80];
    char ebuff[EBUFF_SZ];
    char pdt_name[64];

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->pg_code = -1;
    res = parse_cmd_line(op, argc, argv);
    if (res)
        return (SG_LIB_OK_FALSE == res) ? 0 : res;
    if (op->do_help) {
        usage_for(op);
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
    vb = op->verbose;
    if (vb && op->page_acron) {
        pr2serr("page acronynm: '%s' maps to page_code=0x%x",
                op->page_acron, op->pg_code);
        if (op->subpg_code > 0)
            pr2serr(", subpage_code=0x%x\n", op->subpg_code);
        else
            pr2serr("\n");
    }

    if (NULL == op->device_name) {
        if (op->do_list) {
            if ((op->pg_code < 0) || (op->pg_code > PG_CODE_MAX)) {
                printf("    Assume peripheral device type: disk\n");
                list_page_codes(0, false, false, -1);
            } else {
                printf("    peripheral device type: %s\n",
                       sg_get_pdt_str(op->pg_code, sizeof(pdt_name),
                                      pdt_name));
                if (op->subpg_code_given)
                    list_page_codes(op->pg_code, false, false,
                                    op->subpg_code);
                else
                    list_page_codes(op->pg_code, false, false, -1);
            }
            return 0;
        }
        pr2serr("No DEVICE argument given\n\n");
        usage_for(op);
        return SG_LIB_SYNTAX_ERROR;
    }

    if (op->do_examine && (op->pg_code >= 0)) {
        pr2serr("can't give '-e' and a page number\n");
        return SG_LIB_CONTRADICT;
    }

    if (op->do_six && op->do_llbaa) {
        pr2serr("LLBAA not defined for MODE SENSE 6, try without '-L'\n");
        return SG_LIB_CONTRADICT;
    }
    if (op->maxlen > 0) {
        if (op->do_six && (op->maxlen > 255)) {
            pr2serr("For Mode Sense (6) maxlen cannot exceed 255\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        rsp_buff = sg_memalign(op->maxlen, 0, &free_rsp_buff, false);
        rsp_buff_sz = op->maxlen;
    } else {    /* maxlen == 0 */
        rsp_buff = sg_memalign(rsp_buff_sz, 0, &free_rsp_buff, false);
        if (op->do_six)
            rsp_buff_sz = DEF_6_ALLOC_LEN;
    }
    if (NULL == rsp_buff) {     /* check for both sg_memalign()s */
        pr2serr("Unable to allocate %d bytes on heap\n", rsp_buff_sz);
        return sg_convert_errno(ENOMEM);
    }
    /* If no pages or list selected than treat as 'a' */
    if (! ((op->pg_code >= 0) || op->do_all || op->do_list || op->do_examine))
        op->do_all = 1;

    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto fini;
        }
    }

    if ((sg_fd = sg_cmds_open_device(op->device_name, ! op->o_readwrite,
                                     vb)) < 0) {
        pr2serr("error opening file: %s: %s\n", op->device_name,
                safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    if ((res = sg_simple_inquiry(sg_fd, &inq_out, true, vb))) {
        pr2serr("%s doesn't respond to a SCSI INQUIRY\n", op->device_name);
        ret = (res > 0) ? res : sg_convert_errno(-res);
        goto fini;
    }
    inq_pdt = inq_out.peripheral_type;
    encserv = !! (0x40 & inq_out.byte_6);
    mchngr = !! (0x8 & inq_out.byte_6);
    if ((0 == op->do_raw) && (op->do_hex < 3))
        printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n",
               inq_out.vendor, inq_out.product, inq_out.revision,
               sg_get_pdt_str(inq_pdt, sizeof(pdt_name), pdt_name), inq_pdt);
    if (op->do_list) {
        if (op->subpg_code_given)
            list_page_codes(inq_pdt, encserv, mchngr, op->subpg_code);
        else
            list_page_codes(inq_pdt, encserv, mchngr, -1);
        goto fini;
    }
    if (op->do_examine) {
        ret = examine_pages(sg_fd, inq_pdt, encserv, mchngr, op);
        goto fini;
    }
    if (PG_CODE_ALL == op->pg_code) {
        if (0 == op->do_all)
            ++op->do_all;
    } else if (op->do_all)
        op->pg_code = PG_CODE_ALL;
    if (op->do_all > 1)
        op->subpg_code = SPG_CODE_ALL;

    if (op->do_raw > 1) {
        if (op->do_all) {
            if (op->opt_new)
                pr2serr("'-R' requires a specific (sub)page, not all\n");
            else
                pr2serr("'-r' requires a specific (sub)page, not all\n");
            usage_for(op);
            ret = SG_LIB_CONTRADICT;
            goto fini;
        }
    }

    resid = 0;
    if (op->do_six) {
        res = sg_ll_mode_sense6(sg_fd, op->do_dbd, op->page_control,
                                op->pg_code, op->subpg_code, rsp_buff,
                                rsp_buff_sz, true, vb);
        if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr(">>>>>> try again without the '-6' switch for a 10 byte "
                    "MODE SENSE command\n");
    } else {
        res = sg_ll_mode_sense10_v2(sg_fd, op->do_llbaa, op->do_dbd,
                                    op->page_control, op->pg_code,
                                    op->subpg_code, rsp_buff, rsp_buff_sz,
                                    0, &resid, true, vb);
        if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr(">>>>>> try again with a '-6' switch for a 6 byte MODE "
                    "SENSE command\n");
    }
    if (SG_LIB_CAT_ILLEGAL_REQ == res) {
        if (op->subpg_code > 0)
            pr2serr("invalid field in cdb (perhaps subpages not "
                    "supported)\n");
        else if (op->page_control > 0)
            pr2serr("invalid field in cdb (perhaps page control (PC) not "
                    "supported)\n");
        else
            pr2serr("invalid field in cdb (perhaps page 0x%x not "
                    "supported)\n", op->pg_code);
    } else if (res) {
        sg_get_category_sense_str(res, sizeof(b), b, vb);
        pr2serr("%s\n", b);
    }
    ret = res;
    if (0 == res) {
        int medium_type, specific, headerlen;

        ret = 0;
        resp_mode6 = op->do_six;
        if (op->do_flexible) {
            num = rsp_buff[0];
            if (op->do_six && (num < 3))
                resp_mode6 = false;
            if ((! op->do_six) && (num > 5)) {
                if ((num > 11) && (0 == (num % 2)) && (0 == rsp_buff[4]) &&
                    (0 == rsp_buff[5]) && (0 == rsp_buff[6])) {
                    rsp_buff[1] = num;
                    rsp_buff[0] = 0;
                    pr2serr(">>> msense(10) but resp[0]=%d and not msense(6) "
                            "response so fix length\n", num);
                } else
                    resp_mode6 = true;
            }
        }
        cdbLenStr = resp_mode6 ? "6" : "10";
        if (op->do_raw || (1 == op->do_hex) || (op->do_hex > 2))
            ;
        else {
            if (resp_mode6 == op->do_six)
                printf("Mode parameter header from MODE SENSE(%s):\n",
                       cdbLenStr);
            else
                printf(" >>> Mode parameter header from MODE SENSE(%s),\n"
                       "     decoded as %s byte response:\n",
                       cdbLenStr, (resp_mode6 ? "6" : "10"));
        }
        rsp_buff_sz -= resid;
        if (rsp_buff_sz < 0) {
            pr2serr("MS(%s) resid=%d implies negative response length "
                    "(%d)\n", cdbLenStr, resid, rsp_buff_sz);
            ret = SG_LIB_WILD_RESID;
            goto fini;
        }
        if (resp_mode6) {
            if (rsp_buff_sz < 4) {
                pr2serr("MS(6) resid=%d implies abridged header length "
                        "(%d)\n", resid, rsp_buff_sz);
                ret = SG_LIB_WILD_RESID;
                goto fini;
            }
            headerlen = 4;
            medium_type = rsp_buff[1];
            specific = rsp_buff[2];
            longlba = false;
        } else {        /* MODE SENSE(10) with resid */
            if (rsp_buff_sz < 8) {
                pr2serr("MS(10) resid=%d implies abridged header length "
                        "(%d)\n", resid, rsp_buff_sz);
                ret = SG_LIB_WILD_RESID;
                goto fini;
            }
            headerlen = 8;
            medium_type = rsp_buff[2];
            specific = rsp_buff[3];
            longlba = !!(rsp_buff[4] & 1);
        }
        md_len = sg_msense_calc_length(rsp_buff, rsp_buff_sz, resp_mode6,
                                       &bd_len);
        if (md_len < 0) {
            pr2serr("MS(%s): sg_msense_calc_length() failed\n", cdbLenStr);
            ret = SG_LIB_CAT_MALFORMED;
            goto fini;
        }
        md_len = (md_len < rsp_buff_sz) ? md_len : rsp_buff_sz;
        if ((bd_len + headerlen) > md_len) {
            pr2serr("Invalid block descriptor length=%d, ignore\n", bd_len);
            bd_len = 0;
        }
        if (op->do_raw || (op->do_hex > 2)) {
            if (1 == op->do_raw)
                dStrRaw(rsp_buff, md_len);
            else if (op->do_raw > 1) {
                bp = rsp_buff + bd_len + headerlen;
                md_len -= bd_len + headerlen;
                spf = !!(bp[0] & 0x40);
                len = (spf ? (sg_get_unaligned_be16(bp + 2) + 4) :
                             (bp[1] + 2));
                len = (len < md_len) ? len : md_len;
                for (k = 0; k < len; ++k)
                    printf("%02x\n", bp[k]);
            } else
                hex2stdout(rsp_buff, md_len, -1);
            goto fini;
        }
        if (1 == op->do_hex) {
            hex2stdout(rsp_buff, md_len, 1);
            goto fini;
        } else if (op->do_hex > 1) {
            hex2stdout(rsp_buff, headerlen, 1);
            goto fini;
        }
        if ((PDT_DISK == inq_pdt) || (PDT_ZBC == inq_pdt))
            printf("  Mode data length=%d, medium type=0x%.2x, WP=%d,"
                   " DpoFua=%d, longlba=%d\n", md_len, medium_type,
                   !!(specific & 0x80), !!(specific & 0x10), (int)longlba);
        else
            printf("  Mode data length=%d, medium type=0x%.2x, specific"
                   " param=0x%.2x, longlba=%d\n", md_len, medium_type,
                   specific, (int)longlba);
        if (md_len > rsp_buff_sz) {
            printf("Only fetched %d bytes of response, truncate output\n",
                   rsp_buff_sz);
            md_len = rsp_buff_sz;
            if (bd_len + headerlen > rsp_buff_sz)
                bd_len = rsp_buff_sz - headerlen;
        }
        if (! op->do_dbout) {
            printf("  Block descriptor length=%d\n", bd_len);
            if (bd_len > 0) {
                len = 8;
                density_code_off = 0;
                num = bd_len;
                if (longlba) {
                    printf("> longlba direct access device block "
                           "descriptors:\n");
                    len = 16;
                    density_code_off = 8;
                }
                else if ((PDT_DISK == inq_pdt) || (PDT_ZBC == inq_pdt)) {
                    printf("> Direct access device block descriptors:\n");
                    density_code_off = 4;
                }
                else
                    printf("> General mode parameter block descriptors:\n");

                bp = rsp_buff + headerlen;
                while (num > 0) {
                    printf("   Density code=0x%x\n",
                           *(bp + density_code_off));
                    hex2stdout(bp, len, 1);
                    bp += len;
                    num -= len;
                }
                printf("\n");
            }
        }
        bp = rsp_buff + bd_len + headerlen;    /* start of mode page(s) */
        md_len -= bd_len + headerlen;           /* length of mode page(s) */
        num_ua_pages = 0;
        for (k = 0; md_len > 0; ++k) { /* got mode page(s) */
            if ((k > 0) && (! op->do_all) &&
                (SPG_CODE_ALL != op->subpg_code)) {
                pr2serr("Unexpectedly received extra mode page responses, "
                        "ignore\n");
                break;
            }
            uc = *bp;
            spf = !!(uc & 0x40);
            len = (spf ? (sg_get_unaligned_be16(bp + 2) + 4) : (bp[1] + 2));
            page_num = bp[0] & PG_CODE_MASK;
            if (0x0 == page_num) {
                ++num_ua_pages;
                if((num_ua_pages > 3) && (md_len > 0xa00)) {
                    pr2serr(">>> Seen 3 unit attention pages (only one "
                            "should be at end)\n     and mpage length=%d, "
                            "looks malformed, try '-f' option\n", md_len);
                    break;
                }
            }
            if (op->do_hex) {
                if (spf)
                    printf(">> page_code=0x%x, subpage_code=0x%x, page_cont"
                           "rol=%d\n", page_num, bp[1], op->page_control);
                else
                    printf(">> page_code=0x%x, page_control=%d\n", page_num,
                           op->page_control);
            } else {
                descp = NULL;
                if ((0x18 == page_num) || (0x19 == page_num)) {
                    t_proto = (spf ? bp[5] : bp[2]) & 0xf;
                    descp = find_page_code_desc(page_num, (spf ? bp[1] : 0),
                                                inq_pdt, encserv, mchngr,
                                                t_proto);
                } else
                    descp = find_page_code_desc(page_num, (spf ? bp[1] : 0),
                                                inq_pdt, encserv, mchngr, -1);
                if (NULL == descp) {
                    if (spf)
                        snprintf(ebuff, EBUFF_SZ, "0x%x, subpage_code: 0x%x",
                                 page_num, bp[1]);
                    else
                        snprintf(ebuff, EBUFF_SZ, "0x%x", page_num);
                }
                if (descp)
                    printf(">> %s, page_control: %s\n", descp,
                           pg_control_str_arr[op->page_control]);
                else
                    printf(">> page_code: %s, page_control: %s\n", ebuff,
                           pg_control_str_arr[op->page_control]);
            }
            num = (len > md_len) ? md_len : len;
            if ((k > 0) && (num > UNLIKELY_ABOVE_LEN)) {
                num = UNLIKELY_ABOVE_LEN;
                pr2serr(">>> page length (%d) > %d bytes, unlikely, trim\n"
                        "    Try '-f' option\n", len, num);
            }
            hex2stdout(bp, num , 1);
            bp += len;
            md_len -= len;
        }
    }

fini:
    if (sg_fd >= 0)
        sg_cmds_close_device(sg_fd);
    if (free_rsp_buff)
        free(free_rsp_buff);
    if (0 == vb) {
        if (! sg_if_can2stderr("sg_modes failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

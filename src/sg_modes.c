/*
 *  Copyright (C) 2000-2013 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
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
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"

static char * version_str = "1.41 20130301";

#define DEF_ALLOC_LEN (1024 * 4)
#define DEF_6_ALLOC_LEN 252
#define PG_CODE_ALL 0x3f
#define PG_CODE_MASK 0x3f
#define PG_CODE_MAX 0x3f
#define SPG_CODE_ALL 0xff
#define PROTO_SPECIFIC_1 0x18
#define PROTO_SPECIFIC_2 0x19

#define EBUFF_SZ 256


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
        {"six", no_argument, 0, '6'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_all;
    int do_dbd;
    int do_dbout;
    int do_examine;
    int do_flexible;
    int do_help;
    int do_hex;
    int do_list;
    int do_llbaa;
    int maxlen;
    int do_raw;
    int do_six;
    int do_verbose;
    int do_version;
    int page_control;
    int pg_code;
    int subpg_code;
    int subpg_code_set;
    const char * device_name;
    int opt_new;
};

static void
usage()
{
    printf("Usage: sg_modes [--all] [--control=PC] [--dbd] [--dbout] "
           "[--examine]\n"
           "                [--flexible] [--help] [--hex] [--list] "
           "[--llbaa]\n"
           "                [--maxlen=LEN] [--page=PG[,SPG]] [--raw] [-R] "
           "[--six]\n"
           "                [--verbose] [--version] [DEVICE]\n"
           "  where:\n"
           "    --all|-a        get all mode pages supported by device\n"
           "                    use twice to get all mode pages and subpages\n"
           "    --control=PC|-c PC    page control (default: 0)\n"
           "                       0: current, 1: changeable,\n"
           "                       2: (manufacturer's) defaults, "
           "3: saved\n"
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
           "    --page=PG|-p PG    page code to fetch (def: 63)\n"
           "    --page=PG,SPG|-p PG,SPG\n"
           "                       page code and subpage code to fetch "
           "(defs: 63,0)\n"
           "    --raw|-r        output response in binary to stdout\n"
           "    -R              mode page response to stdout, a byte per "
           "line in ASCII\n"
           "                    hex (same result as '--raw --raw')\n"
           "    --six|-6        use MODE SENSE(6), by default uses MODE "
           "SENSE(10)\n"
           "    --verbose|-v    increase verbosity\n"
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
           "   -p=PG     page code in hex (def: 3f)\n"
           "   -p=PG,SPG    both in hex, (defs: 3f,0)\n"
           "   -r    mode page output to stdout, a byte per line in "
           "ASCII hex\n"
           "   -subp=SPG    sub page code in hex (def: 0)\n"
           "   -v    verbose\n"
           "   -V    output version string\n"
           "   -6    Use MODE SENSE(6), by default uses MODE SENSE(10)\n"
           "   -?    output this usage message\n\n"
           "Performs a SCSI MODE SENSE (10 or 6) command\n");
}

static void
usage_for(const struct opts_t * optsp)
{
    if (optsp->opt_new)
        usage();
    else
        usage_old();
}

/* Processes command line options according to new option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
process_cl_new(struct opts_t * optsp, int argc, char * argv[])
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
            ++optsp->do_six;
            break;
        case 'a':
            ++optsp->do_all;
            break;
        case 'A':
            optsp->do_all += 2;
            break;
        case 'c':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 3)) {
                fprintf(stderr, "bad argument to '--control='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->page_control = n;
            break;
        case 'd':
            ++optsp->do_dbd;
            break;
        case 'D':
            ++optsp->do_dbout;
            break;
        case 'e':
            ++optsp->do_examine;
            break;
        case 'f':
            ++optsp->do_flexible;
            break;
        case 'h':
        case '?':
            ++optsp->do_help;
            break;
        case 'H':
            ++optsp->do_hex;
            break;
        case 'l':
            ++optsp->do_list;
            break;
        case 'L':
            ++optsp->do_llbaa;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 65535)) {
                fprintf(stderr, "bad argument to '--maxlen='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->maxlen = n;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            optsp->opt_new = 0;
            return 0;
        case 'p':
            cp = strchr(optarg, ',');
            n = sg_get_num_nomult(optarg);
            if ((n < 0) || (n > 63)) {
                fprintf(stderr, "Bad argument to '--page='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            if (cp) {
                nn = sg_get_num_nomult(cp + 1);
                if ((nn < 0) || (nn > 255)) {
                    fprintf(stderr, "Bad second value in argument to "
                            "'--page='\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->subpg_code = nn;
                optsp->subpg_code_set = 1;
            } else
                nn = 0;
            optsp->pg_code = n;
            break;
        case 'r':
            ++optsp->do_raw;
            break;
        case 'R':
            optsp->do_raw += 2;
            break;
        case 's':
            ++optsp->do_six;
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
            usage();
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
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

/* Processes command line options according to old option format. Returns
 * 0 is ok, else SG_LIB_SYNTAX_ERROR is returned. */
static int
process_cl_old(struct opts_t * optsp, int argc, char * argv[])
{
    int k, jmp_out, plen, num, n;
    unsigned int u, uu;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case '6':
                    ++optsp->do_six;
                    break;
                case 'a':
                    ++optsp->do_all;
                    break;
                case 'A':
                    optsp->do_all += 2;
                    break;
                case 'd':
                    ++optsp->do_dbd;
                    break;
                case 'D':
                    ++optsp->do_dbout;
                    break;
                case 'e':
                    ++optsp->do_examine;
                    break;
                case 'f':
                    ++optsp->do_flexible;
                    break;
                case 'h':
                case 'H':
                    optsp->do_hex += 2;
                    break;
                case 'l':
                    ++optsp->do_list;
                    break;
                case 'L':
                    ++optsp->do_llbaa;
                    break;
                case 'N':
                    optsp->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'r':
                    optsp->do_raw += 2;
                    break;
                case 'v':
                    ++optsp->do_verbose;
                    break;
                case 'V':
                    ++optsp->do_version;
                    break;
                case '?':
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
            if (0 == strncmp("c=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 3)) {
                    fprintf(stderr, "Bad page control after 'c=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->page_control = u;
            } else if (0 == strncmp("m=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &n);
                if ((1 != num) || (n < 0) || (n > 65535)) {
                    fprintf(stderr, "Bad argument after 'm=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->maxlen = n;
            } else if (0 == strncmp("p=", cp, 2)) {
                if (NULL == strchr(cp + 2, ',')) {
                    num = sscanf(cp + 2, "%x", &u);
                    if ((1 != num) || (u > 63)) {
                        fprintf(stderr, "Bad page code value after 'p=' "
                                "option\n");
                        usage_old();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    optsp->pg_code = u;
                } else if (2 == sscanf(cp + 2, "%x,%x", &u, &uu)) {
                    if (uu > 255) {
                        fprintf(stderr, "Bad sub page code value after 'p=' "
                                "option\n");
                        usage_old();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    optsp->pg_code = u;
                    optsp->subpg_code = uu;
                    optsp->subpg_code_set = 1;
                } else {
                    fprintf(stderr, "Bad page code, subpage code sequence "
                            "after 'p=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else if (0 == strncmp("subp=", cp, 5)) {
                num = sscanf(cp + 5, "%x", &u);
                if ((1 != num) || (u > 255)) {
                    fprintf(stderr, "Bad sub page code after 'subp=' "
                            "option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
                optsp->subpg_code = u;
                optsp->subpg_code_set = 1;
                if (-1 == optsp->pg_code)
                    optsp->pg_code = 0;
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == optsp->device_name)
            optsp->device_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", optsp->device_name, cp);
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

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}


struct page_code_desc {
    int page_code;
    int subpage_code;
    const char * desc;
};

static struct page_code_desc pc_desc_common[] = {
    {0x0, 0x0, "Unit Attention condition [vendor specific format]"},
    {0x2, 0x0, "Disconnect-Reconnect"},
    {0x9, 0x0, "Peripheral device (obsolete)"},
    {0xa, 0x0, "Control"},
    {0xa, 0x1, "Control extension"},
    {0x15, 0x0, "Extended"},
    {0x16, 0x0, "Extended device-type specific"},
    {0x18, 0x0, "Protocol specific lu"},
    {0x19, 0x0, "Protocol specific port"},
    {0x1a, 0x0, "Power condition"},
    {0x1a, 0x1, "Power consumption"},
    {0x1c, 0x0, "Informational exceptions control"},
    {PG_CODE_ALL, 0x0, "[yields all supported pages]"},
    {PG_CODE_ALL, SPG_CODE_ALL, "[yields all supported pages and subpages]"},
};

static struct page_code_desc pc_desc_disk[] = {
    {0x1, 0x0, "Read-Write error recovery"},
    {0x3, 0x0, "Format (obsolete)"},
    {0x4, 0x0, "Rigid disk geometry (obsolete)"},
    {0x5, 0x0, "Flexible geometry (obsolete)"},
    {0x7, 0x0, "Verify error recovery"},
    {0x8, 0x0, "Caching"},
    {0xa, 0x02, "Application tag"},
    {0xa, 0xf1, "Parallel ATA control (SAT)"},
    {0xa, 0xf2, "Reserved (SATA control) (SAT)"},
    {0xb, 0x0, "Medium types supported (obsolete)"},
    {0xc, 0x0, "Notch and partition (obsolete)"},
    {0xd, 0x0, "Power condition (obsolete, moved to 0x1a)"},
    {0x10, 0x0, "XOR control"}, /* obsolete in sbc3r32 */
    {0x1a, 0xf1, "ATA Power condition"},
    {0x1c, 0x1, "Background control"},
    {0x1c, 0x2, "Logical block provisioning"},
};

static struct page_code_desc pc_desc_tape[] = {
    {0x1, 0x0, "Read-Write error recovery"},
    {0xa, 0xf0, "Control data protection"},
    {0xf, 0x0, "Data Compression"},
    {0x10, 0x0, "Device configuration"},
    {0x10, 0x1, "Device configuration extension"},
    {0x11, 0x0, "Medium Partition [1]"},
    {0x12, 0x0, "Medium Partition [2]"},
    {0x13, 0x0, "Medium Partition [3]"},
    {0x14, 0x0, "Medium Partition [4]"},
    {0x1c, 0x0, "Informational exceptions control (tape version)"},
    {0x1d, 0x0, "Medium configuration"},
};

static struct page_code_desc pc_desc_cddvd[] = {
    {0x1, 0x0, "Read-Write error recovery"},
    {0x3, 0x0, "MRW"},
    {0x5, 0x0, "Write parameters"},
    {0x7, 0x0, "Verify error recovery"},
    {0x8, 0x0, "Caching"},
    {0xd, 0x0, "CD device parameters (obsolete)"},
    {0xe, 0x0, "CD audio"},
    {0x1a, 0x0, "Power condition (mmc)"},
    {0x1c, 0x0, "Fault/failure reporting control (mmc)"},
    {0x1d, 0x0, "Timeout and protect"},
    {0x2a, 0x0, "MM capabilities and mechanical status (obsolete)"},
};

static struct page_code_desc pc_desc_smc[] = {
    {0x1d, 0x0, "Element address assignment"},
    {0x1e, 0x0, "Transport geometry parameters"},
    {0x1f, 0x0, "Device capabilities"},
    {0x1f, 0x41, "Extended device capabilities"},
};

static struct page_code_desc pc_desc_scc[] = {
    {0x1b, 0x0, "LUN mapping"},
};

static struct page_code_desc pc_desc_ses[] = {
    {0x14, 0x0, "Enclosure services management"},
};

static struct page_code_desc pc_desc_rbc[] = {
    {0x6, 0x0, "RBC device parameters"},
};

static struct page_code_desc pc_desc_adc[] = {
    /* {0xe, 0x0, "ADC device configuration"}, */
    {0xe, 0x1, "Target device"},
    {0xe, 0x2, "DT device primary port"},
    {0xe, 0x3, "Logical unit"},
    {0xe, 0x4, "Target device serial number"},
};

static struct page_code_desc *
mode_page_cs_table(int scsi_ptype, int * size)
{
    switch (scsi_ptype)
    {
        case -1:        /* common list */
            *size = sizeof(pc_desc_common) / sizeof(pc_desc_common[0]);
            return &pc_desc_common[0];
        case PDT_DISK:         /* disk (direct access) type devices */
        case PDT_WO:
        case PDT_OPTICAL:
            *size = sizeof(pc_desc_disk) / sizeof(pc_desc_disk[0]);
            return &pc_desc_disk[0];
        case PDT_TAPE:         /* tape devices */
        case PDT_PRINTER:
            *size = sizeof(pc_desc_tape) / sizeof(pc_desc_tape[0]);
            return &pc_desc_tape[0];
        case PDT_MMC:         /* cd/dvd/bd devices */
            *size = sizeof(pc_desc_cddvd) / sizeof(pc_desc_cddvd[0]);
            return &pc_desc_cddvd[0];
        case PDT_MCHANGER:         /* medium changer devices */
            *size = sizeof(pc_desc_smc) / sizeof(pc_desc_smc[0]);
            return &pc_desc_smc[0];
        case PDT_SAC:       /* storage array devices */
            *size = sizeof(pc_desc_scc) / sizeof(pc_desc_scc[0]);
            return &pc_desc_scc[0];
        case PDT_SES:       /* enclosure services devices */
            *size = sizeof(pc_desc_ses) / sizeof(pc_desc_ses[0]);
            return &pc_desc_ses[0];
        case PDT_RBC:       /* simplified direct access device */
            *size = sizeof(pc_desc_rbc) / sizeof(pc_desc_rbc[0]);
            return &pc_desc_rbc[0];
        case PDT_ADC:       /* automation device/interface */
            *size = sizeof(pc_desc_adc) / sizeof(pc_desc_adc[0]);
            return &pc_desc_adc[0];
    }
    *size = 0;
    return NULL;
}

static struct page_code_desc pc_desc_t_fcp[] = {
    {0x18, 0x0, "LU control"},
    {0x19, 0x0, "Port control"},
};

static struct page_code_desc pc_desc_t_spi4[] = {
    {0x18, 0x0, "LU control"},
    {0x19, 0x0, "Port control short format"},
    {0x19, 0x1, "Margin control"},
    {0x19, 0x2, "Saved training configuration value"},
    {0x19, 0x3, "Negotiated settings"},
    {0x19, 0x4, "Report transfer capabilities"},
};

static struct page_code_desc pc_desc_t_sas[] = {
    {0x18, 0x0, "Protocol specific logical unit (SAS)"},
    {0x19, 0x0, "Protocol specific port (SAS)"},
    {0x19, 0x1, "Phy control and discover (SAS)"},
    {0x19, 0x2, "Shared port control (SAS)"},
    {0x19, 0x3, "Enhanced phy control (SAS)"},
};

static struct page_code_desc pc_desc_t_adc[] = {
    {0xe, 0x1, "Target device"},
    {0xe, 0x2, "DT device primary port"},
    {0xe, 0x3, "Logical unit"},
    {0x18, 0x0, "Protocol specific lu"},
    {0x19, 0x0, "Protocol specific port"},
};

static struct page_code_desc *
mode_page_transp_table(int t_proto, int * size)
{
    switch (t_proto)
    {
        case TPROTO_FCP:
            *size = sizeof(pc_desc_t_fcp) / sizeof(pc_desc_t_fcp[0]);
            return &pc_desc_t_fcp[0];
        case TPROTO_SPI:
            *size = sizeof(pc_desc_t_spi4) / sizeof(pc_desc_t_spi4[0]);
            return &pc_desc_t_spi4[0];
        case TPROTO_SAS:
            *size = sizeof(pc_desc_t_sas) / sizeof(pc_desc_t_sas[0]);
            return &pc_desc_t_sas[0];
        case TPROTO_ADT:
            *size = sizeof(pc_desc_t_adc) / sizeof(pc_desc_t_adc[0]);
            return &pc_desc_t_adc[0];
    }
    *size = 0;
    return NULL;
}

static const char *
find_page_code_desc(int page_num, int subpage_num, int scsi_ptype,
                    int inq_byte6, int t_proto)
{
    int k;
    int num;
    const struct page_code_desc * pcdp;

    if (t_proto >= 0) {
        pcdp = mode_page_transp_table(t_proto, &num);
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
    pcdp = mode_page_cs_table(scsi_ptype, &num);
    if (pcdp) {
        for (k = 0; k < num; ++k, ++pcdp) {
            if ((page_num == pcdp->page_code) &&
                (subpage_num == pcdp->subpage_code))
                return pcdp->desc;
            else if (page_num < pcdp->page_code)
                break;
        }
    }
    if ((0xd != scsi_ptype) && (inq_byte6 & 0x40)) {
        /* check for attached enclosure services processor */
        pcdp = mode_page_cs_table(0xd, &num);
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
    if ((0x8 != scsi_ptype) && (inq_byte6 & 0x8)) {
        /* check for attached medium changer device */
        pcdp = mode_page_cs_table(0x8, &num);
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
    pcdp = mode_page_cs_table(-1, &num);
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
list_page_codes(int scsi_ptype, int inq_byte6, int t_proto)
{
    int num, num_ptype, pg, spg, c, d, valid_transport;
    const struct page_code_desc * dp;
    const struct page_code_desc * pe_dp;
    char b[64];

    valid_transport = ((t_proto >= 0) && (t_proto <= 0xf)) ? 1 : 0;
    printf("Page[,subpage]   Name\n");
    printf("=====================\n");
    dp = mode_page_cs_table(-1, &num);
    pe_dp = mode_page_cs_table(scsi_ptype, &num_ptype);
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
            if (pe_dp->subpage_code)
                printf(" 0x%02x,0x%02x    *  %s\n", pe_dp->page_code,
                       pe_dp->subpage_code, pe_dp->desc);
            else
                printf(" 0x%02x         *  %s\n", pe_dp->page_code,
                       pe_dp->desc);
            dp = (--num <= 0) ? NULL : (dp + 1);
            pe_dp = (--num_ptype <= 0) ? NULL : (pe_dp + 1);
        } else if (c < d) {
            if (dp->subpage_code)
                printf(" 0x%02x,0x%02x       %s\n", dp->page_code,
                       dp->subpage_code, dp->desc);
            else
                printf(" 0x%02x            %s\n", dp->page_code,
                       dp->desc);
            dp = (--num <= 0) ? NULL : (dp + 1);
        } else {
            if (pe_dp->subpage_code)
                printf(" 0x%02x,0x%02x       %s\n", pe_dp->page_code,
                       pe_dp->subpage_code, pe_dp->desc);
            else
                printf(" 0x%02x            %s\n", pe_dp->page_code,
                       pe_dp->desc);
            pe_dp = (--num_ptype <= 0) ? NULL : (pe_dp + 1);
        }
        if ((NULL == dp) && (NULL == pe_dp))
            break;
    }
    if ((0xd != scsi_ptype) && (inq_byte6 & 0x40)) {
        /* check for attached enclosure services processor */
        printf("\n    Attached enclosure services processor\n");
        dp = mode_page_cs_table(0xd, &num);
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
    if ((0x8 != scsi_ptype) && (inq_byte6 & 0x8)) {
        /* check for attached medium changer device */
        printf("\n    Attached medium changer device\n");
        dp = mode_page_cs_table(0x8, &num);
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
        dp = mode_page_transp_table(t_proto, &num);
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

static int
examine_pages(int sg_fd, int inq_pdt, int inq_byte6,
              const struct opts_t * optsp)
{
    int k, res, header, mresp_len, len;
    unsigned char rbuf[256];
    const char * cp;

    mresp_len = (optsp->do_raw || optsp->do_hex) ? sizeof(rbuf) : 4;
    for (header = 0, k = 0; k < PG_CODE_MAX; ++k) {
        if (optsp->do_six) {
            res = sg_ll_mode_sense6(sg_fd, 0, 0, k, 0, rbuf, mresp_len,
                                    1, optsp->do_verbose);
            if (SG_LIB_CAT_INVALID_OP == res) {
                fprintf(stderr, ">>>>>> try again without the '-6' "
                        "switch for a 10 byte MODE SENSE command\n");
                return res;
            } else if (SG_LIB_CAT_NOT_READY == res) {
                fprintf(stderr, "MODE SENSE (6) failed, device not ready\n");
                return res;
            }
        } else {
            res = sg_ll_mode_sense10(sg_fd, 0, 0, 0, k, 0, rbuf, mresp_len,
                                     1, optsp->do_verbose);
            if (SG_LIB_CAT_INVALID_OP == res) {
                fprintf(stderr, ">>>>>> try again with a '-6' "
                        "switch for a 6 byte MODE SENSE command\n");
                return res;
            } else if (SG_LIB_CAT_NOT_READY == res) {
                fprintf(stderr, "MODE SENSE (10) failed, device not ready\n");
                return res;
            }
        }
        if (0 == res) {
            len = optsp->do_six ? (rbuf[0] + 1) :
                                  ((rbuf[0] << 8) + rbuf[1] + 2);
            if (len > mresp_len)
                len = mresp_len;
            if (optsp->do_raw) {
                dStrRaw((const char *)rbuf, len);
                continue;
            }
            if (0 == header) {
                printf("Discovered mode pages:\n");
                header = 1;
            }
            cp = find_page_code_desc(k, 0, inq_pdt, inq_byte6, -1);
            if (cp)
                printf("    %s\n", cp);
            else
                printf("    [0x%x]\n", k);
            if (optsp->do_hex)
                dStrHex((const char *)rbuf, len, 1);
        }
    }
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
    int sg_fd, k, num, len, res, md_len, bd_len, longlba, page_num, spf;
    char ebuff[EBUFF_SZ];
    const char * descp;
    unsigned char * rsp_buff = NULL;
    unsigned char def_rsp_buff[DEF_ALLOC_LEN];
    unsigned char * malloc_rsp_buff = NULL;
    int rsp_buff_size = DEF_ALLOC_LEN;
    int ret = 0;
    int density_code_off, t_proto, inq_pdt, inq_byte6, resp_mode6;
    int num_ua_pages;
    unsigned char * ucp;
    unsigned char uc;
    struct sg_simple_inquiry_resp inq_out;
    char pdt_name[64];
    struct opts_t opts;

    memset(&opts, 0, sizeof(opts));
    opts.pg_code = -1;
    res = process_cl(&opts, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (opts.do_help) {
        usage_for(&opts);
        return 0;
    }
    if (opts.do_version) {
        fprintf(stderr, "Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == opts.device_name) {
        if (opts.do_list) {
            if ((opts.pg_code < 0) || (opts.pg_code > PG_CODE_MAX)) {
                printf("    Assume peripheral device type: disk\n");
                list_page_codes(0, 0, -1);
            } else {
                printf("    peripheral device type: %s\n",
                       sg_get_pdt_str(opts.pg_code, sizeof(pdt_name),
                                      pdt_name));
                if (opts.subpg_code_set)
                    list_page_codes(opts.pg_code, 0, opts.subpg_code);
                else
                    list_page_codes(opts.pg_code, 0, -1);
            }
            return 0;
        }
        fprintf(stderr, "No DEVICE argument given\n");
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }

    if (opts.do_examine && (opts.pg_code >= 0)) {
        fprintf(stderr, "can't give '-e' and a page number\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((opts.do_six) && (opts.do_llbaa)) {
        fprintf(stderr, "LLBAA not defined for MODE SENSE 6, try "
                "without '-L'\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.maxlen > 0) {
        if (opts.do_six && (opts.maxlen > 255)) {
            fprintf(stderr, "For Mode Sense (6) maxlen cannot exceed "
                    "255\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (opts.maxlen > DEF_ALLOC_LEN) {
            malloc_rsp_buff = malloc(opts.maxlen);
            if (NULL == malloc_rsp_buff) {
                fprintf(stderr, "Unable to malloc maxlen=%d bytes\n",
                        opts.maxlen);
                return SG_LIB_SYNTAX_ERROR;
            }
            rsp_buff = malloc_rsp_buff;
        } else
            rsp_buff = def_rsp_buff;
        rsp_buff_size = opts.maxlen;
    } else {    /* maxlen == 0 */
        rsp_buff_size = opts.do_six ? DEF_6_ALLOC_LEN : DEF_ALLOC_LEN;
        rsp_buff = def_rsp_buff;
    }
    /* If no pages or list selected than treat as 'a' */
    if (! ((opts.pg_code >= 0) || opts.do_all || opts.do_list ||
            opts.do_examine))
        opts.do_all = 1;

    if (opts.do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if ((sg_fd = sg_cmds_open_device(opts.device_name, 1 /* ro */,
                                     opts.do_verbose)) < 0) {
        fprintf(stderr, "error opening file: %s: %s\n",
                opts.device_name, safe_strerror(-sg_fd));
        if (malloc_rsp_buff)
            free(malloc_rsp_buff);
        return SG_LIB_FILE_ERROR;
    }

    if (sg_simple_inquiry(sg_fd, &inq_out, 1, opts.do_verbose)) {
        fprintf(stderr, "%s doesn't respond to a SCSI INQUIRY\n",
                opts.device_name);
        ret = SG_LIB_CAT_OTHER;
        goto finish;
    }
    inq_pdt = inq_out.peripheral_type;
    inq_byte6 = inq_out.byte_6;
    if (0 == opts.do_raw)
        printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n",
               inq_out.vendor, inq_out.product, inq_out.revision,
               sg_get_pdt_str(inq_pdt, sizeof(pdt_name), pdt_name), inq_pdt);
    if (opts.do_list) {
        if (opts.subpg_code_set)
            list_page_codes(inq_pdt, inq_byte6, opts.subpg_code);
        else
            list_page_codes(inq_pdt, inq_byte6, -1);
        goto finish;
    }
    if (opts.do_examine) {
        ret = examine_pages(sg_fd, inq_pdt, inq_byte6, &opts);
        goto finish;
    }
    if (PG_CODE_ALL == opts.pg_code) {
        if (0 == opts.do_all)
            ++opts.do_all;
    } else if (opts.do_all)
        opts.pg_code = PG_CODE_ALL;
    if (opts.do_all > 1)
        opts.subpg_code = SPG_CODE_ALL;

    if (opts.do_raw > 1) {
        if (opts.do_all) {
            if (opts.opt_new)
                fprintf(stderr, "'-R' requires a specific (sub)page, not "
                        "all\n");
            else
                fprintf(stderr, "'-r' requires a specific (sub)page, not "
                        "all\n");
            usage_for(&opts);
            ret = SG_LIB_SYNTAX_ERROR;
            goto finish;
        }
    }

    memset(rsp_buff, 0, sizeof(rsp_buff));
    if (opts.do_six) {
        res = sg_ll_mode_sense6(sg_fd, opts.do_dbd, opts.page_control,
                                opts.pg_code, opts.subpg_code, rsp_buff,
                                rsp_buff_size, 1, opts.do_verbose);
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, ">>>>>> try again without the '-6' "
                    "switch for a 10 byte MODE SENSE command\n");
    } else {
        res = sg_ll_mode_sense10(sg_fd, opts.do_llbaa, opts.do_dbd,
                                 opts.page_control, opts.pg_code,
                                 opts.subpg_code, rsp_buff, rsp_buff_size,
                                 1, opts.do_verbose);
        if (SG_LIB_CAT_INVALID_OP == res)
            fprintf(stderr, ">>>>>> try again with a '-6' "
                    "switch for a 6 byte MODE SENSE command\n");
    }
    if (SG_LIB_CAT_ILLEGAL_REQ == res) {
        if (opts.subpg_code > 0)
            fprintf(stderr, "invalid field in cdb (perhaps subpages "
                    "not supported)\n");
        else if (opts.page_control > 0)
            fprintf(stderr, "invalid field in cdb (perhaps "
                    "page control (PC) not supported)\n");
        else
            fprintf(stderr, "invalid field in cdb (perhaps "
                "page 0x%x not supported)\n", opts.pg_code);
    } else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "device not ready\n");
    else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        fprintf(stderr, "unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "aborted command\n");
    ret = res;
    if (0 == res) {
        int medium_type, specific, headerlen;

        ret = 0;
        resp_mode6 = opts.do_six;
        if (opts.do_flexible) {
            num = rsp_buff[0];
            if (opts.do_six && (num < 3))
                resp_mode6 = 0;
            if ((0 == opts.do_six) && (num > 5)) {
                if ((num > 11) && (0 == (num % 2)) && (0 == rsp_buff[4]) &&
                    (0 == rsp_buff[5]) && (0 == rsp_buff[6])) {
                    rsp_buff[1] = num;
                    rsp_buff[0] = 0;
                    fprintf(stderr, ">>> msense(10) but resp[0]=%d and "
                            "not msense(6) response so fix length\n", num);
                } else
                    resp_mode6 = 1;
            }
        }
        if ((! opts.do_raw) && (1 != opts.do_hex)) {
            if (resp_mode6 == opts.do_six)
                printf("Mode parameter header from MODE SENSE(%s):\n",
                       (opts.do_six ? "6" : "10"));
            else
                printf(" >>> Mode parameter header from MODE SENSE(%s),\n"
                       "     decoded as %s byte response:\n",
                       (opts.do_six ? "6" : "10"), (resp_mode6 ? "6" : "10"));
        }
        if (resp_mode6) {
            headerlen = 4;
            md_len = rsp_buff[0] + 1;
            bd_len = rsp_buff[3];
            medium_type = rsp_buff[1];
            specific = rsp_buff[2];
            longlba = 0;
        } else {
            headerlen = 8;
            md_len = (rsp_buff[0] << 8) + rsp_buff[1] + 2;
            bd_len = (rsp_buff[6] << 8) + rsp_buff[7];
            medium_type = rsp_buff[2];
            specific = rsp_buff[3];
            longlba = rsp_buff[4] & 1;
        }
        if ((bd_len + headerlen) > md_len) {
            fprintf(stderr, "Invalid block descriptor length=%d, ignore\n",
                    bd_len);
            bd_len = 0;
        }
        if (opts.do_raw) {
            if (1 == opts.do_raw)
                dStrRaw((const char *)rsp_buff, md_len);
            else {
                ucp = rsp_buff + bd_len + headerlen;
                md_len -= bd_len + headerlen;
                spf = ((ucp[0] & 0x40) ? 1 : 0);
                len = (spf ? ((ucp[2] << 8) + ucp[3] + 4) : (ucp[1] + 2));
                len = (len < md_len) ? len : md_len;
                for (k = 0; k < len; ++k)
                    printf("%02x\n", ucp[k]);
            }
            goto finish;
        }
        if (1 == opts.do_hex) {
            dStrHex((const char *)rsp_buff, md_len, 1);
            goto finish;
        } else if (opts.do_hex > 1)
            dStrHex((const char *)rsp_buff, headerlen, 1);
        if (0 == inq_pdt)
            printf("  Mode data length=%d, medium type=0x%.2x, WP=%d,"
                   " DpoFua=%d, longlba=%d\n", md_len, medium_type,
                   !!(specific & 0x80), !!(specific & 0x10), longlba);
        else
            printf("  Mode data length=%d, medium type=0x%.2x, specific"
                   " param=0x%.2x, longlba=%d\n", md_len, medium_type,
                   specific, longlba);
        if (md_len > rsp_buff_size) {
            printf("Only fetched %d bytes of response, truncate output\n",
                   rsp_buff_size);
            md_len = rsp_buff_size;
            if (bd_len + headerlen > rsp_buff_size)
                bd_len = rsp_buff_size - headerlen;
        }
        if (! opts.do_dbout) {
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
                else if (0 == inq_pdt) {
                    printf("> Direct access device block descriptors:\n");
                    density_code_off = 4;
                }
                else
                    printf("> General mode parameter block descriptors:\n");

                ucp = rsp_buff + headerlen;
                while (num > 0) {
                    printf("   Density code=0x%x\n",
                           *(ucp + density_code_off));
                    dStrHex((const char *)ucp, len, 1);
                    ucp += len;
                    num -= len;
                }
                printf("\n");
            }
        }
        ucp = rsp_buff + bd_len + headerlen;    /* start of mode page(s) */
        md_len -= bd_len + headerlen;           /* length of mode page(s) */
        num_ua_pages = 0;
        for (k = 0; md_len > 0; ++k) { /* got mode page(s) */
            if ((k > 0) && (! opts.do_all) &&
                (SPG_CODE_ALL != opts.subpg_code)) {
                fprintf(stderr, "Unexpectedly received extra mode page "
                                "responses, ignore\n");
                break;
            }
            uc = *ucp;
            spf = ((uc & 0x40) ? 1 : 0);
            len = (spf ? ((ucp[2] << 8) + ucp[3] + 4) : (ucp[1] + 2));
            page_num = ucp[0] & PG_CODE_MASK;
            if (0x0 == page_num) {
                ++num_ua_pages;
                if((num_ua_pages > 3) && (md_len > 0xa00)) {
                    fprintf(stderr, ">>> Seen 3 unit attention pages "
                            "(only one should be at end)\n     and mpage "
                            "length=%d, looks malformed, try '-f' option\n",
                            md_len);
                    break;
                }
            }
            if (opts.do_hex) {
                if (spf)
                    printf(">> page_code=0x%x, subpage_code=0x%x, page_cont"
                           "rol=%d\n", page_num, ucp[1], opts.page_control);
                else
                    printf(">> page_code=0x%x, page_control=%d\n", page_num,
                           opts.page_control);
            } else {
                descp = NULL;
                if ((0x18 == page_num) || (0x19 == page_num)) {
                    t_proto = (spf ? ucp[5] : ucp[2]) & 0xf;
                    descp = find_page_code_desc(page_num, (spf ? ucp[1] : 0),
                                                inq_pdt, inq_byte6, t_proto);
                } else
                    descp = find_page_code_desc(page_num, (spf ? ucp[1] : 0),
                                                inq_pdt, inq_byte6, -1);
                if (NULL == descp) {
                    if (spf)
                        snprintf(ebuff, EBUFF_SZ, "0x%x, subpage_code: 0x%x",
                                 page_num, ucp[1]);
                    else
                        snprintf(ebuff, EBUFF_SZ, "0x%x", page_num);
                }
                if (descp)
                    printf(">> %s, page_control: %s\n", descp,
                           pg_control_str_arr[opts.page_control]);
                else
                    printf(">> page_code: %s, page_control: %s\n", ebuff,
                           pg_control_str_arr[opts.page_control]);
            }
            num = (len > md_len) ? md_len : len;
            if ((k > 0) && (num > 256)) {
                num = 256;
                fprintf(stderr, ">>> page length (%d) > 256 bytes, unlikely "
                                "trim\n    Try '-f' option\n", len);
            }
            dStrHex((const char *)ucp, num , 1);
            ucp += len;
            md_len -= len;
        }
    }

finish:
    sg_cmds_close_device(sg_fd);
    if (malloc_rsp_buff)
        free(malloc_rsp_buff);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

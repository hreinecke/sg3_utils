/*
 * Copyright (c) 2017 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * The utility can send six variants of the SCSI WRITE command: (normal)
 * WRITE(16 or 32), WRITE ATOMIC(16 or 32), ORWRITE(16 or 32),
 * WRITE SAME(16 or 32), WRITE SCATTERED (16 or 32) or WRITE
 * STREAM(16 or 32).
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>  /* needed for lseek() */
#include <sys/stat.h>
#include <sys/param.h>  /* contains PAGE_SIZE */
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.05 20171127";


#define ME "sg_write_x: "

#define ORWRITE16_OP 0x8b
#define WRITE_16_OP 0x8a
#define WRITE_ATOMIC16_OP 0x9c
#define WRITE_SAME16_OP 0x93
#define SERVICE_ACTION_OUT_16_OP 0x9f   /* WRITE SCATTERED (16) uses this */
#define WRITE_SCATTERED16_SA 0x12
#define WRITE_STREAM16_OP 0x9a
#define VARIABLE_LEN_OP 0x7f
#define ORWRITE32_SA 0xe
#define WRITE_32_SA 0xb
#define WRITE_ATOMIC32_SA 0xf
#define WRITE_SAME_SA 0xd
#define WRITE_SCATTERED32_SA 0x11
#define WRITE_STREAM32_SA 0x10
#define WRITE_X_16_LEN 16
#define WRITE_X_32_LEN 32
#define WRITE_X_32_ADD 0x18
#define RCAP10_RESP_LEN 8
#define RCAP16_RESP_LEN 32
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_TIMEOUT_SECS 120    /* might need more for large NUM */
#define DEF_WR_NUMBLOCKS 0      /* do nothing; for safety */
#define DEF_RT 0xffffffff
#define DEF_AT 0xffff
#define DEF_TM 0xffff
#define MAX_XFER_LEN (64 * 1024)
#define EBUFF_SZ 256

#define MAX_NUM_ADDR 128

#ifndef UINT32_MAX
#define UINT32_MAX ((uint32_t)-1)
#endif
#ifndef UINT16_MAX
#define UINT16_MAX ((uint16_t)-1)
#endif

static struct option long_options[] = {
    {"32", no_argument, 0, '3'},
    {"16", no_argument, 0, '6'},
    {"app-tag", required_argument, 0, 'a'},
    {"app_tag", required_argument, 0, 'a'},
    {"atomic", required_argument, 0, 'A'},
    {"bmop", required_argument, 0, 'B'},
    {"bs", required_argument, 0, 'b'},
    {"combined", required_argument, 0, 'c'},
    {"dld", required_argument, 0, 'D'},
    {"dpo", no_argument, 0, 'd'},
    {"dry-run", no_argument, 0, 'x'},
    {"dry_run", no_argument, 0, 'x'},
    {"fua", no_argument, 0, 'f'},
    {"grpnum", required_argument, 0, 'g'},
    {"generation", required_argument, 0, 'G'},
    {"help", no_argument, 0, 'h'},
    {"in", required_argument, 0, 'i'},
    {"lba", required_argument, 0, 'l'},
    {"normal", no_argument, 0, 'N'},
    {"num", required_argument, 0, 'n'},
    {"offset", required_argument, 0, 'o'},
    {"or", no_argument, 0, 'O'},
    {"raw", no_argument, 0, 'r'},
    {"ref-tag", required_argument, 0, 'R'},
    {"ref_tag", required_argument, 0, 'R'},
    {"same", required_argument, 0, 'M'},
    {"scat-file", required_argument, 0, 'q'},
    {"scat_file", required_argument, 0, 'q'},
    {"scattered", required_argument, 0, 'S'},
    {"stream", required_argument, 0, 'T'},
    {"strict", no_argument, 0, 's'},
    {"tag-mask", required_argument, 0, 't'},
    {"tag_mask", required_argument, 0, 't'},
    {"timeout", required_argument, 0, 'I'},
    {"unmap", required_argument, 0, 'u'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"wrprotect", required_argument, 0, 'w'},
    {0, 0, 0, 0},
};

struct opts_t {
    bool do_16;
    bool do_32;
    bool do_anchor;
    bool do_atomic;             /* -A  WRITE ATOMIC(16 or 32) */
                                /*  --atomic=AB  AB --> .atomic_boundary */
    bool do_combined;           /* -c DOF --> .scat_lbdof */
    bool do_dry_run;
    bool do_or;                 /* -O  ORWRITE(16 or 32) */
    bool do_raw;
    bool do_same;               /* -M  WRITE SAME(16 or 32) */
                                /*  --same=NDOB  NDOB --> .ndob */
    bool do_scattered;          /* -S  WRITE SCATTERED(16 or 32) */
                                /*  --scattered=RD  RD --> .scat_num_lbard */
    bool do_stream;             /* -T  WRITE STREAM(16 or 32) */
                                /*  --stream=ID  ID --> .str_id */
    bool do_unmap;
    bool do_write_normal;       /* -N  WRITE (16 or 32) */
    bool expect_pi_do;          /* expect protection information (PI) which
                                 * is 8 bytes long following each logical
                                 * block in the data out buffer. */
    bool dpo;
    bool fua;
    bool ndob;
    bool strict;
    int dld;            /* only used by WRITE(16) [why not WRITE(32) ?] */
    int grpnum;
    int help;
    int pi_type;        /* -1: unknown: 0: type 0 (none): 1: type 1 */
    int timeout;
    int verbose;
    int wrprotect;      /* is ORPROTECT field for ORWRITE */
    uint8_t bmop;       /* bit mask operators for ORWRITE(32) */
    uint8_t pgp;        /* previous generation processing for ORWRITE(32) */
    uint16_t app_tag;   /* part of protection information (def: 0xffff) */
    uint16_t atomic_boundary;
    uint16_t scat_lbdof;
    uint16_t scat_num_lbard;
    uint16_t str_id;    /* (stream ID) is for WRITE STREAM */
    uint16_t tag_mask;  /* part of protection information (def: 0xffff) */
    uint32_t bs;        /* logical block size (def: 0). 0 implies use READ
                         * CAPACITY(10 or 16) to determine */
    uint32_t bs_pi_do;  /* logical block size plus PI, if any */
    uint32_t numblocks;
    uint32_t orw_eog;
    uint32_t orw_nog;
    uint32_t ref_tag;   /* part of protection information (def: 0xffffffff) */
    uint64_t lba;
    uint64_t offset;    /* byte offset in if_name to start reading */
    uint64_t dlen;    /* bytes to read after offset from if_name, 0->rest */
    uint64_t tot_lbs;   /* from READ CAPACITY */
    ssize_t xfer_bytes;     /* derived value: bs_pi_do * numblocks */
    const char * device_name;
    const char * if_name;
    const char * scat_filename;
    const char * cmd_name;      /* e.g. 'Write atomic' */
    char cdb_name[24];          /* e.g. 'Write atomic (16)' */
};


static void
usage(int do_help)
{
    if (do_help < 2) {
        pr2serr("Usage:\n"
            "sg_write_x [--16] [--32] [--app-tag=AT] [--atomic=AB] "
            "[--bmop=OP,PGP]\n"
            "           [--bs=LBS] [--combined=DOF] [--dld=DLD] [--dpo] "
            "[--dry-run]\n"
            "           [--fua] [--generation=EOG,NOG] [--grpnum=GN] "
            "[--help] --in=IF\n"
            "           [--lba=LBA,LBA...] [--normal] [--num=NUM,NUM...]\n"
            "           [--offset=OFF[,DLEN]] [--or] [--raw] [--ref-tag=RT] "
            "[--same=NDOB]\n"
            "           [--scat-file=SF] [--scattered=RD] [--stream=ID] "
            "[--strict]\n"
            "           [--tag-mask=TM] [--timeout=TO] [--unmap=U_A] "
            "[--verbose]\n"
            "           [--version] [--wrprotect=WRP] DEVICE\n");
        if (1 != do_help) {
            pr2serr("\nOr the corresponding short option usage:\n"
                "sg_write_x [-6] [-3] [-a AT] [-A AB] [-B OP,PGP] [-b LBS] "
                "[-c DOF] [-D DLD]\n"
                "           [-d] [-x] [-f] [-G EOG,NOG] [-g GN] [-h] -i IF "
                "[-l LBA,LBA...]\n"
                "           [-N] [-n NUM,NUM...] [-o OFF[,DLEN]] [-O] [-r] "
                "[-R RT] [-M NDOB]\n"
                "           [-q SF] [-S RD] [-T ID] [-s] [-t TM] [-I TO] "
                "[-u U_A] [-v] [-V]\n"
                "           [-w WPR] DEVICE\n"
                   );
            pr2serr("\nUse '-h' or '--help' for more help\n");
            return;
        }
        pr2serr("  where:\n"
            "    --16|-6            send 16 byte cdb variant (this is "
            "default action)\n"
            "    --32|-3            send 32 byte cdb variant of command "
            "(def: 16 byte)\n"
            "    --app-tag=AT|-a AT    expected application tag field "
            "(def: 0xffff)\n"
            "    --atomic=AB|-A AB    send WRITE ATOMIC command with AB "
            "being its\n"
            "                         Atomic Boundary field (0 to 0xffff)\n"
            "    --bmop=OP,PGP|-p OP,PGP    set BMOP field to OP and "
            " Previous\n"
            "                               Generation Processing field "
            "to PGP\n"
            "    --bs=LBS|-b LBS    logical block size (def: use READ "
            "CAPACITY)\n"
            "    --combined=DOF|-c DOF    scatter list and data combined "
            "for WRITE\n"
            "                             SCATTERED, data starting at "
            "offset DOF which\n"
            "                             has units of sizeof(LB+PI); "
            "sizeof(PI)=8 or 0\n"
            "    --dld=DLD|-D DLD    set duration limit descriptor (dld) "
            "bits (def: 0)\n"
            "    --dpo|-d           set DPO (disable page out) field "
            "(def: clear)\n"
            "    --dry-run|-x       exit just before sending SCSI command\n"
            "    --fua|-f           set FUA (force unit access) field "
            "(def: clear)\n"
            "    --generation=EOG,NOG    set Expected ORWgeneration field "
            "to EOG\n"
            "        |-G EOG,NOG         and New ORWgeneration field to "
            "NOG\n"
            );
        pr2serr(
            "    --grpnum=GN|-g GN    GN is group number field (def: 0)\n"
            "    --help|-h          use multiple times for different "
            "usage messages\n"
            "    --in=IF|-i IF      IF is file to fetch NUM blocks of "
            "data from.\n"
            "                       Blocks written to DEVICE. 1 or no "
            "blocks read\n"
            "                       in the case of WRITE SAME\n"
            "    --lba=LBA,LBA...     list of LBAs (Logical Block Addresses) "
            "to start\n"
            "        |-l LBA,LBA...   writes (def: --lba=0). Alternative is "
            "--scat-file=SF\n"
            "    --normal|-N        send 'normal' WRITE command (default "
            "when no other\n"
            "                       command option given)\n"
            "    --num=NUM,NUM...     NUM is number of logical blocks to "
            "write (def:\n"
            "        |-n NUM,NUM...   --num=0). Number of block sent is "
            "sum of NUMs\n"
            "    --offset=OFF[,DLEN]    OFF is byte offset in IF to start "
            "reading from\n"
            "        |-o OFF[,DLEN]     (def: 0), then read DLEN bytes(def: "
            "rest of IF)\n"
            "    --or|-O            send ORWRITE command\n"
            "    --raw|-r           read --scat_file=SF as binary (def: "
            "ASCII hex)\n"
            "    --ref-tag=RT|-R RT     expected reference tag field (def: "
            "0xffffffff)\n"
            "    --same=NDOB|-M NDOB    send WRITE SAME command. NDOB (no "
            "data out buffer)\n"
            "                           can be either 0 (do send buffer) or "
            "1 (don't)\n"
            "    --scat-file=SF|-q SF    file containing LBA, NUM pairs, "
            "see manpage\n"
            "    --scattered=RD|-S RD    send WRITE SCATTERED command with "
            "RD range\n"
            "                            descriptors (RD can be 0 when "
            "--combined= given)\n"
            "    --stream=ID|-T ID    send WRITE STREAM command with its "
            "STR_ID\n"
            "                         field set to ID\n"
            "    --strict|-s        exit if read less than requested from "
            "IF ;\n"
            "                       require variety of WRITE to be given "
            "as option\n"
            "    --tag-mask=TM|-t TM    tag mask field (def: 0xffff)\n"
            "    --timeout=TO|-I TO    command timeout (unit: seconds) "
            "(def: 120)\n"
            "    --unmap=U_A|-u U_A    0 clears both UNMAP and ANCHOR bits "
            "(default),\n"
            "                          1 sets UNMAP, 2 sets ANCHOR, 3 sets "
            "both\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string then exit\n"
            "    --wrprotect=WPR|-w WPR    WPR is the WRPROTECT field "
            "value (def: 0)\n\n"
            "Performs a SCSI WRITE (normal), ORWRITE, WRITE ATOMIC, WRITE "
            "SAME, WRITE\nSCATTERED, or WRITE STREAM command. A 16 or 32 "
            "byte cdb variant can be\nselected. The --in=IF option (data to "
            "be written) is required apart from\nwhen --same=1 (i.e. when "
            "NDOB is set). If no WRITE variant option is given\nthen, in "
            "the absence of --strict, a (normal) WRITE is performed. Only "
            "WRITE\nSCATTERED uses multiple LBAs and NUMs, or a SF file "
            "with multiple pairs.\nThe --num=NUM field defaults to 0 (do "
            "nothing) for safety. Using '-h'\nmultiple times shows the "
            "applicable options for each command variant.\n"
            );
    } else if (2 == do_help) {
        printf("WRITE ATOMIC (16 or 32) applicable options:\n"
            "  sg_write_x --atomic=AB --in=IF [--16] [--32] [--app-tag=AT] "
            "[--bs=LBS]\n"
            "             [--dpo] [--fua] [--grpnum=GN] [--lba=LBA] "
            "[--num=NUM]\n"
            "             [--offset=OFF[,DLEN]] [--ref-tag=RT] [--strict] "
            "[--tag-mask=TM]\n"
            "             [--timeout=TO] [--wrprotect=WRP] DEVICE\n"
            "\n"
            "normal WRITE (32) applicable options:\n"
            "  sg_write_x --normal --in=IF --32 [--app-tag=AT] [--bs=LBS] "
            "[--dpo] [--fua]\n"
            "             [--grpnum=GN] [--lba=LBA] [--num=NUM] "
            "[--offset=OFF[,DLEN]]\n"
            "             [--ref-tag=RT] [--strict] [--tag-mask=TM] "
            "[--timeout=TO]\n"
            "             [--wrprotect=WRP] DEVICE\n"
            "\n"
            "normal WRITE (16) applicable options:\n"
            "  sg_write_x --normal --in=IF [--16] [--bs=LBS] [--dld=DLD] "
            "[--dpo] [--fua]\n"
            "            [--grpnum=GN] [--lba=LBA] [--num=NUM] "
            "[--offset=OFF[,DLEN]]\n"
            "            [--strict] [--timeout=TO] [--verbose] "
            "[--wrprotect=WRP] DEVICE\n"
            "\n"
            "ORWRITE (32) applicable options:\n"
            "  sg_write_x --or --in=IF --32 [--bmop=OP,PGP] [--bs=LBS] "
            "[--dpo] [--fua]\n"
            "             [--generation=EOG,NOG] [--grpnum=GN] [--lba=LBA] "
            "[--num=NUM]\n"
            "             [--offset=OFF{,DLEN]] [--strict] [--timeout=TO]\n"
            "             [--wrprotect=ORP] DEVICE\n"
            "\n"
            "ORWRITE (16) applicable options:\n"
            "  sg_write_x --or --in=IF [--16] [--bs=LBS] [--dpo] [--fua] "
            "[--grpnum=GN]\n"
            "             [--lba=LBA] [--num=NUM] [--offset=OFF[,DLEN]] "
            "[--strict]\n"
            "             [--timeout=TO] [--wrprotect=ORP] DEVICE\n"
            "\n"
              );
    } else if (3 == do_help) {
        printf("WRITE SAME (32) applicable options:\n"
            "  sg_write_x --same=NDOB --32 [--app-tag=AT] [--bs=LBS] "
            "[--grpnum=GN]\n"
            "             [--in=IF] [--lba=LBA] [--num=NUM] "
            "[--offset=OFF[,DLEN]]\n"
            "             [--ref-tag=RT] [--strict] [--tag-mask=TM] "
            "[--timeout=TO]\n"
            "             [--unmap=U_A] [--wrprotect=WRP] DEVICE\n"
            "\n"
            "WRITE SCATTERED (32) applicable options:\n"
            "  sg_write_x --scattered --in=IF --32 [--app-tag=AT] "
            "[--bs=LBS]\n"
            "             [--combined=DOF] [--dpo] [--fua] [--grpnum=GN]\n"
            "             [--lba=LBA,LBA...] [--num=NUM,NUM...] "
            "[--offset=OFF[,DLEN]]\n"
            "             [--raw] [--ref-tag=RT] [--scat-file=SF] "
            "[--strict]\n"
            "             [--tag-mask=TM] [--timeout=TO] [--wrprotect=WRP] "
            "DEVICE\n"
            "\n"
            "WRITE SCATTERED (16) applicable options:\n"
            "  sg_write_x --scattered --in=IF [--bs=LBS] [--combined=DOF] "
            "[--dld=DLD]\n"
            "             [--dpo] [--fua] [--grpnum=GN] [--lba=LBA,LBA...]\n"
            "             [--num=NUM,NUM...] [--offset=OFF[,DLEN]] [--raw] "
            "[--scat-file=SF]\n"
            "             [--strict] [--timeout=TO] [--wrprotect=WRP] "
            "DEVICE\n"
            "\n"
            "WRITE STREAM (32) applicable options:\n"
            "  sg_write_x --stream=ID --in=IF --32 [--app-tag=AT] "
            "[--bs=LBS] [--dpo]\n"
            "             [--fua] [--grpnum=GN] [--lba=LBA] [--num=NUM]\n"
            "             [--offset=OFF[,DLEN]] [--ref-tag=RT] [--strict] "
            "[--tag-mask=TM]\n"
            "             [--timeout=TO] [--verbose] [--wrprotect=WRP] "
            "DEVICE\n"
            "\n"
            "WRITE STREAM (16) applicable options:\n"
            "  sg_write_x --stream=ID --in=IF [--16] [--bs=LBS] [--dpo] "
            "[--fua]\n"
            "             [--grpnum=GN] [--lba=LBA] [--num=NUM] "
            "[--offset=OFF[,DLEN]]\n"
            "             [--strict] [--timeout=TO] [--wrprotect=WRP] "
            "DEVICE\n"
            "\n"
              );
    } else {
        printf("Notes:\n"
            " - all 32 byte cdb variants, apart from ORWRITE(32), need type "
            "1, 2, or 3\n"
            "   protection information active on the DEVICE\n"
            " - all commands can take one or more --verbose (-v) options "
            "and/or the\n"
            "   --dry-run option\n"
            " - all WRITE X commands will accept --scat-file=SF and "
            "optionally --raw\n"
            "   options but only the first addr,num pair is used (any "
            "more are ignored)\n"
            " - when '--raw --scat-file=SF' are used then the binary "
            "format expected in\n"
            "   SF is as defined for the WRITE SCATTERED commands. "
            "That is 32 bytes\n"
            "   of zeros followed by the first LBA range descriptor "
            "followed by the\n"
            "   second LBA range descriptor, etc. Each LBA range "
            "descriptor is 32 bytes\n"
            "   long with an 8 byte LBA at offset 0 and a 4 byte "
            "number_of_logical_\n"
            "   blocks at offset 8 (both big endian). The 'pad' following "
            "the last LBA\n"
            "   range descriptor does not need to be given\n"
            " - WRITE SCATTERED(32) additionally has expected initial "
            "LB reference tag,\n"
            "   application tag and LB application tag mask fields in the "
            "LBA range\n"
            "   descriptor. If --strict is given then all reserved fields "
            "are checked\n"
            "   for zeros, an error is generated for non zero bytes.\n"
            " - when '--lba=LBA,LBA...' is used on commands other than "
            "WRITE SCATTERED\n"
            "   then only the first LBA value is used.\n"
            " - when '--num=NUM,NUM...' is used on commands other than "
            "WRITE SCATTERED\n"
            "   then only the first NUM value is used.\n"
            " - whenever '--lba=LBA,LBA...' is used then "
            "'--num=NUM,NUM...' should\n"
            "   also be used. Also they should have the same number of "
            "elements.\n"
              );
    }
}

/* Returns true if num_of_f_chars of ASCII 'f' or 'F' characters are found
 * in sequence. Any leading "0x" or "0X" is ignored; otherwise false is
 * returned (and the comparsion stops when the first mismatch is found).
 * For example a sequence of 'f' characters in a null terminated C string
 * that is two characters shorter than the requested num_of_f_chars will
 * compare the null character in the string with 'f', find them unequal,
 * stop comparing and return false. */
static bool
all_ascii_f_s(const char * cp, int num_of_f_chars)
{
    if ((NULL == cp) || (num_of_f_chars < 1))
        return false;   /* define degenerate cases */
    if (('0' == cp[0]) && (('x' == cp[1]) || ('X' == cp[1])))
        cp += 2;
    for ( ; num_of_f_chars >= 0 ; --num_of_f_chars, ++cp) {
        if ('F' != toupper(*cp))
            return false;
    }
    return true;
}

/* Read numbers (up to 64 bits in size) from command line (comma (or
 * (single) space) separated list). Assumed decimal unless prefixed
 * by '0x', '0X' or contains trailing 'h' or 'H' (which indicate hex).
 * Returns 0 if ok, or 1 if error. */
static int
build_lba_arr(const char * inp, uint64_t * lba_arr, uint32_t * lba_arr_len,
              int max_arr_len)
{
    int in_len, k;
    int64_t ll;
    const char * lcp;
    char * cp;
    char * c2p;

    if ((NULL == inp) || (NULL == lba_arr) ||
        (NULL == lba_arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *lba_arr_len = 0;
    if ('-' == inp[0]) {        /* read from stdin */
        pr2serr("'--lba' cannot be read from stdin\n");
        return 1;
    } else {        /* list of numbers (default decimal) on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfFhHxXiIkKmMgGtTpP, ");
        if (in_len != k) {
            pr2serr("build_lba_arr: error at pos %d\n", k + 1);
            return 1;
        }
        for (k = 0; k < max_arr_len; ++k) {
            ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                lba_arr[k] = (uint64_t)ll;
                cp = (char *)strchr(lcp, ',');
                c2p = (char *)strchr(lcp, ' ');
                if (NULL == cp)
                    cp = c2p;
                if (NULL == cp)
                    break;
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                pr2serr("build_lba_arr: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        *lba_arr_len = (uint32_t)(k + 1);
        if (k == max_arr_len) {
            pr2serr("build_lba_arr: array length exceeded\n");
            return 1;
        }
    }
    return 0;
}

/* Read numbers (up to 32 bits in size) from command line (comma (or
 * (single) space) separated list). Assumed decimal unless prefixed
 * by '0x', '0X' or contains trailing 'h' or 'H' (which indicate hex).
 * Returns 0 if ok, or 1 if error. */
static int
build_num_arr(const char * inp, uint32_t * num_arr, uint32_t * num_arr_len,
              int max_arr_len)
{
    int in_len, k;
    const char * lcp;
    int64_t ll;
    char * cp;
    char * c2p;

    if ((NULL == inp) || (NULL == num_arr) ||
        (NULL == num_arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *num_arr_len = 0;
    if ('-' == inp[0]) {        /* read from stdin */
        pr2serr("'--len' cannot be read from stdin\n");
        return 1;
    } else {        /* list of numbers (default decimal) on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfFhHxXiIkKmMgGtTpP, ");
        if (in_len != k) {
            pr2serr("build_num_arr: error at pos %d\n", k + 1);
            return 1;
        }
        for (k = 0; k < max_arr_len; ++k) {
            ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                if (ll > UINT32_MAX) {
                    pr2serr("build_num_arr: number exceeds 32 bits at pos "
                            "%d\n", (int)(lcp - inp + 1));
                    return 1;
                }
                num_arr[k] = (uint32_t)ll;
                cp = (char *)strchr(lcp, ',');
                c2p = (char *)strchr(lcp, ' ');
                if (NULL == cp)
                    cp = c2p;
                if (NULL == cp)
                    break;
                if (c2p && (c2p < cp))
                    cp = c2p;
                lcp = cp + 1;
            } else {
                pr2serr("build_num_arr: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        *num_arr_len = (uint32_t)(k + 1);
        if (k == max_arr_len) {
            pr2serr("build_num_arr: array length exceeded\n");
            return 1;
        }
    }
    return 0;
}

/* Tries to parse LBA,NUM[,RT,AP,TM] on one line, comma separated. Returns
 * 0 if parsed ok, else 999 if nothing parsed, else error (currently always
 * SG_LIB_SYNTAX_ERROR). If protection information fields not given, then
 * default values are given (i.e. all 0xff bytes). Ignores all spaces and
 * tabs and everything after '#' on lcp (assumed to be an ASCII line that
 * is null terminated. If successful writes a LBA range descriptor starting
 * at 'up'. */
static int
parse_scat_pi_line(const char * lcp, uint8_t * up, uint32_t * sum_num)
{
    bool ok;
    int n;
    int64_t ll;
    const char * cp;
    const char * bp;
    char c[1024];

    bp = c;
    cp = strchr(lcp, '#');
    n = strspn(lcp, " \t");
    lcp = lcp + n;
    if (('\0' == *lcp) || (cp && (lcp >= cp)))
        return 999;   /* blank line or blank prior to first '#' */
    if (cp) {   /* copy from first non whitespace ... */
        memcpy(c, lcp, cp - lcp);
        c[cp - lcp] = '\0';     /* ... to just before first '#' */
    } else
        strcpy(c, lcp);         /* ... to end of line, including null */
    ll = sg_get_llnum(bp);
    ok = ((-1 != ll) || all_ascii_f_s(bp, 16));
    if (! ok) {
        pr2serr("%s: error reading LBA (first) item on ", __func__);
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_put_unaligned_be64((uint64_t)ll, up + 0);
    ok = false;
    cp = strchr(bp, ',');
    if (cp) {
        bp = cp + 1;
        if (*cp) {
            ll = sg_get_llnum(bp);
            if (-1 != ll)
                ok = true;
        }
    }
    if ((! ok) || (ll > UINT32_MAX)) {
        pr2serr("%s: error reading NUM (second) item on ", __func__);
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_put_unaligned_be32((uint32_t)ll, up + 8);
    *sum_num += (uint32_t)ll;
    cp = strchr(bp, ',');
    if (NULL == cp) {
        sg_put_unaligned_be32((uint32_t)DEF_RT, up + 12);
        sg_put_unaligned_be16((uint16_t)DEF_AT, up + 16);
        sg_put_unaligned_be16((uint16_t)DEF_TM, up + 18);
        return 0;
    }
    ok = false;
    bp = cp + 1;
    if (*cp) {
        ll = sg_get_llnum(bp);
        if (-1 != ll)
            ok = true;
    }
    if ((! ok) || (ll > UINT32_MAX)) {
        pr2serr("%s: error reading RT (third) item on ", __func__);
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_put_unaligned_be32((uint32_t)ll, up + 12);
    ok = false;
    cp = strchr(bp, ',');
    if (cp) {
        bp = cp + 1;
        if (*cp) {
            n = sg_get_num(bp);
            if (-1 != ll)
                ok = true;
        }
    }
    if ((! ok) || (n > UINT16_MAX)) {
        pr2serr("%s: error reading AT (fourth) item on ", __func__);
        return SG_LIB_SYNTAX_ERROR;
    }
    sg_put_unaligned_be32((uint16_t)n, up + 16);
    ok = false;
    cp = strchr(bp, ',');
    if (cp) {
        bp = cp + 1;
        if (*cp) {
            n = sg_get_num(bp);
            if (-1 != ll)
                ok = true;
        }
    }
    if ((! ok) || (n > UINT16_MAX)) {
        pr2serr("%s: error reading TM (fifth) item on ", __func__);
        return SG_LIB_SYNTAX_ERROR;
    }
    return 0;
}

/* Read pairs or LBAs and NUMs from a scat_file. A T10 scatter list array is
 * built at t10_scat_list_out (e.g. as per T10 the first 32 bytes are zeros
 * followed by the first LBA range descriptor (also 32 bytes long) then the
 * second LBA range descriptor, etc. If pi_as_well is false then only LBA,NUM
 * pairs are expected, loosely formatted if they are in the scat_file (e.g.
 * single line entries alternating LBA and NUM, with an even number of
 * elements. If pa_as_well is true then a stricter format for quintets is
 * expected: on each non comment line should contain: LBA,NUM[,RT,AT,TM] . If
 * RT,AT,TM are not given then they assume their defaults (i.e. 0xffffffff,
 * 0xffff, 0xffff). Each number (up to 64 bits in size) from command line or
 * scat_file may be a comma or (single) space separated list. Assumed decimal
 * unless prefixed by '0x', '0X' or contains trailing 'h' or 'H' (which
 * indicate hex). Returns 0 if ok, else error number. If ok also yields the
 * actual byte length of t10_scat_list_out written into act_list_blen and the
 * number of LBA range descriptors written in num_scat_elems . */
static int
build_t10_scat(const char * scat_fname, bool pi_as_well,
               uint8_t * t10_scat_list_out, uint32_t * act_list_blen,
               uint32_t * num_scat_elems, uint32_t * sum_num,
               int max_list_blen)
{
    bool have_stdin = false;
    bool bit0, ok;
    int off = 0;
    int in_len, k, j, m, n, ind, res;
    int64_t ll;
    char * lcp;
    uint8_t * up = t10_scat_list_out;
    FILE * fp = NULL;
    char line[1024];

    if ((NULL == scat_fname) || (NULL == up) || (NULL == act_list_blen) ||
        (NULL == num_scat_elems) || (max_list_blen < 64)) {
        pr2serr("%s: failed sanity\n", __func__);
        return 1;
    } else {
        memset(up, 0, max_list_blen);
        n = 32;
    }

    have_stdin = ((1 == strlen(scat_fname)) && ('-' == scat_fname[0]));
    if (have_stdin) {
        fp = stdin;
        scat_fname = "<stdin>";
    } else {
        fp = fopen(scat_fname, "r");
        if (NULL == fp) {
            pr2serr("%s: unable to open %s\n", __func__, scat_fname);
            return 1;
        }
    }
    for (j = 0; j < 1024; ++j) {    /* loop over each line in file */
        if (NULL == fgets(line, sizeof(line), fp))
            break;
        // could improve with carry_over logic if sizeof(line) too small
        in_len = strlen(line);
        if (in_len > 0) {
            if ('\n' == line[in_len - 1]) {
                --in_len;
                line[in_len] = '\0';
            }
        }
        if (in_len < 1)
            continue;
        lcp = line;
        m = strspn(lcp, " \t");
        if (m == in_len)
            continue;
        lcp += m;
        in_len -= m;
        if ('#' == *lcp)    /* Comment? If so skip rest of line */
            continue;
        k = strspn(lcp, "0123456789aAbBcCdDeEfFhHxXiIkKmMgGtTpP ,\t");
        if ((k < in_len) && ('#' != lcp[k])) {
            pr2serr("%s: syntax error in %s at line %d, pos %d\n",
                    __func__, scat_fname, j + 1, m + k + 1);
            goto bad_exit;
        }
        if (pi_as_well) {
            res = parse_scat_pi_line(lcp, up + n, sum_num);
            if (999 == res)
                ;
            else if (0 == res)
                n += 32;
            else {
                pr2serr("line %d in %s\n", j + 1, scat_fname);
                goto bad_exit;
            }
            continue;
        }
        for (k = 0; k < 1024; ++k) {
            ll = sg_get_llnum(lcp);
            ok = ((-1 != ll) || all_ascii_f_s(lcp, 16));
            if (ok) {
                ind = ((off + k) >> 1);
                bit0 = !! (0x1 & (off + k));
                if (ind >= max_list_blen) {
                    pr2serr("%s: array length exceeded in %s\n", __func__,
                            scat_fname);
                    goto bad_exit;
                }
                if (bit0) {
                    if (ll > UINT32_MAX) {
                        pr2serr("%s: number exceeds 32 bits in line %d, at "
                                "pos %d of %s\n", __func__, j + 1,
                                (int)(lcp - line + 1), scat_fname);
                        goto bad_exit;
                    }
                    sg_put_unaligned_be32((uint32_t)ll, up + n + 8);
                    *sum_num += (uint32_t)ll;
                    n += 32;  /* skip to next LBA range descriptor */
                } else
                    sg_put_unaligned_be64((uint64_t)ll, up + n + 0);
                lcp = strpbrk(lcp, " ,\t");
                if (NULL == lcp)
                    break;
                lcp += strspn(lcp, " ,\t");
                if ('\0' == *lcp)
                    break;
            } else {        /* no valid number found */
                if ('#' == *lcp) {
                    --k;
                    break;
                }
                pr2serr("%s: error on line %d, at pos %d\n", __func__, j + 1,
                        (int)(lcp - line + 1));
                goto bad_exit;
            }
        }   /* inner for loop(k) over line elements */
        off += (k + 1);
    }       /* outer for loop(j) over lines */
    if ((! pi_as_well) && (0x1 & off)) {
        pr2serr("%s: expect LBA,NUM pairs but decoded odd number\n  from "
                "%s\n", __func__, scat_fname);
        goto bad_exit;
    }
    *act_list_blen = n - 32;
    *num_scat_elems = (n / 32) - 1;
    if (fp && (stdin != fp))
        fclose(fp);
    return 0;
bad_exit:
    if (fp && (stdin != fp))
        fclose(fp);
    return 1;
}

static bool
is_pi_default(const struct opts_t * op)
{
    return ((DEF_AT == op->app_tag) && (DEF_RT == op->ref_tag) &&
            (DEF_TM == op->tag_mask));
}

static int
do_write_x(int sg_fd, const void * dataoutp, int dout_len,
           const struct opts_t * op)
{
    int k, ret, res, sense_cat, cdb_len;
    unsigned char x_cdb[WRITE_X_32_LEN];        /* use for both lengths */
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    memset(x_cdb, 0, sizeof(x_cdb));
    cdb_len = op->do_16 ? WRITE_X_16_LEN : WRITE_X_32_LEN;
    if (16 == cdb_len) {
        if (! op->do_scattered)
            sg_put_unaligned_be64(op->lba, x_cdb + 2);
        x_cdb[14] = (op->grpnum & 0x1f);
    } else {
        x_cdb[0] = VARIABLE_LEN_OP;
        x_cdb[6] = (op->grpnum & 0x1f);
        x_cdb[7] = WRITE_X_32_ADD;
        if (! op->do_scattered)
            sg_put_unaligned_be64(op->lba, x_cdb + 12);
    }
    if (op->do_write_normal) {
        if (16 == cdb_len)  {
            x_cdb[0] = WRITE_16_OP;
            x_cdb[1] = ((op->wrprotect & 0x7) << 5);
            if (op->dpo)
                x_cdb[1] |= 0x10;
            if (op->fua)
                x_cdb[1] |= 0x8;
            if (op->dld) {
                if (op->dld & 1)
                    x_cdb[14] |= 0x40;
                if (op->dld & 2)
                    x_cdb[14] |= 0x80;
                if (op->dld & 4)
                    x_cdb[1] |= 0x1;
            }
            sg_put_unaligned_be32(op->numblocks, x_cdb + 10);
        } else {        /* 32 byte WRITE */
            sg_put_unaligned_be16((uint16_t)WRITE_32_SA, x_cdb + 8);
            x_cdb[10] = ((op->wrprotect & 0x7) << 5);
            if (op->dpo)
                x_cdb[10] |= 0x10;
            if (op->fua)
                x_cdb[10] |= 0x8;
            sg_put_unaligned_be32(op->ref_tag, x_cdb + 20);
            sg_put_unaligned_be16(op->app_tag, x_cdb + 24);
            sg_put_unaligned_be16(op->tag_mask, x_cdb + 26);
            sg_put_unaligned_be32(op->numblocks, x_cdb + 28);
        }
    } else if (op->do_atomic) {
        if (16 == cdb_len)  {
            if (op->numblocks > UINT16_MAX) {
                pr2serr("Need WRITE ATOMIC(32) since blocks exceed 65535\n");
                return -1;
            }
            x_cdb[0] = WRITE_ATOMIC16_OP;
            x_cdb[1] = ((op->wrprotect & 0x7) << 5);
            if (op->dpo)
                x_cdb[1] |= 0x10;
            if (op->fua)
                x_cdb[1] |= 0x8;
            sg_put_unaligned_be16(op->atomic_boundary, x_cdb + 10);
            sg_put_unaligned_be16((uint16_t)op->numblocks, x_cdb + 12);
        } else {        /* 32 byte WRITE ATOMIC */
            sg_put_unaligned_be16(op->atomic_boundary, x_cdb + 4);
            sg_put_unaligned_be16((uint16_t)WRITE_ATOMIC32_SA, x_cdb + 8);
            x_cdb[10] = ((op->wrprotect & 0x7) << 5);
            if (op->dpo)
                x_cdb[10] |= 0x10;
            if (op->fua)
                x_cdb[10] |= 0x8;
            sg_put_unaligned_be32(op->ref_tag, x_cdb + 20);
            sg_put_unaligned_be16(op->app_tag, x_cdb + 24);
            sg_put_unaligned_be16(op->tag_mask, x_cdb + 26);
            sg_put_unaligned_be32(op->numblocks, x_cdb + 28);
        }
    } else if (op->do_or) {     /* ORWRITE(16 or 32) */
        if (16 == cdb_len) {
            x_cdb[0] = ORWRITE16_OP;
            x_cdb[1] = ((op->wrprotect & 0x7) << 5);  /* actually ORPROTECT */
            if (op->dpo)
                x_cdb[1] |= 0x10;
            if (op->fua)
                x_cdb[1] |= 0x8;
            sg_put_unaligned_be32(op->numblocks, x_cdb + 10);
        } else {
            x_cdb[2] = op->bmop;
            x_cdb[3] = op->pgp;
            sg_put_unaligned_be16((uint16_t)ORWRITE32_SA, x_cdb + 8);
            x_cdb[10] = ((op->wrprotect & 0x7) << 5);
            if (op->dpo)
                x_cdb[10] |= 0x10;
            if (op->fua)
                x_cdb[10] |= 0x8;
            sg_put_unaligned_be32(op->orw_eog, x_cdb + 20);
            sg_put_unaligned_be32(op->orw_nog, x_cdb + 24);
            sg_put_unaligned_be32(op->numblocks, x_cdb + 28);
        }
    } else if (op->do_same) {
        if (16 == cdb_len) {
            x_cdb[0] = WRITE_SAME16_OP;
            x_cdb[1] = ((op->wrprotect & 0x7) << 5);
            if (op->do_anchor)
                x_cdb[1] |= 0x10;
            if (op->do_unmap)
                x_cdb[1] |= 0x8;
            if (op->ndob)
                x_cdb[1] |= 0x1;
            sg_put_unaligned_be32(op->numblocks, x_cdb + 10);
        } else {
            sg_put_unaligned_be16((uint16_t)WRITE_SAME_SA, x_cdb + 8);
            x_cdb[10] = ((op->wrprotect & 0x7) << 5);
            if (op->do_anchor)
                x_cdb[10] |= 0x10;
            if (op->do_unmap)
                x_cdb[10] |= 0x8;
            if (op->ndob)
                x_cdb[10] |= 0x1;
            /* Expected initial logical block reference tag */
            sg_put_unaligned_be32(op->ref_tag, x_cdb + 20);
            sg_put_unaligned_be16(op->app_tag, x_cdb + 24);
            sg_put_unaligned_be16(op->tag_mask, x_cdb + 26);
            sg_put_unaligned_be32(op->numblocks, x_cdb + 28);
        }
    } else if (op->do_scattered) {
        if (16 == cdb_len) {
            x_cdb[0] = SERVICE_ACTION_OUT_16_OP;
            x_cdb[1] = WRITE_SCATTERED16_SA;
            x_cdb[2] = ((op->wrprotect & 0x7) << 5);
            if (op->dpo)
                x_cdb[2] |= 0x10;
            if (op->fua)
                x_cdb[2] |= 0x8;
            if (op->dld) {
                if (op->dld & 1)
                    x_cdb[14] |= 0x40;
                if (op->dld & 2)
                    x_cdb[14] |= 0x80;
                if (op->dld & 4)
                    x_cdb[2] |= 0x1;
            }
            sg_put_unaligned_be16(op->scat_lbdof, x_cdb + 4);
            sg_put_unaligned_be16(op->scat_num_lbard, x_cdb + 8);
            sg_put_unaligned_be32(op->numblocks, x_cdb + 10);

        } else {
            sg_put_unaligned_be16((uint16_t)WRITE_SCATTERED32_SA, x_cdb + 8);
            x_cdb[10] = ((op->wrprotect & 0x7) << 5);
            if (op->dpo)
                x_cdb[10] |= 0x10;
            if (op->fua)
                x_cdb[10] |= 0x8;
            sg_put_unaligned_be16(op->scat_lbdof, x_cdb + 12);
            sg_put_unaligned_be16(op->scat_num_lbard, x_cdb + 16);
            sg_put_unaligned_be32(op->numblocks, x_cdb + 28);
        }
    } else if (op->do_stream) {
        if (16 == cdb_len) {
            x_cdb[0] = WRITE_STREAM16_OP;
            x_cdb[1] = ((op->wrprotect & 0x7) << 5);
            if (op->dpo)
                x_cdb[1] |= 0x10;
            if (op->fua)
                x_cdb[1] |= 0x8;
            sg_put_unaligned_be16(op->str_id, x_cdb + 10);
            sg_put_unaligned_be16((uint16_t)op->numblocks, x_cdb + 12);
        } else {
            sg_put_unaligned_be16(op->str_id, x_cdb + 4);
            sg_put_unaligned_be16((uint16_t)WRITE_STREAM32_SA, x_cdb + 8);
            x_cdb[10] = ((op->wrprotect & 0x7) << 5);
            if (op->dpo)
                x_cdb[10] |= 0x10;
            if (op->fua)
                x_cdb[10] |= 0x8;
            sg_put_unaligned_be32(op->ref_tag, x_cdb + 20);
            sg_put_unaligned_be16(op->app_tag, x_cdb + 24);
            sg_put_unaligned_be16(op->tag_mask, x_cdb + 26);
            sg_put_unaligned_be32(op->numblocks, x_cdb + 28);
        }
    } else {
        pr2serr("%s: bad cdb name or length (%d)\n", __func__, cdb_len);
        return -1;
    }

    if (op->verbose > 1) {
        pr2serr("    %s cdb: ", op->cdb_name);
        for (k = 0; k < cdb_len; ++k)
            pr2serr("%02x ", x_cdb[k]);
        pr2serr("\n");
    }
    if ((op->verbose > 3) && (dout_len > 0)) {
        pr2serr("    Data-out buffer contents:\n");
        dStrHexErr((const char *)dataoutp, op->xfer_bytes, 1);
    }
    if (op->do_dry_run) {
        if (op->verbose)
            pr2serr("Exit just before sending command+data due to "
                    "--dry-run\n");
        return 0;
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", op->cdb_name);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, x_cdb, cdb_len);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)dataoutp, op->xfer_bytes);
    res = do_scsi_pt(ptvp, sg_fd, op->timeout, op->verbose);
    ret = sg_cmds_process_resp(ptvp, op->cdb_name, res, SG_NO_DATA_IN,
                               sense_b, true /*noisy */, op->verbose,
                               &sense_cat);
    if (-1 == ret)
        ;       /* general (OS) error like ioctl not recognized */
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            {
                bool valid;
                int slen;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                if (valid) {
                    pr2serr("Medium or hardware error starting at ");
                    if (op->do_scattered)
                        pr2serr("scatter descriptor=%" PRIu64 "]\n", ull);
                    else
                        pr2serr("lba=%" PRIu64 " [0x%" PRIx64 "]\n", ull,
                                ull);
                }
            }
            ret = sense_cat;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static int
do_read_capacity(int sg_fd, struct opts_t *op)
{
    bool prot_en = false;
    int res;
    int vb = op->verbose;
    char b[80];
    unsigned char resp_buff[RCAP16_RESP_LEN];

    res = sg_ll_readcap_16(sg_fd, false /* pmi */, 0 /* llba */, resp_buff,
                           RCAP16_RESP_LEN, true, (vb ? (vb - 1): 0));
    if (SG_LIB_CAT_UNIT_ATTENTION == res) {
        pr2serr("Read capacity(16) unit attention, try again\n");
        res = sg_ll_readcap_16(sg_fd, false, 0, resp_buff, RCAP16_RESP_LEN,
                               true, (vb ? (vb - 1): 0));
    }
    if (0 == res) {
        if (vb > 3) {
            pr2serr("Read capacity(16) response:\n");
            dStrHexErr((const char *)resp_buff, RCAP16_RESP_LEN, 1);
        }
        op->bs = sg_get_unaligned_be32(resp_buff + 8);
        op->tot_lbs = sg_get_unaligned_be64(resp_buff + 0) + 1;
        prot_en = !!(resp_buff[12] & 0x1);
        if (prot_en) {
            op->pi_type = ((resp_buff[12] >> 1) & 0x7) + 1;
            if (op->wrprotect > 0) {
                op->bs_pi_do = op->bs + 8;
                if (vb > 1)
                    pr2serr("  For data out buffer purposes the effective "
                            "block size is %u (lb size\n  is %u) because "
                            "PROT_EN=1 and WRPROTECT>0\n", op->bs,
                            op->bs_pi_do);
           }
        } else {    /* device formatted to PI type 0 (i.e. none) */
            op->pi_type = 0;
            if (op->wrprotect > 0) {
                if (vb)
                    pr2serr("--wrprotect (%d) expects PI but %s says it "
                            "has none\n", op->wrprotect, op->device_name);
                if (op->strict)
                    return SG_LIB_FILE_ERROR;
                else if (vb)
                    pr2serr("  ... continue but could be dangerous\n");
            }
        }
        if (vb) {
            uint8_t d[2];

            pr2serr("Read capacity(16) response fields:\n");
            pr2serr("  Last_LBA=0x%" PRIx64 ", LB size: %u (with PI: "
                    "%u) bytes, p_type=%u\n", op->tot_lbs - 1, op->bs,
                    op->bs + (prot_en ? 8 : 0),
                    ((resp_buff[12] >> 1) & 0x7));
            pr2serr("  prot_en=%u (PI type=%u), p_i_exp=%u, "
                    "lbppb_exp=%u, lbpme=%u, ",
                    prot_en, op->pi_type,
                    ((resp_buff[13] >> 4) & 0xf),
                    (resp_buff[13] & 0xf), (resp_buff[14] & 0x80));
            memcpy(d, resp_buff + 14, 2);
            d[0] &= 0x3f;
            pr2serr("lbprz=%u, low_ali_lba=%u\n", (resp_buff[14] & 0x40),
                    sg_get_unaligned_be16(d));
        }
    } else if ((SG_LIB_CAT_INVALID_OP == res) ||
               (SG_LIB_CAT_ILLEGAL_REQ == res)) {
        if (vb)
            pr2serr("Read capacity(16) not supported, try Read "
                    "capacity(10)\n");
        res = sg_ll_readcap_10(sg_fd, false /* pmi */, 0 /* lba */,
                               resp_buff, RCAP10_RESP_LEN, true,
                               (vb ? (vb - 1): 0));
        if (0 == res) {
            if (vb > 3) {
                pr2serr("Read capacity(10) response:\n");
                dStrHexErr((const char *)resp_buff, RCAP10_RESP_LEN, 1);
            }
            op->tot_lbs = sg_get_unaligned_be32(resp_buff + 0) + 1;
            op->bs = sg_get_unaligned_be32(resp_buff + 4);
        } else {
            strcpy(b,"OS error");
            if (res > 0)
                sg_get_category_sense_str(res, sizeof(b), b, vb);
            pr2serr("Read capacity(10): %s\n", b);
            pr2serr("Unable to calculate block size\n");
            return (res > 0) ? res : SG_LIB_FILE_ERROR;
        }
    } else if (vb) {
        strcpy(b,"OS error");
        if (res > 0)
            sg_get_category_sense_str(res, sizeof(b), b, vb);
        pr2serr("Read capacity(16): %s\n", b);
        pr2serr("Unable to calculate block size\n");
        return (res > 0) ? res : SG_LIB_FILE_ERROR;
    }
    op->bs_pi_do = op->expect_pi_do ? (op->bs + 8) : op->bs;
    return 0;
}

#define WANT_ZERO_EXIT 9999
static const char * const opt_long_ctl_str =
    "36a:A:b:B:c:dD:Efg:G:hi:I:l:M:n:No:Oq:rR:sS:t:T:u:vVw:x";

/* command line processing, options and arguments. Returns 0 if ok,
 * returns WANT_ZERO_EXIT so upper level yields an exist status of zero.
 * Other return values (mainly SG_LIB_SYNTAX_ERROR) indicate errors. */
static int
cl_process(struct opts_t *op, int argc, char *argv[], const char ** lba_opp,
           const char ** num_opp)
{
    int c, j;
    int64_t ll;
    const char * cp;

    while (1) {
        int opt_ind = 0;

        c = getopt_long(argc, argv, opt_long_ctl_str, long_options, &opt_ind);
        if (c == -1)
            break;

        switch (c) {
        case '3':       /* same as --32 */
            op->do_32 = true;
            break;
        case '6':       /* same as --16 */
            op->do_16 = true;
            break;
        case 'a':
            j = sg_get_num(optarg);
            if ((j < 0) || (j > UINT16_MAX)) {
                pr2serr("bad argument to '--app-tag='. Expect 0 to 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->app_tag = (uint16_t)j;
            break;
        case 'A':
            j = sg_get_num(optarg);
            if ((j < 0) || (j > UINT16_MAX)) {
                pr2serr("bad argument to '--atomic='. Expect 0 to 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->atomic_boundary = (uint16_t)j;
            op->do_atomic = true;
            op->cmd_name = "Write atomic";
            break;
        case 'b':                        /* logical block size in bytes */
            j = sg_get_num(optarg); /* 0 -> look up with READ CAPACITY */
            if ((j < 0) || (j > (1 << 28))) {
                pr2serr("bad argument to '--bs='. Expect 0 or greater\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->bs = (uint32_t)j;
            op->bs_pi_do = op->bs;
            break;
        case 'B':       /* --bmop=OP,PGP (for ORWRITE(32)) */
            j = sg_get_num(optarg);
            if ((j < 0) || (j > 7)) {
                pr2serr("bad first argument to '--bmop='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->bmop = (uint8_t)j;
            if ((cp = strchr(optarg, ','))) {
                j = sg_get_num(cp + 1);
                if ((j < 0) || (j > 15)) {
                    pr2serr("bad second argument to '--bmop='\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->pgp = (uint8_t)j;
            }
            break;
        case 'c':       /* --combined=DOF for W SCATTERED, DOF: data offset */
            j = sg_get_num(optarg);
            if ((j < 0) || (j > INT32_MAX)) {
                pr2serr("bad argument to '--combined='. Expect 0 to "
                        "0x7fffffff\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->scat_lbdof = (uint16_t)j;
            op->do_combined = true;
            break;
        case 'd':
            op->dpo = true;
            break;
        case 'D':
            op->dld = sg_get_num(optarg);
            if ((op->dld < 0) || (op->dld > 7))  {
                pr2serr("bad argument to '--dld=', expect 0 to 7 "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'f':
            op->fua = true;
            break;
        case 'g':
            op->grpnum = sg_get_num(optarg);
            if ((op->grpnum < 0) || (op->grpnum > 63))  {
                pr2serr("bad argument to '--grpnum'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'G':       /* --generation=EOG,NOG */
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad first argument to '--generation='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->orw_eog = (uint32_t)ll;
            if ((cp = strchr(optarg, ','))) {
                ll = sg_get_llnum(cp + 1);
                if ((ll < 0) || (ll > UINT32_MAX)) {
                    pr2serr("bad second argument to '--generation='\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->orw_nog = (uint32_t)ll;
            } else {
                pr2serr("need two arguments with --generation=EOG,NOG and "
                        "they must be comma separated\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'h':
            ++op->help;
            break;
        case '?':
            pr2serr("\n");
            usage((op->help > 0) ? op->help : 0);
            return SG_LIB_SYNTAX_ERROR;
        case 'i':
            op->if_name = optarg;
            break;
        case 'I':
            op->timeout = sg_get_num(optarg);
            if (op->timeout < 0)  {
                pr2serr("bad argument to '--timeout='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'l':
            if (*lba_opp) {
                pr2serr("only expect '--lba=' option once\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            *lba_opp = optarg;
            break;
        case 'M':               /* WRITE SAME */
            j = sg_get_num(optarg);
            if ((j < 0) || (j > 1))  {
                pr2serr("bad argument to '--same', expect 0 or 1\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->ndob = (bool)j;
            op->do_same = true;
            op->cmd_name = "Write same";
            break;
        case 'n':
            if (*num_opp) {
                pr2serr("only expect '--num=' option once\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            *num_opp = optarg;
            break;
        case 'N':
            op->do_write_normal = true;
            op->cmd_name = "Write";
            break;
        case 'o':
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad first argument to '--offset='\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->offset = (uint64_t)ll;
            if ((cp = strchr(optarg, ','))) {
                ll = sg_get_llnum(cp + 1);
                if (-1 == ll) {
                    pr2serr("bad second argument to '--offset='\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->dlen = (uint64_t)ll;
            }
            break;
        case 'O':
            op->do_or = true;
            op->cmd_name = "Orwrite";
            break;
        case 'q':
            op->scat_filename = optarg;
            break;
        case 'r':
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--ref-tag='. Expect 0 to "
                        "0xffffffff inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->ref_tag = (uint32_t)ll;
            break;
        case 'R':               /* same as --ref-tag= */
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--ref-tag='. Expect 0 to 0xffffffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->ref_tag = (uint32_t)ll;
            break;
        case 's':
            op->strict = true;
            break;
        case 'S':
            j = sg_get_num(optarg);
            if ((j < 0) || (j > UINT16_MAX)) {
                pr2serr("bad argument to '--scattered='. Expect 0 to 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->scat_num_lbard = (uint16_t)j;
            op->do_scattered = true;
            op->cmd_name = "Write scattered";
            break;
        case 't':               /* same as --tag-mask= */
            j = sg_get_num(optarg);
            if ((j < 0) || (j > UINT16_MAX)) {
                pr2serr("bad argument to '--tag-mask='. Expect 0 to 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->tag_mask = (uint16_t)j;
            break;
        case 'T':               /* WRITE STREAM */
            j = sg_get_num(optarg);
            if ((j < 0) || (j > UINT16_MAX)) {
                pr2serr("bad argument to '--stream=', expect 0 to 65535\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->str_id = (uint16_t)j;
            op->do_stream = true;
            op->cmd_name = "Write stream";
            break;
        case 'u':               /* WRITE SAME, UNMAP and ANCHOR bit */
            j = sg_get_num(optarg);
            if ((j < 0) || (j > 3)) {
                pr2serr("bad argument to '--unmap=', expect 0 to "
                        "3\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_unmap = !!(1 & j);
            op->do_anchor = !!(2 & j);
            break;
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return WANT_ZERO_EXIT;
        case 'w':       /* WRPROTECT field (or ORPROTECT for ORWRITE) */
            op->wrprotect = sg_get_num(optarg);
            if ((op->wrprotect < 0) || (op->wrprotect > 7))  {
                pr2serr("bad argument to '--wrprotect'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->expect_pi_do = (op->wrprotect > 0);
            break;
        case 'x':
            op->do_dry_run = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage((op->help > 0) ? op->help : 0);
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
            usage((op->help > 0) ? op->help : 0);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool got_stdin = false;
    bool got_stat = false;
    int k, n, err, vb;
    int infd = -1;
    int sg_fd = -1;
    int rsl_fd = -1;
    int ret = -1;
    uint32_t addr_arr_len, num_arr_len, num_lbard, do_len;
    ssize_t res;
    off_t if_len = 0;
    struct opts_t * op;
    unsigned char * wBuff = NULL;
    const char * lba_op = NULL;
    const char * num_op = NULL;
    uint8_t * up = NULL;
    char ebuff[EBUFF_SZ];
    char b[80];
    uint64_t addr_arr[MAX_NUM_ADDR];
    uint32_t num_arr[MAX_NUM_ADDR];
    struct stat if_stat, sf_stat;
    struct opts_t opts;

    op = &opts;
    memset(op, 0, sizeof(opts));
    memset(&if_stat, 0, sizeof(if_stat));
    memset(&sf_stat, 0, sizeof(sf_stat));
    op->numblocks = DEF_WR_NUMBLOCKS;
    op->pi_type = -1;           /* Protection information type unknown */
    op->ref_tag = DEF_RT;       /* first 4 bytes of 8 byte protection info */
    op->app_tag = DEF_AT;       /* part of protection information */
    op->tag_mask = DEF_TM;      /* part of protection information */
    op->timeout = DEF_TIMEOUT_SECS;

    ret = cl_process(op, argc, argv, &lba_op, &num_op);
    if (ret) {
        if (WANT_ZERO_EXIT == ret)
            return 0;
        return ret;
    }
    if (op->help > 0) {
        usage(op->help);
        return 0;
    }
    vb = op->verbose;
    if ((! op->do_16) && (! op->do_32)) {
        op->do_16 = true;
        if (vb > 1)
            pr2serr("Since neither --16 nor --32 given, choose --16\n");
    } else if (op->do_16 && op->do_32) {
        op->do_16 = false;
        if (vb > 1)
            pr2serr("Since both --16 and --32 given, choose --32\n");
    }
    n = (int)op->do_atomic + (int)op->do_write_normal + (int)op->do_or +
        (int)op->do_same + (int)op->do_scattered + (int)op->do_stream;
    if (n > 1) {
        pr2serr("Can only select one command; so only one of --atomic, "
                "--normal, --or,\n--same=, --scattered= or --stream=\n") ;
        return SG_LIB_SYNTAX_ERROR;
    } else if (n < 1) {
        op->do_write_normal = true;
        op->cmd_name = "Write";
        if (vb)
            pr2serr("No command selected so choose 'normal' WRITE\n");
    }
    snprintf(op->cdb_name, sizeof(op->cdb_name), "%s(%d)", op->cmd_name,
             (op->do_16 ? 16 : 32));

    if (! op->ndob) {
        if (NULL == op->if_name) {
            pr2serr("Need --if=FN option to be given, exiting.\n");
            if (vb > 1)
                pr2serr("To write zeros use --in=/dev/zero\n");
            usage((op->help > 0) ? op->help : 0);
            return SG_LIB_SYNTAX_ERROR;
        }
        if ((1 == strlen(op->if_name)) && ('-' == op->if_name[0]))
            got_stdin = true;
        if (got_stdin) {
            infd = STDIN_FILENO;
            if (sg_set_binary_mode(STDIN_FILENO) < 0) {
                perror("sg_set_binary_mode");
                return SG_LIB_FILE_ERROR;
            }
        } else {
            if ((infd = open(op->if_name, O_RDONLY)) < 0) {
                snprintf(ebuff, EBUFF_SZ, "could not open %s for reading",
                         op->if_name);
                perror(ebuff);
                return SG_LIB_FILE_ERROR;
            } else if (sg_set_binary_mode(infd) < 0)
                perror("sg_set_binary_mode");
            if (fstat(infd, &if_stat) < 0) {
                snprintf(ebuff, EBUFF_SZ, "could not fstat %s", op->if_name);
                perror(ebuff);
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
            got_stat = true;
            if (S_ISREG(if_stat.st_mode))
                if_len = if_stat.st_size;
        }
        if (got_stat && if_len && ((int64_t)op->offset >= (if_len - 1))) {
            pr2serr("Offset (%" PRIu64 ") is at or beyond IF byte length (%"
                    PRIu64 ")\n", op->offset, if_len);
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
        if (op->offset > 0) {
            off_t off = op->offset;

            if (got_stdin) {
                if (vb)
                    pr2serr("--offset= ignored when IF is stdin\n");
            } else {
                /* lseek() won't work with stdin or pipes, for example */
                if (lseek(infd, off, SEEK_SET) < 0) {
                    snprintf(ebuff,  EBUFF_SZ,
                        "couldn't offset to required position on %s",
                         op->if_name);
                    perror(ebuff);
                    ret = SG_LIB_FILE_ERROR;
                    goto err_out;
                }
                if_len -= op->offset;
                if (if_len <= 0) {
                    pr2serr("--offset [0x%" PRIx64 "] at or beyond file "
                            "length[0x%" PRIx64 "]\n", (uint64_t)op->offset,
                            (uint64_t)if_len);
                    ret = SG_LIB_FILE_ERROR;
                    goto err_out;
                }
            }
        }
        if (0 != (if_len % op->bs_pi_do)) {
            pr2serr("Warning: number of bytes to read from IF [%u] is not a "
                    "multiple\nblock size %u (including protection "
                    "information, if any);\npad with zeros",
                    (unsigned int)if_len, op->bs_pi_do);
            if_len = (((unsigned int)if_len / op->bs_pi_do) + 1) *
                     op->bs_pi_do;      /* round up */
        }
    }
    if (NULL == op->device_name) {
        pr2serr("missing device name!\n");
        usage((op->help > 0) ? op->help : 0);
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }
    if (op->scat_filename && (lba_op || num_op)) {
        pr2serr("expect '--scat-file=' by itself, or both '--lba=' and "
                "'--num='\n");
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    } else if (op->scat_filename || (lba_op && num_op))
        ;       /* we want this path */
    else {
        if (lba_op)
            pr2serr("since '--lba=' is given, also need '--num='\n");
        else
            pr2serr("expect either both '--lba=' and '--num=', or "
                    "'--scat-file=' by itself\n");
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }

    sg_fd = sg_cmds_open_device(op->device_name, false /* rw */, vb);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: %s\n", op->device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (0 == op->bs) {  /* ask DEVICE about logical/actual block size */
        ret = do_read_capacity(sg_fd, op);
        if (ret)
            goto err_out;
    }

    memset(addr_arr, 0, sizeof(addr_arr));
    memset(num_arr, 0, sizeof(num_arr));
    addr_arr_len = 0;
    if (lba_op && num_op) {
        if (0 != build_lba_arr(lba_op, addr_arr, &addr_arr_len,
                               MAX_NUM_ADDR)) {
            pr2serr("bad argument to '--lba'\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        if (0 != build_num_arr(num_op, num_arr, &num_arr_len,
                               MAX_NUM_ADDR)) {
            pr2serr("bad argument to '--num'\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        if ((addr_arr_len != num_arr_len) || (num_arr_len <= 0)) {
            pr2serr("need same number of arguments to '--lba=' "
                    "and '--num=' options\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
    }
    if (op->do_scattered) {
        uint32_t d;
        uint32_t sum_num = 0;

        do_len = 0;
        if (op->scat_filename) {
            if (op->do_combined) {
                pr2serr("Ambiguous: got --combined=DOF and --scat-file=SF "
                        ".\nGive one, the other or neither\n");
                ret = SG_LIB_SYNTAX_ERROR;
                goto err_out;
            }
            if (stat(op->scat_filename, &sf_stat) < 0) {
                err = errno;
                pr2serr("Unable to stat(%s) as SF: %s\n", op->scat_filename,
                        safe_strerror(err));
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
        }
        if (op->do_combined && op->do_raw) {
            pr2serr("Ambiguous: do expect --combined=DOF and --raw\n"
                    "Give one or the other\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        if ((NULL == op->scat_filename) && op->do_raw) {
            pr2serr("--raw only applies to the --scat-file=SF option\n"
                    "Give both or neither\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        if ((addr_arr_len > 0) && (op->scat_num_lbard > 0) &&
            (op->scat_num_lbard < addr_arr_len)) {
            pr2serr("less LBA,NUM pairs (%d )than --scattered=%d\n",
                    addr_arr_len, op->scat_num_lbard);
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        num_lbard = (addr_arr_len > 0) ? addr_arr_len : op->scat_num_lbard;
        if (num_lbard < 15)
            num_lbard = 15; /* 32 byte leadin, 15  32 byte LRD = 512 bytes */
        if (op->do_combined)
            goto skip_scat_build;
        if (op->do_raw) {
            if (S_ISREG(sf_stat.st_mode)) {
                do_len = sf_stat.st_size;
                d = sf_stat.st_size / 32;
                if (0 == d) {
                    pr2serr("raw SF must be at least 32 bytes long (followed "
                            "by first LBA range descriptor\n");
                    ret = SG_LIB_FILE_ERROR;
                    goto err_out;
                }
                if (sf_stat.st_size % 32)
                    d += 1;     /* round up, will zero pad unfinished RD */
                if (op->scat_num_lbard) {
                    if (op->scat_num_lbard != (d - 1)) {
                        pr2serr("Command line RD (%u) contradicts value "
                                "calculated from raw SF (%u)\n",
                                 op->scat_num_lbard, d - 1);
                        if (op->scat_num_lbard < (d - 1))
                            d = op->scat_num_lbard + 1;
                        else {
                            pr2serr("Command line RD greater than raw SF "
                                    "file length implies, exit\n");
                            ret = SG_LIB_FILE_ERROR;
                            goto err_out;
                        }
                    }
                }
            } else {
                pr2serr("--scat-file= --raw wants regular file for length\n");
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
            num_lbard = d;
        }

        do_len = (1 + num_lbard) * 32;
        op->scat_lbdof = do_len / op->bs_pi_do;
        if (0 != (do_len % op->bs_pi_do)) { /* if not multiple, round up */
            op->scat_lbdof += 1;
            do_len = ((do_len / op->bs_pi_do) + 1) * op->bs_pi_do;
        }
        if (if_len > 0) {
            do_len += (uint32_t)if_len;
        } else {        /* IF is stdin, a pipe or a device (special) ... */
            op->xfer_bytes = _SC_PAGE_SIZE;        /* ... so need length */
            if (op->bs_pi_do > (op->xfer_bytes / 2))
                op->xfer_bytes = op->bs_pi_do * 3;
            else if (do_len >= (op->xfer_bytes / 2)) {
                op->xfer_bytes *= 4;
                if (do_len >= (op->xfer_bytes / 2)) {
                    op->xfer_bytes *= 4;
                    if (do_len >= (op->xfer_bytes / 2)) {
                        pr2serr("Giving up guessing big enough buffers, "
                                "please use --offset=OFF,DLEN\n");
                        ret = SG_LIB_SYNTAX_ERROR;
                        goto err_out;
                    }
                }
            }
            do_len = op->xfer_bytes;
        }
            if (0 != (do_len % op->bs_pi_do)) /* round up */
                do_len = ((do_len / op->bs_pi_do) + 1) * op->bs_pi_do;
        if (do_len < op->bs_pi_do) {
            pr2serr("failed calculating data-out buffer size (%u)\n",
                    do_len);
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
        d = do_len / op->bs_pi_do;
        if (0 != (do_len % op->bs_pi_do)) {
            d += 1;
            do_len = d * op->bs_pi_do;
        }
        op->xfer_bytes = do_len;
        up = calloc(d, op->bs_pi_do); /* zeroed data-out buffer for SL+DATA */
        if (NULL == up) {
            pr2serr("unable to allocate memory for scatterlist+data\n");
            ret = SG_LIB_OS_BASE_ERR + ENOMEM;
            goto err_out;
        }
        if (op->do_raw) {
            rsl_fd = open(op->scat_filename, O_RDONLY);
            if (rsl_fd < 0) {
                err = errno;
                pr2serr("Failed to open %s for raw read: %s\n",
                        op->scat_filename, safe_strerror(err));
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
            if (sg_set_binary_mode(rsl_fd) < 0) {
                perror("sg_set_binary_mode");
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
            if (sf_stat.st_size < 32) {
                pr2serr("Logic error, how did this happen?\n");
                err = SG_LIB_FILE_ERROR;
                goto err_out;
            }
            res = read(rsl_fd, up, sf_stat.st_size);
            if (res < 0) {
                err = errno;
                pr2serr("Error doing raw read of SF file: %s\n",
                        safe_strerror(err));
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
            if (res < sf_stat.st_size) {
                pr2serr("Short (%u) raw read of SF file, wanted %" PRIu64
                        "\n", (unsigned int)res, sf_stat.st_size);
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
            close(rsl_fd);
            rsl_fd = -1;
        } else if (op->scat_filename) {
            ret = build_t10_scat(op->scat_filename, op->expect_pi_do, up, &d,
                                 &num_lbard, &sum_num,
                                 op->scat_lbdof * op->bs_pi_do);
            if (ret)
                goto err_out;
            op->numblocks = sum_num;
        } else if (addr_arr_len > 0) {  /* build RDs for --addr= --num= */
            for (n = 32, k = 0; k < (int)addr_arr_len; ++k, n += 32) {
                sg_put_unaligned_be64(addr_arr[k], up + n + 0);
                sg_put_unaligned_be32(num_arr[k], up + n + 8);
                sum_num += num_arr[k];
                if (op->do_32) {
                    if (0 == k) {
                        sg_put_unaligned_be32(op->ref_tag, up + n + 12);
                        sg_put_unaligned_be16(op->app_tag, up + n + 16);
                        sg_put_unaligned_be16(op->tag_mask, up + n + 18);
                    } else {
                        sg_put_unaligned_be32((uint32_t)DEF_RT, up + n + 12);
                        sg_put_unaligned_be16((uint16_t)DEF_AT, up + n + 16);
                        sg_put_unaligned_be16((uint16_t)DEF_TM, up + n + 18);
                    }
                }
            }
            op->numblocks = sum_num;
        }
        /* now read data to write component into up */
        d = op->scat_lbdof * op->bs_pi_do;
        if (d > op->xfer_bytes) {
            pr2serr("Logic error in scattered, read data into buffer "
                    "(d=%u)\n", d);
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
        res = read(infd, up + d, op->xfer_bytes - d);
        d = op->xfer_bytes - d;
        if (res < 0) {
            err = errno;
            pr2serr("Error doing read of IF file: %s\n", safe_strerror(err));
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
        if (res < d) {
            pr2serr("Short (%u) read of IF file, wanted %u\n",
                    (unsigned int)res, d);
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
    }
skip_scat_build:        // needs more XXXXXXXXX xxxxxx ???

    if (vb) {
        if (op->do_16 && (! is_pi_default(op)))
            pr2serr("--app-tag=, --ref-tag= and --tag-mask= options ignored "
                    "with 16 byte commands\n");
    }
    if (op->do_same)
        op->xfer_bytes = 1 * op->bs_pi_do;
    else if (op->do_scattered) {
        ;       /* already done, scatter_list+data waiting in 'up' */
    } else
        op->xfer_bytes = op->numblocks * op->bs_pi_do;

    if (! op->do_scattered) {
        if (addr_arr_len > 0) {
            op->lba = addr_arr[0];
            op->numblocks = num_arr[0];
        } else if (op->scat_filename) {
            // need to get first pair or quintet out
            // xxxxxxxxxxxxxxxxxxxxxx
        }
    }

    if (op->ndob) {

    } else if (op->do_scattered)
        wBuff = up;
    else if (op->xfer_bytes > 0) {
        /* fill allocated buffer with zeros */
        wBuff = (unsigned char*)calloc(op->numblocks, op->bs_pi_do);
        if (NULL == wBuff) {
            pr2serr("unable to allocate %" PRId64 " bytes of memory with "
                    "calloc()\n", (int64_t)op->xfer_bytes);
            ret = SG_LIB_OS_BASE_ERR + ENOMEM;
            goto err_out;
        }
        res = read(infd, wBuff, op->xfer_bytes);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, "couldn't read from %s", op->if_name);
            perror(ebuff);
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
        if (op->strict && (res != op->xfer_bytes)) {
            if (vb)
                pr2serr("Wanted to read %" PRId64 " bytes but got %" PRId64
                        " bytes and --strict given\n",
                        (int64_t)op->xfer_bytes, (int64_t)res);
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
    } else if (op->xfer_bytes < 0) {
        pr2serr("Product of block size (%" PRIu32 ") and number of blocks "
                "(%" PRIu32 ") too\nlarge for single read\n", op->bs,
                op->numblocks);
        ret = SG_LIB_SYNTAX_ERROR;
        goto err_out;
    }

    ret = do_write_x(sg_fd, wBuff, op->xfer_bytes, op);
    if (ret) {
        strcpy(b,"OS error");
        if (ret > 0)
            sg_get_category_sense_str(ret, sizeof(b), b, vb);
        pr2serr("%s: %s\n", op->cdb_name, b);
    }

err_out:
    if (wBuff)
        free(wBuff);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("sg_fd close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                return SG_LIB_FILE_ERROR;
        }
    }
    if (rsl_fd >= 0)
        close(rsl_fd);
    if ((! got_stdin) && (infd >= 0)) {
        if (close(infd) < 0) {
            perror("infd close error");
            if (0 == ret)
                return SG_LIB_FILE_ERROR;
        }
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

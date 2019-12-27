/*
 * Copyright (c) 2017-2019 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
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

static const char * version_str = "1.22 20191220";

/* Protection Information refers to 8 bytes of extra information usually
 * associated with each logical block and is often abbreviated to PI while
 * its fields: reference-tag (4 bytes), application-tag (2 bytes) and
 * tag-mask (2 bytes) are often abbreviated to RT, AT and TM respectively.
 * And the LBA Range Descriptor associated with the WRITE SCATTERED command
 * is abbreviated to RD. A degenerate RD is one where length components,
 ( and perhaps the LBA, are zero; it is not illegal according to T10 but are
 * a little tricky to handle when scanning and little extra information
 * is provided. */

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
    {"quiet", no_argument, 0, 'Q'},
    {"ref-tag", required_argument, 0, 'r'},
    {"ref_tag", required_argument, 0, 'r'},
    {"same", required_argument, 0, 'M'},
    {"scat-file", required_argument, 0, 'q'},
    {"scat_file", required_argument, 0, 'q'},
    {"scat-raw", no_argument, 0, 'R'},
    {"scat_raw", no_argument, 0, 'R'},
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
    bool do_16;                 /* default when --32 not given */
    bool do_32;
    bool do_anchor;             /* from  --unmap=U_A , bit 1; WRITE SAME */
    bool do_atomic;             /* selects  WRITE ATOMIC(16 or 32) */
                                /*  --atomic=AB  AB --> .atomic_boundary */
    bool do_combined;           /* -c DOF --> .scat_lbdof */
    bool do_or;                 /* -O  ORWRITE(16 or 32) */
    bool do_quiet;              /* -Q  suppress some messages */
    bool do_scat_raw;
    bool do_same;               /* -M  WRITE SAME(16 or 32) */
                                /*  --same=NDOB  NDOB --> .ndob */
    bool do_scattered;          /* -S  WRITE SCATTERED(16 or 32) */
                                /*  --scattered=RD  RD --> .scat_num_lbard */
    bool do_stream;             /* -T  WRITE STREAM(16 or 32) */
                                /*  --stream=ID  ID --> .str_id */
    bool do_unmap;              /* from --unmap=U_A , bit 0; WRITE SAME */
    bool do_write_normal;       /* -N  WRITE (16 or 32) */
    bool expect_pi_do;          /* expect protection information (PI) which
                                 * is 8 bytes long following each logical
                                 * block in the data out buffer. */
    bool dpo;                   /* "Disable Page Out" bit field */
    bool fua;           /* "Force Unit Access" bit field */
    bool ndob;          /* "No Data-Out Buffer" from --same=NDOB */
    bool verbose_given;
    bool version_given;
    int dld;            /* "Duration Limit Descrptor" bit mask; bit 0 -->
                         * DLD0, bit 1 --> DLD1, bit 2 --> DLD2
                         * only WRITE(16) and WRITE SCATTERED(16) */
    int dry_run;        /* temporary write when used more than once */
    int grpnum;         /* "Group Number", 0 to 0x3f */
    int help;
    int pi_type;        /* -1: unknown: 0: type 0 (none): 1: type 1 */
    int strict;         /* > 0, report then exit on questionable meta data */
    int timeout;        /* timeout (in seconds) to abort SCSI commands */
    int verbose;        /* incremented for each -v */
    int wrprotect;      /* is ORPROTECT field for ORWRITE */
    uint8_t bmop;       /* bit mask operators for ORWRITE(32) */
    uint8_t pgp;        /* previous generation processing for ORWRITE(32) */
    uint16_t app_tag;   /* part of protection information (def: 0xffff) */
    uint16_t atomic_boundary;   /* when 0 atomic write spans given length */
    uint16_t scat_lbdof; /* by construction this must be >= 1 */
    uint16_t scat_num_lbard;    /* RD from --scattered=RD, number of LBA
                                 * Range Descriptors */
    uint16_t str_id;    /* (stream ID) is for WRITE STREAM */
    uint16_t tag_mask;  /* part of protection information (def: 0xffff) */
    uint32_t bs;        /* logical block size (def: 0). 0 implies use READ
                         * CAPACITY(10 or 16) to determine */
    uint32_t bs_pi_do;  /* logical block size plus PI, if any. This value is
                         * used as the actual block size */
    uint32_t if_dlen;   /* bytes to read after .if_offset from .if_name,
                         * if 0 given, read rest of .if_name */
    uint32_t numblocks; /* defaults to 0, number of blocks (of user data) to
                         * write */
    uint32_t orw_eog;   /* from --generation=EOG,NOG (first argument) */
    uint32_t orw_nog;   /* from --generation=EOG,NOG (for ORWRITE) */
    uint32_t ref_tag;   /* part of protection information (def: 0xffffffff) */
    uint64_t lba;       /* "Logical Block Address", for non-scattered use */
    uint64_t if_offset; /* byte offset in .if_name to start reading */
    uint64_t tot_lbs;   /* from READ CAPACITY */
    ssize_t xfer_bytes;     /* derived value: bs_pi_do * numblocks */
                            /* for WRITE SCATTERED .xfer_bytes < do_len */
    const char * device_name;
    const char * if_name;       /* from --in=IF */
    const char * scat_filename; /* from --scat-file=SF */
    const char * cmd_name;      /* e.g. 'Write atomic' */
    char cdb_name[24];          /* e.g. 'Write atomic(16)' */
};

static const char * xx_wr_fname = "sg_write_x.bin";
static const uint32_t lbard_sz = 32;
static const char * lbard_str = "LBA range descriptor";


static void
usage(int do_help)
{
    if (do_help < 2) {
        pr2serr("Usage:\n"
            "sg_write_x [--16] [--32] [--app-tag=AT] [--atomic=AB] "
            "[--bmop=OP,PGP]\n"
            "           [--bs=BS] [--combined=DOF] [--dld=DLD] [--dpo] "
            "[--dry-run]\n"
            "           [--fua] [--generation=EOG,NOG] [--grpnum=GN] "
            "[--help] --in=IF\n"
            "           [--lba=LBA,LBA...] [--normal] [--num=NUM,NUM...]\n"
            "           [--offset=OFF[,DLEN]] [--or] [--quiet] "
            "[--ref-tag=RT]\n"
            "           [--same=NDOB] [--scat-file=SF] [--scat-raw] "
            "[--scattered=RD]\n"
            "           [--stream=ID] [--strict] [--tag-mask=TM] "
            "[--timeout=TO]\n"
            "           [--unmap=U_A] [--verbose] [--version] "
            "[--wrprotect=WRP]\n"
            "           DEVICE\n");
        if (1 != do_help) {
            pr2serr("\nOr the corresponding short option usage:\n"
                "sg_write_x [-6] [-3] [-a AT] [-A AB] [-B OP,PGP] [-b BS] "
                "[-c DOF] [-D DLD]\n"
                "           [-d] [-x] [-f] [-G EOG,NOG] [-g GN] [-h] -i IF "
                "[-l LBA,LBA...]\n"
                "           [-N] [-n NUM,NUM...] [-o OFF[,DLEN]] [-O] [-Q] "
                "[-r RT] [-M NDOB]\n"
                "           [-q SF] [-R] [-S RD] [-T ID] [-s] [-t TM] [-I TO] "
                "[-u U_A] [-v]\n"
                "           [-V] [-w WPR] DEVICE\n"
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
            "    --bs=BS|-b BS      block size (def: use READ CAPACITY), "
            "if power of\n"
            "                       2: logical block size, otherwise: "
            "actual block size\n"
            "    --combined=DOF|-c DOF    scatter list and data combined "
            "for WRITE\n"
            "                             SCATTERED, data starting at "
            "offset DOF which\n"
            "                             has units of sizeof(LB+PI); "
            "sizeof(PI)=8n or 0\n"
            "    --dld=DLD|-D DLD    set duration limit descriptor (dld) "
            "bits (def: 0)\n"
            "    --dpo|-d           set DPO (disable page out) field "
            "(def: clear)\n"
            "    --dry-run|-x       exit just before sending SCSI write "
            "command\n"
            "    --fua|-f           set FUA (force unit access) field "
            "(def: clear)\n"
            "    --generation=EOG,NOG    set Expected ORWgeneration field "
            "to EOG\n"
            "        |-G EOG,NOG         and New ORWgeneration field to "
            "NOG\n"
            );
        pr2serr(
            "    --grpnum=GN|-g GN    GN is group number field (def: 0, "
            "range: 0 to 31)\n"
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
            "    --quiet|-Q         suppress some informational messages\n"
            "    --ref-tag=RT|-r RT     expected reference tag field (def: "
            "0xffffffff)\n"
            "    --same=NDOB|-M NDOB    send WRITE SAME command. NDOB (no "
            "data out buffer)\n"
            "                           can be either 0 (do send buffer) or "
            "1 (don't)\n"
            "    --scat-file=SF|-q SF    file containing LBA, NUM pairs, "
            "see manpage\n"
            "    --scat-raw|-R      read --scat_file=SF as binary (def: "
            "ASCII hex)\n"
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
            "[--bs=BS]\n"
            "             [--dpo] [--fua] [--grpnum=GN] [--lba=LBA] "
            "[--num=NUM]\n"
            "             [--offset=OFF[,DLEN]] [--ref-tag=RT] [--strict] "
            "[--tag-mask=TM]\n"
            "             [--timeout=TO] [--wrprotect=WRP] DEVICE\n"
            "\n"
            "normal WRITE (32) applicable options:\n"
            "  sg_write_x --normal --in=IF --32 [--app-tag=AT] [--bs=BS] "
            "[--dpo] [--fua]\n"
            "             [--grpnum=GN] [--lba=LBA] [--num=NUM] "
            "[--offset=OFF[,DLEN]]\n"
            "             [--ref-tag=RT] [--strict] [--tag-mask=TM] "
            "[--timeout=TO]\n"
            "             [--wrprotect=WRP] DEVICE\n"
            "\n"
            "normal WRITE (16) applicable options:\n"
            "  sg_write_x --normal --in=IF [--16] [--bs=BS] [--dld=DLD] "
            "[--dpo] [--fua]\n"
            "            [--grpnum=GN] [--lba=LBA] [--num=NUM] "
            "[--offset=OFF[,DLEN]]\n"
            "            [--strict] [--timeout=TO] [--verbose] "
            "[--wrprotect=WRP] DEVICE\n"
            "\n"
            "ORWRITE (32) applicable options:\n"
            "  sg_write_x --or --in=IF --32 [--bmop=OP,PGP] [--bs=BS] "
            "[--dpo] [--fua]\n"
            "             [--generation=EOG,NOG] [--grpnum=GN] [--lba=LBA] "
            "[--num=NUM]\n"
            "             [--offset=OFF{,DLEN]] [--strict] [--timeout=TO]\n"
            "             [--wrprotect=ORP] DEVICE\n"
            "\n"
            "ORWRITE (16) applicable options:\n"
            "  sg_write_x --or --in=IF [--16] [--bs=BS] [--dpo] [--fua] "
            "[--grpnum=GN]\n"
            "             [--lba=LBA] [--num=NUM] [--offset=OFF[,DLEN]] "
            "[--strict]\n"
            "             [--timeout=TO] [--wrprotect=ORP] DEVICE\n"
            "\n"
              );
    } else if (3 == do_help) {
        printf("WRITE SAME (32) applicable options:\n"
            "  sg_write_x --same=NDOB --32 [--app-tag=AT] [--bs=BS] "
            "[--grpnum=GN]\n"
            "             [--in=IF] [--lba=LBA] [--num=NUM] "
            "[--offset=OFF[,DLEN]]\n"
            "             [--ref-tag=RT] [--strict] [--tag-mask=TM] "
            "[--timeout=TO]\n"
            "             [--unmap=U_A] [--wrprotect=WRP] DEVICE\n"
            "\n"
            "WRITE SCATTERED (32) applicable options:\n"
            "  sg_write_x --scattered --in=IF --32 [--app-tag=AT] "
            "[--bs=BS]\n"
            "             [--combined=DOF] [--dpo] [--fua] [--grpnum=GN]\n"
            "             [--lba=LBA,LBA...] [--num=NUM,NUM...] "
            "[--offset=OFF[,DLEN]]\n"
            "             [--ref-tag=RT] [--scat-file=SF] [--scat-raw] "
            "[--strict]\n"
            "             [--tag-mask=TM] [--timeout=TO] [--wrprotect=WRP] "
            "DEVICE\n"
            "\n"
            "WRITE SCATTERED (16) applicable options:\n"
            "  sg_write_x --scattered --in=IF [--bs=BS] [--combined=DOF] "
            "[--dld=DLD]\n"
            "             [--dpo] [--fua] [--grpnum=GN] [--lba=LBA,LBA...]\n"
            "             [--num=NUM,NUM...] [--offset=OFF[,DLEN]] "
            "[--scat-raw]\n"
            "             [--scat-file=SF] [--strict] [--timeout=TO] "
            "[--wrprotect=WRP]\n"
            "             DEVICE\n"
            "\n"
            "WRITE STREAM (32) applicable options:\n"
            "  sg_write_x --stream=ID --in=IF --32 [--app-tag=AT] "
            "[--bs=BS] [--dpo]\n"
            "             [--fua] [--grpnum=GN] [--lba=LBA] [--num=NUM]\n"
            "             [--offset=OFF[,DLEN]] [--ref-tag=RT] [--strict] "
            "[--tag-mask=TM]\n"
            "             [--timeout=TO] [--verbose] [--wrprotect=WRP] "
            "DEVICE\n"
            "\n"
            "WRITE STREAM (16) applicable options:\n"
            "  sg_write_x --stream=ID --in=IF [--16] [--bs=BS] [--dpo] "
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
            "optionally --scat-raw\n"
            "   options but only the first lba,num pair is used (any "
            "more are ignored)\n"
            " - when '--rscat-aw --scat-file=SF' are used then the binary "
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

/* Returns 0 if successful, else sg3_utils error code. */
static int
bin_read(int fd, uint8_t * up, uint32_t len, const char * fname)
{
    int res, err;

    res = read(fd, up, len);
    if (res < 0) {
        err = errno;
        pr2serr("Error doing read of %s file: %s\n", fname,
                safe_strerror(err));
        return sg_convert_errno(err);
    }
    if ((uint32_t)res < len) {
        pr2serr("Short (%u) read of %s file, wanted %u\n", (unsigned int)res,
                fname, len);
        return SG_LIB_FILE_ERROR;
    }
    return 0;
}

/* Returns true if num_of_f_chars of ASCII 'f' or 'F' characters are found
 * in sequence. Any leading "0x" or "0X" is ignored; otherwise false is
 * returned (and the comparison stops when the first mismatch is found).
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
 * Returns 0 if ok, else a sg3_utils error code is returned. */
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
        return SG_LIB_LOGIC_ERROR;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *num_arr_len = 0;
    if ('-' == inp[0]) {        /* read from stdin */
        pr2serr("'--len' cannot be read from stdin\n");
        return SG_LIB_SYNTAX_ERROR;
    } else {        /* list of numbers (default decimal) on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfFhHxXiIkKmMgGtTpP, ");
        if (in_len != k) {
            pr2serr("%s: error at pos %d\n", __func__, k + 1);
            return SG_LIB_SYNTAX_ERROR;
        }
        for (k = 0; k < max_arr_len; ++k) {
            ll = sg_get_llnum(lcp);
            if (-1 != ll) {
                if (ll > UINT32_MAX) {
                    pr2serr("%s: number exceeds 32 bits at pos %d\n",
                            __func__, (int)(lcp - inp + 1));
                    return SG_LIB_SYNTAX_ERROR;
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
                pr2serr("%s: error at pos %d\n", __func__,
                        (int)(lcp - inp + 1));
                return SG_LIB_SYNTAX_ERROR;
            }
        }
        *num_arr_len = (uint32_t)(k + 1);
        if (k == max_arr_len) {
            pr2serr("%s: array length exceeded\n", __func__);
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

/* Tries to parse LBA,NUM[,RT,AP,TM] on one line, comma separated. Returns
 * 0 if parsed ok, else 999 if nothing parsed, else error (currently always
 * SG_LIB_SYNTAX_ERROR). If protection information fields not given, then
 * default values are given (i.e. all 0xff bytes). Ignores all spaces and
 * tabs and everything after '#' on lcp (assumed to be an ASCII line that
 * is null terminated). If successful and 'up' is non NULL then writes a
 * LBA range descriptor starting at 'up'. */
static int
parse_scat_pi_line(const char * lcp, uint8_t * up, uint32_t * sum_num)
{
    bool ok;
    int k;
    int64_t ll;
    const char * cp;
    const char * bp;
    char c[1024];

    bp = c;
    cp = strchr(lcp, '#');
    lcp += strspn(lcp, " \t");
    if (('\0' == *lcp) || (cp && (lcp >= cp)))
        return 999;   /* blank line or blank prior to first '#' */
    if (cp) {   /* copy from first non whitespace ... */
        memcpy(c, lcp, cp - lcp);  /* ... to just prior to first '#' */
        c[cp - lcp] = '\0';
    } else {
        /* ... to end of line, including null */
        snprintf(c, sizeof(c), "%s", lcp);
    }
    ll = sg_get_llnum(bp);
    ok = ((-1 != ll) || all_ascii_f_s(bp, 16));
    if (! ok) {
        pr2serr("%s: error reading LBA (first) item on ", __func__);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (up)
        sg_put_unaligned_be64((uint64_t)ll, up + 0);
    ok = false;
    cp = strchr(bp, ',');
    if (cp) {
        bp = cp + 1;
        if (*bp) {
            ll = sg_get_llnum(bp);
            if (-1 != ll)
                ok = true;
        }
    }
    if ((! ok) || (ll > UINT32_MAX)) {
        pr2serr("%s: error reading NUM (second) item on ", __func__);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (up)
        sg_put_unaligned_be32((uint32_t)ll, up + 8);
    if (sum_num)
        *sum_num += (uint32_t)ll;
    /* now for 3 PI items */
    for (k = 0; k < 3; ++k) {
        ok = true;
        cp = strchr(bp, ',');
        if (NULL == cp)
            break;
        bp = cp + 1;
        if (*bp) {
            cp += strspn(bp, " \t");
            if ('\0' == *cp)
                break;
            else if (',' == *cp) {
                if (0 == k)
                    ll = DEF_RT;
                else
                    ll = DEF_AT; /* DEF_AT and DEF_TM have same value */
            } else {
                ll = sg_get_llnum(bp);
                if (-1 == ll)
                    ok = false;
            }
        }
        if (! ok) {
            pr2serr("%s: error reading item %d NUM item on ", __func__,
                    k + 3);
            break;
        }
        switch (k) {
        case 0:
            if (ll > UINT32_MAX) {
                pr2serr("%s: error with item 3, >0xffffffff; on ", __func__);
                ok = false;
            } else if (up)
                sg_put_unaligned_be32((uint32_t)ll, up + 12);
            break;
        case 1:
            if (ll > UINT16_MAX) {
                pr2serr("%s: error with item 4, >0xffff; on ", __func__);
                ok = false;
            } else if (up)
                sg_put_unaligned_be16((uint16_t)ll, up + 16);
            break;
        case 2:
            if (ll > UINT16_MAX) {
                pr2serr("%s: error with item 5, >0xffff; on ", __func__);
                ok = false;
            } else if (up)
                sg_put_unaligned_be16((uint16_t)ll, up + 18);
            break;
        }
        if (! ok)
            break;
    }
    if (! ok)
        return SG_LIB_SYNTAX_ERROR;
    for ( ; k < 3; ++k) {
        switch (k) {
        case 0:
            if (up)
                sg_put_unaligned_be32((uint32_t)DEF_RT, up + 12);
            break;
        case 1:
            if (up)
                sg_put_unaligned_be16((uint16_t)DEF_AT, up + 16);
            break;
        case 2:
            if (up)
                sg_put_unaligned_be16((uint16_t)DEF_TM, up + 18);
            break;
        }
    }
    return 0;
}

/* Read pairs or quintets from a scat_file and places them in a T10 scatter
 * list array is built starting at at t10_scat_list_out (i.e. as per T10 the
 * first 32 bytes are zeros followed by the first LBA range descriptor (also
 * 32 bytes long) then the second LBA range descriptor, etc. The pointer
 * t10_scat_list_out may be NULL in which case the T10 list array is not
 * built but all other operations take place; this can be useful for sizing
 * how large the area holding that list needs to be. The max_list_blen may
 * also be 0. If do_16 is true then only LBA,NUM pairs are expected,
 * loosely formatted with numbers found alternating between LBA and NUM, with
 * an even number of elements required overall. If do_16 is false then a
 * stricter format for quintets is expected: each non comment line should
 * contain: LBA,NUM[,RT,AT,TM] . If RT,AT,TM are not given then they assume
 * their defaults (i.e. 0xffffffff, 0xffff, 0xffff). Each number (64 bits for
 * the LBA, 32 bits for NUM and RT, 16 bit for AT and TM) may be a comma,
 * space or tab separated list. Assumed decimal unless prefixed by '0x', '0X'
 * or contains trailing 'h' or 'H' (which indicate hex). Returns 0 if ok,
 * else error number. If ok also yields the number of LBA range descriptors
 * written in num_scat_elems and the sum of NUM elements found. Note that
 * sum_num is not initialized to 0. If parse_one is true then exits
 * after one LBA range descriptor is decoded. */
static int
build_t10_scat(const char * scat_fname, bool do_16, bool parse_one,
               uint8_t * t10_scat_list_out, uint16_t * num_scat_elems,
               uint32_t * sum_num, uint32_t max_list_blen)
{
    bool have_stdin = false;
    bool bit0, ok;
    int off = 0;
    int in_len, k, j, m, n, res, err;
    int64_t ll;
    char * lcp;
    uint8_t * up = t10_scat_list_out;
    FILE * fp = NULL;
    char line[1024];

    if (up) {
        if (max_list_blen < 64) {
            pr2serr("%s: t10_scat_list_out is too short\n", __func__);
            return SG_LIB_SYNTAX_ERROR;
        }
        memset(up, 0, max_list_blen);
    }
    n = lbard_sz;

    have_stdin = ((1 == strlen(scat_fname)) && ('-' == scat_fname[0]));
    if (have_stdin) {
        fp = stdin;
        scat_fname = "<stdin>";
    } else {
        fp = fopen(scat_fname, "r");
        if (NULL == fp) {
            err = errno;
            pr2serr("%s: unable to open %s: %s\n", __func__, scat_fname,
                    safe_strerror(err));
            return sg_convert_errno(err);
        }
    }
    for (j = 0; j < 1024; ++j) {/* loop over lines in file */
        if ((max_list_blen > 0) && ((n + lbard_sz) > max_list_blen))
            goto fini;
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
        if (! do_16) {
            res = parse_scat_pi_line(lcp, up ? (up + n) : up, sum_num);
            if (999 == res)
                ;
            else if (0 == res) {
                n += lbard_sz;
                if (parse_one)
                    goto fini;
            } else {
                if (SG_LIB_CAT_NOT_READY == res)
                    goto bad_mem_exit;
                pr2serr("line %d in %s\n", j + 1, scat_fname);
                goto bad_exit;
            }
            continue;
        }
        for (k = 0; k < 1024; ++k) {
            ll = sg_get_llnum(lcp);
            ok = ((-1 != ll) || all_ascii_f_s(lcp, 16));
            if (ok) {
                bit0 = !! (0x1 & (off + k));
                if (bit0) {
                    if (ll > UINT32_MAX) {
                        pr2serr("%s: number exceeds 32 bits in line %d, at "
                                "pos %d of %s\n", __func__, j + 1,
                                (int)(lcp - line + 1), scat_fname);
                        goto bad_exit;
                    }
                    if (up)
                        sg_put_unaligned_be32((uint32_t)ll, up + n + 8);
                    if (sum_num)
                        *sum_num += (uint32_t)ll;
                    n += lbard_sz;  /* skip to next LBA range descriptor */
                    if (parse_one)
                        goto fini;
                } else {
                    if (up)
                        sg_put_unaligned_be64((uint64_t)ll, up + n + 0);
                }
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
    if (do_16 && (0x1 & off)) {
        pr2serr("%s: expect LBA,NUM pairs but decoded odd number\n  from "
                "%s\n", __func__, scat_fname);
        goto bad_exit;
    }
fini:
    *num_scat_elems = (n / lbard_sz) - 1;
    if (fp && (stdin != fp))
        fclose(fp);
    return 0;
bad_exit:
    if (fp && (stdin != fp))
        fclose(fp);
    return SG_LIB_SYNTAX_ERROR;
bad_mem_exit:
    if (fp && (stdin != fp))
        fclose(fp);
    return SG_LIB_CAT_NOT_READY;        /* flag output buffer too small */
}

static bool
is_pi_default(const struct opts_t * op)
{
    return ((DEF_AT == op->app_tag) && (DEF_RT == op->ref_tag) &&
            (DEF_TM == op->tag_mask));
}

/* Given a t10 parameter list header (32 zero bytes) for WRITE SCATTERED
 * (16 or 32) followed by n RDs with a total length of at least
 * max_lbrds_blen bytes, find "n" and increment where num_lbard points
 * n times. Further get the LBA length component from each RD and add each
 * length into where sum_num points. Note: the caller probably wants to zero
 * where num_lbard and sum_num point before invoking this function. If all
 * goes well return true, else false. If a degenerate RD is detected then
 * if 'RD' (from --scattered=RD) is 0 then stop looking for further RDs;
 * otherwise keep going. Currently overlapping LBA range descriptors are no
 * checked for. If op->strict > 0 then the first 32 bytes are checked for
 * zeros; any non-zero bytes will report to stderr, stop the check and
 * return false. If op->strict > 0 then the trailing 20 or 12 bytes (only
 * 12 if RT, AT and TM fields (for PI) are present) are checked for zeros;
 * any non-zero bytes cause the same action as the previous check. If
 * the number of RDs (when 'RD' from --scattered=RD > 0) is greater than
 * the number of RDs found then a report is sent to stderr and if op->strict
 * > 0 then returns false, else returns true.  */
static bool
check_lbrds(const uint8_t * up, uint32_t max_lbrds_blen,
            const struct opts_t * op, uint16_t * num_lbard,
            uint32_t * sum_num)
{
    bool ok;
    int k, j, n;
    const int max_lbrd_start = max_lbrds_blen - lbard_sz;
    int vb = op->verbose;

    if (op->strict) {
        if (max_lbrds_blen < lbard_sz) {
            pr2serr("%s: %ss too short (%d < 32)\n", __func__, lbard_str,
                    max_lbrds_blen);
            return false;
        }
        if (! sg_all_zeros(up, lbard_sz)) {
            pr2serr("%s: first 32 bytes of WRITE SCATTERED data-out buffer "
                    "should be zero.\nFound non-zero byte.\n", __func__);
            return false;
        }
    }
    if (max_lbrds_blen < (2 * lbard_sz)) {
        *num_lbard = 0;
        return true;
    }
    n = op->scat_num_lbard ? (int)op->scat_num_lbard : -1;
    for (k = lbard_sz, j = 0; k < max_lbrd_start; k += lbard_sz, ++j) {
        if ((n < 0) && sg_all_zeros(up + k + 0, 12)) { /* degenerate LBA */
            if (vb)   /* ... range descriptor terminator if --scattered=0 */
                pr2serr("%s: degenerate %s stops scan at k=%d (num_rds=%d)\n",
                        __func__, lbard_str, k, j);
            break;
        }
        *sum_num += sg_get_unaligned_be32(up + k + 8);
        *num_lbard += 1;
        if (op->strict) {
            ok = true;
            if (op->wrprotect) {
                if (! sg_all_zeros(up + k + 20, 12))
                    ok = false;
            } else if (! sg_all_zeros(up + k + 12, 20))
                ok = false;
            if (! ok) {
                pr2serr("%s: %s %d non zero in reserved fields\n", __func__,
                        lbard_str, (k / lbard_sz) - 1);
                return false;
            }
        }
        if (n >= 0) {
            if (--n <= 0)
                break;
        }
    }
    if ((k < max_lbrd_start) && op->strict) { /* check pad all zeros */
        k += lbard_sz;
        j = max_lbrds_blen - k;
        if (! sg_all_zeros(up + k, j)) {
            pr2serr("%s: pad (%d bytes) following %ss is non zero\n",
                    __func__, j, lbard_str);
            return false;
        }
    }
    if (vb > 2)
        pr2serr("%s: about to return true, num_lbard=%u, sum_num=%u "
                "[k=%d, n=%d]\n", __func__, *num_lbard, *sum_num, k, n);
    return true;
}

static int
sum_num_lbards(const uint8_t * up, int num_lbards)
{
    int sum = 0;
    int k, n;

    for (k = 0, n = lbard_sz; k < num_lbards; ++k, n += lbard_sz)
        sum += sg_get_unaligned_be32(up + n + 8);
    return sum;
}

/* Returns 0 if successful, else sg3_utils error code. */
static int
do_write_x(int sg_fd, const void * dataoutp, int dout_len,
           const struct opts_t * op)
{
    int k, ret, res, sense_cat, cdb_len, vb, err;
    uint8_t x_cdb[WRITE_X_32_LEN];        /* use for both lengths */
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    memset(x_cdb, 0, sizeof(x_cdb));
    vb = op->verbose;
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
                return SG_LIB_SYNTAX_ERROR;
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
            /* Spec says Buffer Transfer Length field (BTL) is the number
             * of (user) Logical Blocks in the data-out buffer and that BTL
             * may be 0. So the total data-out buffer length in bytes is:
             *      (scat_lbdof + numblocks) * actual_block_size   */
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
            /* ref_tag, app_tag and tag_mask placed in scatter list */
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
        return SG_LIB_SYNTAX_ERROR;
    }

    if (vb > 1) {
        char b[128];

        pr2serr("    %s cdb: %s\n", op->cdb_name,
                sg_get_command_str(x_cdb, cdb_len, false, sizeof(b), b));
    }
    if (op->do_scattered && (vb > 2) && (dout_len > 31)) {
        uint32_t sod_off = op->bs_pi_do * op->scat_lbdof;
        const uint8_t * up = (const uint8_t *)dataoutp;

        pr2serr("    %s scatter list, number of %ss: %u\n", op->cdb_name,
                lbard_str, op->scat_num_lbard);
        pr2serr("      byte offset of data_to_write: %u, dout_len: %d\n",
                sod_off, dout_len);
        up += lbard_sz;       /* step over parameter list header */
        for (k = 0; k < (int)op->scat_num_lbard; ++k, up += lbard_sz) {
            pr2serr("        desc %d: LBA=0x%" PRIx64 " numblocks=%" PRIu32
                    "%s", k, sg_get_unaligned_be64(up + 0),
                    sg_get_unaligned_be32(up + 8), (op->do_16 ? "\n" : " "));
            if (op->do_32)
                pr2serr("rt=0x%x at=0x%x tm=0x%x\n",
                        sg_get_unaligned_be32(up + 12),
                        sg_get_unaligned_be16(up + 16),
                        sg_get_unaligned_be16(up + 18));
            if ((uint32_t)(((k + 2) * lbard_sz) + 20) > sod_off) {
                pr2serr("Warning: possible clash of descriptor %u with "
                        "data_to_write\n", k);
                if (op->strict > 1)
                    return SG_LIB_FILE_ERROR;
            }
        }
    }
    if ((vb > 3) && (dout_len > 0)) {
        if ((dout_len > 1024) && (vb < 7)) {
            pr2serr("    Data-out buffer contents (first 1024 of %u "
                    "bytes):\n", dout_len);
            hex2stdout((const uint8_t *)dataoutp, 1024, 1);
            pr2serr("    Above: dout's first 1024 of %u bytes [%s]\n",
                    dout_len, op->cdb_name);
        } else {
            pr2serr("    Data-out buffer contents (length=%u):\n", dout_len);
            hex2stderr((const uint8_t *)dataoutp, (int)dout_len, 1);
        }
    }
    if (op->dry_run) {
        if (vb)
            pr2serr("Exit just before sending %s due to --dry-run\n",
                    op->cdb_name);
        if (op->dry_run > 1) {
            int w_fd;

            w_fd = open(xx_wr_fname, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (w_fd < 0) {
                err = errno;
                perror(xx_wr_fname);
                return sg_convert_errno(err);
            }
            res = write(w_fd, dataoutp, dout_len);
            if (res < 0) {
                err = errno;
                perror(xx_wr_fname);
                close(w_fd);
                return sg_convert_errno(err);
            }
            close(w_fd);
            printf("Wrote %u bytes to %s", dout_len, xx_wr_fname);
            if (op->do_scattered)
                printf(", LB data offset: %u\nNumber of %ss: %u\n",
                       op->scat_lbdof, lbard_str, op->scat_num_lbard);
            else
                printf("\n");
        }
        return 0;
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", op->cdb_name);
        return sg_convert_errno(ENOMEM);
    }
    set_scsi_pt_cdb(ptvp, x_cdb, cdb_len);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    if (dout_len > 0)
        set_scsi_pt_data_out(ptvp, (uint8_t *)dataoutp, dout_len);
    else if (vb && (! op->ndob))
        pr2serr("%s:  dout_len==0, so empty dout buffer\n",
                op->cdb_name);
    res = do_scsi_pt(ptvp, sg_fd, op->timeout, vb);
    ret = sg_cmds_process_resp(ptvp, op->cdb_name, res, true /*noisy */, vb,
                               &sense_cat);
    if (-1 == ret)
        ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
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
                    if (op->do_scattered) {
                        if (0 == ull)
                            pr2serr("%s=<not reported>\n", lbard_str);
                        else
                            pr2serr("%s=%" PRIu64 " (origin 0)\n", lbard_str,
                                    ull - 1);
                        if (sg_get_sense_cmd_spec_fld(sense_b, slen, &ull)) {
                            if (0 == ull)
                                pr2serr("  Number of successfully written "
                                        "%ss is 0 or not reported\n",
                                        lbard_str);
                            else
                                pr2serr("  Number of successfully written "
                                        "%ss is %u\n", lbard_str,
                                        (uint32_t)ull);
                        }
                    } else
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

/* Returns 0 if successful, else sg3_utils error code. */
static int
do_read_capacity(int sg_fd, struct opts_t *op)
{
    bool prot_en = false;
    int res;
    int vb = op->verbose;
    char b[80];
    uint8_t resp_buff[RCAP16_RESP_LEN];

    res = sg_ll_readcap_16(sg_fd, false /* pmi */, 0 /* llba */, resp_buff,
                           RCAP16_RESP_LEN, true, (vb ? (vb - 1): 0));
    if (SG_LIB_CAT_UNIT_ATTENTION == res) {
        pr2serr("Read capacity(16) unit attention, try again\n");
        res = sg_ll_readcap_16(sg_fd, false, 0, resp_buff, RCAP16_RESP_LEN,
                               true, (vb ? (vb - 1): 0));
    }
    if (0 == res) {
        uint32_t pi_len = 0;

        if (vb > 3) {
            pr2serr("Read capacity(16) response:\n");
            hex2stderr(resp_buff, RCAP16_RESP_LEN, 1);
        }
        op->bs = sg_get_unaligned_be32(resp_buff + 8);
        op->tot_lbs = sg_get_unaligned_be64(resp_buff + 0) + 1;
        prot_en = !!(resp_buff[12] & 0x1);
        if (prot_en) {
            uint32_t pi_exp;

            op->pi_type = ((resp_buff[12] >> 1) & 0x7) + 1;
            pi_exp = 0xf & (resp_buff[13] >> 4);
            pi_len = 8 * (1 << pi_exp);
            if (op->wrprotect > 0) {
                op->bs_pi_do = op->bs + pi_len;
                if (vb > 1)
                    pr2serr("  For data out buffer purposes the effective "
                            "block size is %u (lb size\n  is %u) because "
                            "PROT_EN=1, PI_EXP=%u and WRPROTECT>0\n", op->bs,
                            pi_exp, op->bs_pi_do);
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
            pr2serr("  Last_LBA=0x%" PRIx64 "  LB size: %u (with PI: "
                    "%u) bytes  p_type=%u\n", op->tot_lbs - 1,
                    op->bs, op->bs + (prot_en ? pi_len : 0),
                    ((resp_buff[12] >> 1) & 0x7));
            pr2serr("  prot_en=%u [PI type=%u] p_i_exp=%u  lbppb_exp=%u  "
                    "lbpme,rz=%u,", prot_en, op->pi_type,
                    ((resp_buff[13] >> 4) & 0xf), (resp_buff[13] & 0xf),
                    !!(resp_buff[14] & 0x80));
            memcpy(d, resp_buff + 14, 2);
            d[0] &= 0x3f;
            pr2serr("%u  low_ali_lba=%u\n", !!(resp_buff[14] & 0x40),
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
                hex2stderr(resp_buff, RCAP10_RESP_LEN, 1);
            }
            op->tot_lbs = sg_get_unaligned_be32(resp_buff + 0) + 1;
            op->bs = sg_get_unaligned_be32(resp_buff + 4);
        } else {
            strcpy(b,"OS error");
            if (res > 0)
                sg_get_category_sense_str(res, sizeof(b), b, vb);
            else
                snprintf(b, sizeof(b), "error: %d", res);
            pr2serr("Read capacity(10): %s\n", b);
            pr2serr("Unable to calculate block size\n");
            return (res > 0) ? res : SG_LIB_FILE_ERROR;
        }
    } else {
        if (vb) {
            strcpy(b,"OS error");
            if (res > 0)
                sg_get_category_sense_str(res, sizeof(b), b, vb);
            pr2serr("Read capacity(16): %s\n", b);
            pr2serr("Unable to calculate block size\n");
        }
        return (res > 0) ? res : SG_LIB_FILE_ERROR;
    }
    op->bs_pi_do = op->expect_pi_do ? (op->bs + 8) : op->bs;
    return 0;
}

#define WANT_ZERO_EXIT 9999
static const char * const opt_long_ctl_str =
    "36a:A:b:B:c:dD:Efg:G:hi:I:l:M:n:No:Oq:Qr:RsS:t:T:u:vVw:x";

/* command line processing, options and arguments. Returns 0 if ok,
 * returns WANT_ZERO_EXIT so upper level yields an exist status of zero.
 * Other return values (mainly SG_LIB_SYNTAX_ERROR) indicate errors. */
static int
parse_cmd_line(struct opts_t *op, int argc, char *argv[],
               const char ** lba_opp, const char ** num_opp)
{
    bool fail_if_strict = false;
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
            if ((j < 0) || (j > (int)UINT16_MAX)) {
                pr2serr("bad argument to '--app-tag='. Expect 0 to 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->app_tag = (uint16_t)j;
            break;
        case 'A':
            j = sg_get_num(optarg);
            if ((j < 0) || (j > (int)UINT16_MAX)) {
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
            if (j > 0) {
                int k;
                int m = j;
                int highest_ind;

                if (j < 512) {
                    pr2serr("warning: --bs=BS value is < 512 which seems too "
                            "small, continue\n");
                    fail_if_strict = true;
                }
                if (0 != (j % 8)) {
                    pr2serr("warning: --bs=BS value is not a multiple of 8, "
                            "unexpected, continue\n");
                    fail_if_strict = true;
                }
                for (k = 0, highest_ind = 0; k < 28; ++ k, m >>= 1) {
                    if (1 & m)
                        highest_ind = k;
                }       /* loop should get log_base2(j) */
                k = 1 << highest_ind;
                if (j == k) {   /* j is a power of two; actual and logical
                                 * block size is assumed to be the same */
                    op->bs = (uint32_t)j;
                    op->bs_pi_do = op->bs;
                } else {  /* j is not power_of_two, use as actual LB size */
                    op->bs = (uint32_t)k;       /* power_of_two less than j */
                    op->bs_pi_do = (uint32_t)j;
                }
            } else {    /* j==0, let READCAP sort this out */
                op->bs = 0;
                op->bs_pi_do = 0;
            }
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
            op->if_offset = (uint64_t)ll;
            if ((cp = strchr(optarg, ','))) {
                ll = sg_get_llnum(cp + 1);
                if (-1 == ll) {
                    pr2serr("bad second argument to '--offset='\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                if (ll > UINT32_MAX) {
                    pr2serr("bad second argument to '--offset=', cannot "
                            "exceed 32 bits\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->if_dlen = (uint32_t)ll;
            }
            break;
        case 'O':
            op->do_or = true;
            op->cmd_name = "Orwrite";
            break;
        case 'q':
            op->scat_filename = optarg;
            break;
        case 'Q':
            op->do_quiet = true;
            break;
        case 'R':
            op->do_scat_raw = true;
            break;
        case 'r':               /* same as --ref-tag= */
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--ref-tag='. Expect 0 to "
                        "0xffffffff inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->ref_tag = (uint32_t)ll;
            break;
        case 's':
            ++op->strict;
            break;
        case 'S':
            j = sg_get_num(optarg);
            if ((j < 0) || (j > (int)UINT16_MAX)) {
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
            if ((j < 0) || (j > (int)UINT16_MAX)) {
                pr2serr("bad argument to '--tag-mask='. Expect 0 to 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->tag_mask = (uint16_t)j;
            break;
        case 'T':               /* WRITE STREAM */
            j = sg_get_num(optarg);
            if ((j < 0) || (j > (int)UINT16_MAX)) {
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
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'w':       /* WRPROTECT field (or ORPROTECT for ORWRITE) */
            op->wrprotect = sg_get_num(optarg);
            if ((op->wrprotect < 0) || (op->wrprotect > 7))  {
                pr2serr("bad argument to '--wrprotect'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->expect_pi_do = (op->wrprotect > 0);
            break;
        case 'x':
            ++op->dry_run;
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
    if (op->strict && fail_if_strict)
        return SG_LIB_SYNTAX_ERROR;
    return 0;
}

static int
process_scattered(int sg_fd, int infd, uint32_t if_len, uint32_t if_rlen,
                  int sfr_fd, uint32_t sf_len, uint64_t * addr_arr,
                  uint32_t addr_arr_len, uint32_t * num_arr,
                  uint16_t num_lbard, uint32_t sum_num, struct opts_t * op)
{
    int k, n, ret;
    int vb = op->verbose;
    uint32_t d, dd, nn, do_len;
    uint8_t * up = NULL;
    uint8_t * free_up = NULL;
    char b[80];

    if (op->do_combined) {      /* --combined=DOF (.scat_lbdof) */
        if (op->scat_lbdof > 0)
            d = op->scat_lbdof * op->bs_pi_do;
        else if (op->scat_num_lbard > 0) {
            d = lbard_sz * (1 + op->scat_num_lbard);
            if (0 != (d % op->bs_pi_do))
                d = ((d / op->bs_pi_do) + 1) * op->bs_pi_do;
        } else if (if_len > 0) {
            d = if_len;
            if (0 != (d % op->bs_pi_do))
                d = ((d / op->bs_pi_do) + 1) * op->bs_pi_do;
        } else {
            pr2serr("With --combined= if DOF, RD are 0 and IF has an "
                    "unknown length\nthen give up\n");
            return SG_LIB_CONTRADICT;
        }
        up = sg_memalign(d, 0, &free_up, false);
        if (NULL == up) {
            pr2serr("unable to allocate aligned memory for "
                    "scatterlist+data\n");
            return sg_convert_errno(ENOMEM);
        }
        ret = bin_read(infd, up, ((if_len < d) ? if_len : d), "IF c1");
        if (ret)
            goto finii;
        if (! check_lbrds(up, d, op, &num_lbard, &sum_num))
            goto file_err_outt;
        if ((op->scat_num_lbard > 0) && (op->scat_num_lbard != num_lbard)) {
            bool rd_gt = (op->scat_num_lbard > num_lbard);

            if (rd_gt || op->strict || vb) {
                pr2serr("RD (%u) %s number of %ss (%u) found in IF\n",
                        op->scat_num_lbard, (rd_gt ? ">" : "<"), lbard_str,
                        num_lbard);
                if (rd_gt)
                    goto file_err_outt;
                else if (op->strict)
                    goto file_err_outt;
            }
            num_lbard = op->scat_num_lbard;
            sum_num = sum_num_lbards(up, op->scat_num_lbard);
        } else
            op->scat_num_lbard = num_lbard;
        dd = lbard_sz * (num_lbard + 1);
        if (0 != (dd % op->bs_pi_do))
            dd = ((dd / op->bs_pi_do) + 1) * op->bs_pi_do; /* round up */
        nn = op->scat_lbdof * op->bs_pi_do;
        if (dd != nn) {
            bool dd_gt = (dd > nn);

            if (dd_gt) {
                pr2serr("%s: Cannot fit %ss (%u) in given LB data offset "
                        "(%u)\n", __func__, lbard_str, num_lbard,
                        op->scat_lbdof);
                goto file_err_outt;
            }
            if (vb || op->strict)
                pr2serr("%s: empty blocks before LB data offset (%u), could "
                        "be okay\n", __func__, op->scat_lbdof);
            if (op->strict) {
                pr2serr("Exiting due to --strict; perhaps try again with "
                        "--combined=%u\n", dd / op->bs_pi_do);
                goto file_err_outt;
            }
            dd = nn;
        }
        dd += (sum_num * op->bs_pi_do);
        if (dd > d) {
            uint8_t * u2p;
            uint8_t * free_u2p;

            if (dd != if_len) {
                bool dd_gt = (dd > if_len);

                if (dd_gt || op->strict || vb) {
                    pr2serr("Calculated dout length (%u) %s bytes available "
                            "in IF (%u)\n", dd, (dd_gt ? ">" : "<"), if_len);
                    if (dd_gt)
                        goto file_err_outt;
                    else if (op->strict)
                        goto file_err_outt;
                }
            }
            u2p = sg_memalign(dd, 0, &free_u2p, false);
            if (NULL == u2p) {
                pr2serr("unable to allocate memory for final "
                        "scatterlist+data\n");
                ret = sg_convert_errno(ENOMEM);
                goto finii;
            }
            memcpy(u2p, up, d);
            free(free_up);
            up = u2p;
            free_up = free_u2p;
            ret = bin_read(infd, up + d, dd - d, "IF c2");
            if (ret)
                goto finii;
        }
        do_len = dd;
        op->numblocks = sum_num;
        op->xfer_bytes = sum_num * op->bs_pi_do;
        goto do_io;
    }

    /* other than do_combined, so --scat-file= or --lba= */
    if (addr_arr_len > 0)
        num_lbard = addr_arr_len;

    if (op->scat_filename && (! op->do_scat_raw)) {
        d = lbard_sz * (num_lbard + 1);
        nn = d;
        op->scat_lbdof = d / op->bs_pi_do;
        if (0 != (d % op->bs_pi_do))  /* if not multiple, round up */
            op->scat_lbdof += 1;
        dd = op->scat_lbdof * op->bs_pi_do;
        d = sum_num * op->bs_pi_do;
        do_len = dd + d;
        /* zeroed data-out buffer for SL+DATA */
        up = sg_memalign(do_len, 0, &free_up, false);
        if (NULL == up) {
            pr2serr("unable to allocate aligned memory for "
                    "scatterlist+data\n");
            return sg_convert_errno(ENOMEM);
        }
        num_lbard = 0;
        sum_num = 0;
        nn = (nn > lbard_sz) ? nn : (op->scat_lbdof *  op->bs_pi_do);
        ret = build_t10_scat(op->scat_filename, op->do_16, ! op->do_scattered,
                             up, &num_lbard, &sum_num, nn);
        if (ret)
            goto finii;
        /* Calculate number of bytes to read from IF (place in 'd') */
        d = sum_num * op->bs_pi_do;
        if (op->if_dlen > d) {
            if (op->strict || vb) {
                pr2serr("DLEN > than bytes implied by sum of scatter "
                        "list NUMs (%u)\n", d);
                if (vb > 1)
                    pr2serr("  num_lbard=%u, sum_num=%u actual_bs=%u",
                            num_lbard, sum_num, op->bs_pi_do);
                if (op->strict)
                    goto file_err_outt;
            }
        } else if ((op->if_dlen > 0) && (op->if_dlen < d))
            d = op->if_dlen;
        if ((if_rlen > 0) && (if_rlen != d)) {
            bool readable_lt = (if_rlen < d);

            if (vb)
                pr2serr("readable length (%u) of IF %s bytes implied by "
                        "sum of\nscatter list NUMs (%u) and DLEN\n",
                        (uint32_t)if_rlen,
                        readable_lt ? "<" : ">", d);
            if (op->strict) {
                if ((op->strict > 1) || (! readable_lt))
                    goto file_err_outt;
            }
            if (readable_lt)
                d = if_rlen;
        }
        if (0 != (d % op->bs_pi_do)) {
            if (vb || (op->strict > 1)) {
                pr2serr("Calculated data-out length (0x%x) not a "
                        "multiple of BS (%u", d, op->bs);
                if (op->bs != op->bs_pi_do)
                    pr2serr(" + %d(PI)", (int)op->bs_pi_do - (int)op->bs);
                if (op->strict > 1) {
                    pr2serr(")\nexiting ...\n");
                    goto file_err_outt;
                } else
                    pr2serr(")\nzero pad and continue ...\n");
            }
        }
        ret = bin_read(infd, up + (op->scat_lbdof * op->bs_pi_do), d,
                       "IF 3");
        if (ret)
            goto finii;
        do_len = ((op->scat_lbdof + sum_num) * op->bs_pi_do);
        op->numblocks = sum_num;
        op->xfer_bytes = sum_num * op->bs_pi_do;
        /* dout for scattered write with ASCII scat_file ready */
    } else if (op->do_scat_raw) {
        bool if_len_gt = false;

        /* guessing game for length of buffer */
        if (op->scat_num_lbard > 0) {
            dd = (op->scat_num_lbard + 1) * lbard_sz;
            if (sf_len < dd) {
                pr2serr("SF not long enough (%u bytes) to provide RD "
                        "(%u) %ss\n", sf_len, dd, lbard_str);
                goto file_err_outt;
            }
            nn = dd / op->bs_pi_do;
            if (0 != (dd % op->bs_pi_do))
                nn +=1;
            dd = nn * op->bs_pi_do;
        } else
            dd = op->bs_pi_do;      /* guess */
        if (if_len > 0) {
            nn = if_len / op->bs_pi_do;
            if (0 != (if_len % op->bs_pi_do))
                nn += 1;
            d = nn * op->bs_pi_do;
        } else
            d = op->bs_pi_do;      /* guess one LB */
        /* zero data-out buffer for SL+DATA */
        nn = dd + d;
        up = sg_memalign(nn, 0, &free_up, false);
        if (NULL == up) {
            pr2serr("unable to allocate aligned memory for "
                    "scatterlist+data\n");
            ret = sg_convert_errno(ENOMEM);
            goto finii;
        }
        ret = bin_read(sfr_fd, up, sf_len, "SF");
        if (ret)
            goto finii;
        if (! check_lbrds(up, dd, op, &num_lbard, &sum_num))
            goto file_err_outt;
        if (num_lbard != op->scat_num_lbard) {
            pr2serr("Try again with --scattered=%u\n", num_lbard);
            goto file_err_outt;
        }
        if ((sum_num * op->bs_pi_do) > d) {
            uint8_t * u2p;
            uint8_t * free_u2p;

            d = sum_num * op->bs_pi_do;
            nn = dd + d;
            u2p = sg_memalign(nn, 0, &free_u2p, false);
            if (NULL == u2p) {
                pr2serr("unable to allocate memory for final "
                        "scatterlist+data\n");
                ret = sg_convert_errno(ENOMEM);
                goto finii;
            }
            memcpy(u2p, up, dd);
            free(free_up);
            up = u2p;
            free_up = free_u2p;
        }
        if ((if_len != (nn - d)) && (op->strict || vb)) {
            if_len_gt = (if_len > (nn - d));
            pr2serr("IF length (%u) %s 'sum_num' bytes (%u), ", if_len,
                    (if_len_gt ? ">" : "<"), nn - d);
            if (op->strict > 1) {
                pr2serr("exiting (strict=%d)\n", op->strict);
                goto file_err_outt;
            } else
                pr2serr("continuing ...\n");
        }
        ret = bin_read(infd, up + d, (if_len_gt ? nn - d : if_len), "IF 4");
        if (ret)
            goto finii;
        do_len = (num_lbard + sum_num) * op->bs_pi_do;
        op->numblocks = sum_num;
        op->xfer_bytes = sum_num * op->bs_pi_do;
    } else if (addr_arr_len > 0) {  /* build RDs for --lba= --num= */
        if ((op->scat_num_lbard > 0) && (op->scat_num_lbard > addr_arr_len)) {
            pr2serr("%s: number given to --scattered= (%u) exceeds number of "
                    "--lba= elements (%u)\n", __func__, op->scat_num_lbard,
                    addr_arr_len);
            return SG_LIB_CONTRADICT;
        }
        d = lbard_sz * (num_lbard + 1);
        op->scat_lbdof = d / op->bs_pi_do;
        if (0 != (d % op->bs_pi_do))  /* if not multiple, round up */
            op->scat_lbdof += 1;
        for (sum_num = 0, k = 0; k < (int)addr_arr_len; ++k)
            sum_num += num_arr[k];
        do_len = ((op->scat_lbdof + sum_num) * op->bs_pi_do);
        up = sg_memalign(do_len, 0, &free_up, false);
        if (NULL == up) {
            pr2serr("unable to allocate aligned memory for "
                    "scatterlist+data\n");
            ret = sg_convert_errno(ENOMEM);
            goto finii;
        }
        for (n = lbard_sz, k = 0; k < (int)addr_arr_len; ++k,
             n += lbard_sz) {
            sg_put_unaligned_be64(addr_arr[k], up + n + 0);
            sg_put_unaligned_be32(num_arr[k], up + n + 8);
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
    } else {
        pr2serr("How did we get here??\n");
        goto syntax_err_outt;
    }
do_io:
    ret = do_write_x(sg_fd, up, do_len, op);
    if (ret) {
        strcpy(b,"OS error");
        if (ret > 0)
            sg_get_category_sense_str(ret, sizeof(b), b, vb);
        pr2serr("%s: %s\n", op->cdb_name, b);
    }
    goto finii;

syntax_err_outt:
    ret = SG_LIB_SYNTAX_ERROR;
    goto finii;
file_err_outt:
    ret = SG_LIB_FILE_ERROR;
finii:
    if (free_up)
        free(free_up);
    return ret;
}


int
main(int argc, char * argv[])
{
    bool got_stdin = false;
    bool got_stat = false;
    bool if_reg_file = false;
    int n, err, vb;
    int infd = -1;
    int sg_fd = -1;
    int sfr_fd = -1;
    int ret = -1;
    uint32_t nn, addr_arr_len, num_arr_len;     /* --lba= */
    uint32_t do_len = 0;
    uint16_t num_lbard = 0;
    uint32_t if_len = 0;    /* after accounting for OFF,DLEN and moving file
                             * file pointer to OFF, is bytes available in IF */
    uint32_t sf_len = 0;
    uint32_t sum_num = 0;
    ssize_t res;
    off_t if_readable_len = 0;  /* similar to if_len but doesn't take DLEN
                                 * into account */
    struct opts_t * op;
    const char * lba_op = NULL;
    const char * num_op = NULL;
    uint8_t * up = NULL;
    uint8_t * free_up = NULL;
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
    op->app_tag = DEF_AT;       /* 2 bytes of protection information */
    op->tag_mask = DEF_TM;      /* final 2 bytes of protection information */
    op->timeout = DEF_TIMEOUT_SECS;

    /* Process command line */
    ret = parse_cmd_line(op, argc, argv, &lba_op, &num_op);
    if (ret) {
        if (WANT_ZERO_EXIT == ret)
            return 0;
        return ret;
    }
    if (op->help > 0) {
        usage(op->help);
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
        pr2serr("sg_write_x version: %s\n", version_str);
        return WANT_ZERO_EXIT;
    }

    vb = op->verbose;
    /* sanity checks */
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
        return SG_LIB_CONTRADICT;
    } else if (n < 1) {
        if (op->strict) {
            pr2serr("With --strict won't default to a normal WRITE, add "
                    "--normal\n");
            return SG_LIB_CONTRADICT;
        } else {
            op->do_write_normal = true;
            op->cmd_name = "Write";
            if (vb)
                pr2serr("No command selected so choose 'normal' WRITE\n");
        }
    }
    snprintf(op->cdb_name, sizeof(op->cdb_name), "%s(%d)", op->cmd_name,
             (op->do_16 ? 16 : 32));
    if (op->do_combined) {
        if (! op->do_scattered) {
            pr2serr("--combined=DOF only allowed with --scattered=RD (i.e. "
                    "only with\nWRITE SCATTERED command)\n");
            return SG_LIB_CONTRADICT;
        }
        if (op->scat_filename) {
            pr2serr("Ambiguous: got --combined=DOF and --scat-file=SF .\n"
                    "Give one, the other or neither\n");
            return SG_LIB_CONTRADICT;
        }
        if (lba_op || num_op) {
            pr2serr("--scattered=RD --combined=DOF does not use --lba= or "
                    "--num=\nPlease remove.\n");
            return SG_LIB_CONTRADICT;
        }
        if (op->do_scat_raw) {
            pr2serr("Ambiguous: don't expect --combined=DOF and --scat-raw\n"
                    "Give one or the other\n");
            return SG_LIB_CONTRADICT;
        }
    }
    if ((NULL == op->scat_filename) && op->do_scat_raw) {
        pr2serr("--scat-raw only applies to the --scat-file=SF option\n"
                "--scat-raw without the --scat-file=SF option is an "
                "error\n");
        return SG_LIB_CONTRADICT;
    }
    n = (!! op->scat_filename) + (!! (lba_op || num_op)) +
        (!! op->do_combined);
    if (n > 1) {
        pr2serr("want one and only one of: (--lba=LBA and/or --num=NUM), or\n"
                "--scat-file=SF, or --combined=DOF\n");
        return SG_LIB_CONTRADICT;
    }
    if (op->scat_filename && (1 == strlen(op->scat_filename)) &&
        ('-' == op->scat_filename[0])) {
        pr2serr("don't accept '-' (implying stdin) as a filename in "
                "--scat-file=SF\n");
        return SG_LIB_CONTRADICT;
    }
    if (vb && op->do_16 && (! is_pi_default(op)))
        pr2serr("--app-tag=, --ref-tag= and --tag-mask= options ignored "
                "with 16 byte commands\n");

    /* examine .if_name . Open, move to .if_offset, calculate length that we
     * want to read. */
    if (! op->ndob) {           /* as long as --same=1 is not active */
        if_len = op->if_dlen;   /* from --offset=OFF,DLEN; defaults to 0 */
        if (NULL == op->if_name) {
            pr2serr("Need --if=FN option to be given, exiting.\n");
            if (vb > 1)
                pr2serr("To write zeros use --in=/dev/zero\n");
            pr2serr("\n");
            usage((op->help > 0) ? op->help : 0);
            return SG_LIB_SYNTAX_ERROR;
        }
        if ((1 == strlen(op->if_name)) && ('-' == op->if_name[0])) {
            got_stdin = true;
            infd = STDIN_FILENO;
            if (sg_set_binary_mode(STDIN_FILENO) < 0) {
                perror("sg_set_binary_mode");
                return SG_LIB_FILE_ERROR;
            }
        } else {
            if ((infd = open(op->if_name, O_RDONLY)) < 0) {
                err = errno;
                snprintf(ebuff, EBUFF_SZ, "could not open %s for reading",
                         op->if_name);
                perror(ebuff);
                return sg_convert_errno(err);
            }
            if (sg_set_binary_mode(infd) < 0) {
                perror("sg_set_binary_mode");
                return SG_LIB_FILE_ERROR;
            }
            if (fstat(infd, &if_stat) < 0) {
                err = errno;
                snprintf(ebuff, EBUFF_SZ, "could not fstat %s", op->if_name);
                perror(ebuff);
                return sg_convert_errno(err);
            }
            got_stat = true;
            if (S_ISREG(if_stat.st_mode)) {
                if_reg_file = true;
                if_readable_len = if_stat.st_size;
                if (0 == if_len)
                    if_len = if_readable_len;
            }
        }
        if (got_stat && if_readable_len &&
            ((int64_t)op->if_offset >= (if_readable_len - 1))) {
            pr2serr("Offset (%" PRIu64 ") is at or beyond IF byte length (%"
                    PRIu64 ")\n", op->if_offset, (uint64_t)if_readable_len);
            goto file_err_out;
        }
        if (op->if_offset > 0) {
            off_t off = op->if_offset;
            off_t h = if_readable_len;

            if (if_reg_file) {
                /* lseek() won't work with stdin, pipes or sockets, etc */
                if (lseek(infd, off, SEEK_SET) < 0) {
                    err = errno;
                    snprintf(ebuff,  EBUFF_SZ, "couldn't offset to required "
                            "position on %s", op->if_name);
                    perror(ebuff);
                    ret = sg_convert_errno(err);
                    goto err_out;
                }
                if_readable_len -= op->if_offset;
                if (if_readable_len <= 0) {
                    pr2serr("--offset [0x%" PRIx64 "] at or beyond file "
                            "length[0x%" PRIx64 "]\n",
                            (uint64_t)op->if_offset, (uint64_t)h);
                    goto file_err_out;
                }
                if (op->strict && ((off_t)op->if_dlen > if_readable_len)) {
                    pr2serr("after accounting for OFF, DLEN exceeds %s "
                            "remaining length (%u bytes)\n",
                            op->if_name, (uint32_t)if_readable_len);
                    goto file_err_out;
                }
                if_len = (uint32_t)((if_readable_len < (off_t)if_len) ?
                                if_readable_len : (off_t)if_len);
                if (vb > 2)
                    pr2serr("Moved IF byte pointer to %u, if_len=%u, "
                            "if_readable_len=%u\n", (uint32_t)op->if_offset,
                            if_len, (uint32_t)if_readable_len);
            } else {
                if (vb)
                    pr2serr("--offset=OFF ignored when IF is stdin, pipe, "
                            "socket, etc\nDLEN, if given, is used\n");
            }
        }
    }
    /* Check device name has been given */
    if (NULL == op->device_name) {
        pr2serr("missing device name!\n");
        usage((op->help > 0) ? op->help : 0);
        goto syntax_err_out;
    }

    /* Open device file, do READ CAPACITY(16, maybe 10) if no BS */
    sg_fd = sg_cmds_open_device(op->device_name, false /* rw */, vb);
    if (sg_fd < 0) {
        if (op->verbose)
            pr2serr("open error: %s: %s\n", op->device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }
    if (0 == op->bs) {  /* ask DEVICE about logical/actual block size */
        ret = do_read_capacity(sg_fd, op);
        if (ret)
            goto err_out;
    }
    if ((0 == op->bs_pi_do) || (0 == op->bs)) {
        pr2serr("Logic error, need block size by now\n");
        goto syntax_err_out;
    }
    if (! op->ndob) {
        if (0 != (if_len % op->bs_pi_do)) {
            if (op->strict > 1) {
                pr2serr("Error: number of bytes to read from IF [%u] is "
                        "not a multiple\nblock size %u (including "
                        "protection information)\n", (unsigned int)if_len,
                        op->bs_pi_do);
                goto file_err_out;
            }
            if (op->strict || vb)
                pr2serr("Warning: number of bytes to read from IF [%u] is "
                        "not a multiple\nof actual block size %u; pad with "
                        "zeros\n", (unsigned int)if_len, op->bs_pi_do);
        }
    }

    /* decode --lba= and --num= options */
    memset(addr_arr, 0, sizeof(addr_arr));
    memset(num_arr, 0, sizeof(num_arr));
    addr_arr_len = 0;
    num_arr_len = 0;
    if (lba_op) {
        if (0 != build_lba_arr(lba_op, addr_arr, &addr_arr_len,
                               MAX_NUM_ADDR)) {
            pr2serr("bad argument to '--lba'\n");
            goto syntax_err_out;
        }
    }
    if (num_op) {
        if (0 != build_num_arr(num_op, num_arr, &num_arr_len,
                               MAX_NUM_ADDR)) {
            pr2serr("bad argument to '--num'\n");
            goto err_out;
        }
    }
    if (((addr_arr_len > 1) && (addr_arr_len != num_arr_len)) ||
        ((0 == addr_arr_len) && (num_arr_len > 1))) {
        /* allow all combinations of 0 or 1 element --lba= with 0 or 1
         * element --num=, otherwise this error ... */
        pr2serr("need same number of arguments to '--lba=' and '--num=' "
                    "options\n");
        ret = SG_LIB_CONTRADICT;
        goto err_out;
    }
    if ((0 == addr_arr_len) && (1 == num_arr_len)) {
        if (num_arr[0] > 0) {
            pr2serr("won't write %u blocks without an explicit --lba= "
                    "option\n", num_arr[0]);
            goto syntax_err_out;
        }
        addr_arr_len = 1;  /* allow --num=0 without --lba= since it is safe */
    }
    /* Everything can use a SF, except --same=1 (when op->ndob==true) */
    if (op->scat_filename) {
        if (stat(op->scat_filename, &sf_stat) < 0) {
            err = errno;
            pr2serr("Unable to stat(%s) as SF: %s\n", op->scat_filename,
                    safe_strerror(err));
            ret = sg_convert_errno(err);
            goto err_out;
        }
        if (op->do_scat_raw) {
            if (! S_ISREG(sf_stat.st_mode)) {
                pr2serr("Expect scatter file to be a regular file\n");
                goto file_err_out;
            }
            sf_len = sf_stat.st_size;
            sfr_fd = open(op->scat_filename, O_RDONLY);
            if (sfr_fd < 0) {
                err = errno;
                pr2serr("Failed to open %s for raw read: %s\n",
                        op->scat_filename, safe_strerror(err));
                ret = sg_convert_errno(err);
                goto err_out;
            }
            if (sg_set_binary_mode(sfr_fd) < 0) {
                perror("sg_set_binary_mode");
                goto file_err_out;
            }
        } else { /* scat_file should contain ASCII hex, preliminary parse */
            nn = (op->scat_num_lbard > 0) ?
                                lbard_sz * (1 + op->scat_num_lbard) : 0;
            ret = build_t10_scat(op->scat_filename, op->do_16,
                                 ! op->do_scattered, NULL, &num_lbard,
                                 &sum_num, nn);
            if (ret)
                goto err_out;
            if ((op->scat_num_lbard > 0) &&
                (num_lbard != op->scat_num_lbard)) {
                bool rd_gt = (op->scat_num_lbard > num_lbard);

                if (rd_gt || op->strict || vb) {
                    pr2serr("RD (%u) %s number of %ss (%u) found in SF\n",
                            op->scat_num_lbard, (rd_gt ? ">" : "<"),
                            lbard_str, num_lbard);
                    if (rd_gt)
                        goto file_err_out;
                    else if (op->strict)
                        goto file_err_out;
                }
            }
        }
    }

    if (op->do_scattered) {
        ret = process_scattered(sg_fd, infd, if_len, if_readable_len, sfr_fd,
                                sf_len, addr_arr, addr_arr_len, num_arr,
                                num_lbard, sum_num, op);
        goto fini;
    }

    /* other than scattered */
    if (addr_arr_len > 0) {
        op->lba = addr_arr[0];
        op->numblocks = num_arr[0];
        if (vb && (addr_arr_len > 1))
            pr2serr("warning: %d LBA,number_of_blocks pairs found, only "
                    "taking first\n", addr_arr_len);
    } else if (op->scat_filename && (! op->do_scat_raw)) {
        uint8_t upp[96];

        sum_num = 0;
        ret = build_t10_scat(op->scat_filename, op->do_16,
                             true /* parse one */, upp, &num_lbard,
                             &sum_num, sizeof(upp));
        if (ret)
            goto err_out;
        if (vb && (num_lbard > 1))
            pr2serr("warning: %d LBA,number_of_blocks pairs found, only "
                    "taking first\n", num_lbard);
        if (vb > 2)
            pr2serr("after build_t10_scat, num_lbard=%u, sum_num=%u\n",
                    num_lbard, sum_num);
        if (1 != num_lbard) {
            pr2serr("Unable to decode one LBA range descriptor from %s\n",
                    op->scat_filename);
            goto file_err_out;
        }
        op->lba = sg_get_unaligned_be64(upp + 32 + 0);
        op->numblocks = sg_get_unaligned_be32(upp + 32 + 8);
        if (op->do_32) {
            op->ref_tag = sg_get_unaligned_be32(upp + 32 + 12);
            op->app_tag = sg_get_unaligned_be16(upp + 32 + 16);
            op->tag_mask = sg_get_unaligned_be16(upp + 32 + 18);
        }
    } else if (op->do_scat_raw) {
        uint8_t upp[64];

        if (sf_len < (2 * lbard_sz)) {
            pr2serr("raw scatter file must be at least 64 bytes long "
                    "(length: %u)\n", sf_len);
            goto file_err_out;
        }
        ret = bin_read(sfr_fd, upp, sizeof(upp), "SF");
        if (ret)
            goto err_out;
        if (! check_lbrds(upp, sizeof(upp), op, &num_lbard, &sum_num))
            goto file_err_out;
        if (1 != num_lbard) {
            pr2serr("No %ss found in SF (num=%u)\n", lbard_str, num_lbard);
            goto file_err_out;
        }
        op->lba = sg_get_unaligned_be64(upp + 16);
        op->numblocks = sg_get_unaligned_be32(upp + 16 + 8);
        do_len = sum_num * op->bs_pi_do;
        op->xfer_bytes = do_len;
    } else {
        pr2serr("No LBA or number_of_blocks given, try using --lba= and "
                "--num=\n");
        goto syntax_err_out;
    }
    if (op->do_same)
        op->xfer_bytes = op->ndob ? 0 : op->bs_pi_do;
    else    /* WRITE, ORWRITE, WRITE ATOMIC or WRITE STREAM */
        op->xfer_bytes = op->numblocks * op->bs_pi_do;
    do_len = op->xfer_bytes;

    if (do_len > 0) {
        /* fill allocated buffer with zeros */
        up = sg_memalign(do_len, 0, &free_up, false);
        if (NULL == up) {
            pr2serr("unable to allocate %u bytes of memory\n", do_len);
            ret = sg_convert_errno(ENOMEM);
            goto err_out;
        }
        ret = bin_read(infd, up, ((if_len < do_len) ? if_len : do_len),
                       "IF 5");
        if (ret)
            goto fini;
    } else
        up = NULL;

    ret = do_write_x(sg_fd, up, do_len, op);
    if (ret && (! op->do_quiet)) {
        strcpy(b,"OS error");
        if (ret > 0)
            sg_get_category_sense_str(ret, sizeof(b), b, vb);
        pr2serr("%s: %s\n", op->cdb_name, b);
    }
    goto fini;

syntax_err_out:
    ret = SG_LIB_SYNTAX_ERROR;
    goto err_out;
file_err_out:
    ret = SG_LIB_FILE_ERROR;
err_out:
fini:
    if (free_up)
        free(free_up);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            if (! op->do_quiet)
                pr2serr("sg_fd close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = SG_LIB_FILE_ERROR;
        }
    }
    if (sfr_fd >= 0) {
        if (close(sfr_fd) < 0) {
            if (! op->do_quiet)
                perror("sfr_fd close error");
            if (0 == ret)
                ret = SG_LIB_FILE_ERROR;
        }
    }
    if ((! got_stdin) && (infd >= 0)) {
        if (close(infd) < 0) {
            if (! op->do_quiet)
                perror("infd close error");
            if (0 == ret)
                ret = SG_LIB_FILE_ERROR;
        }
    }
    if ((0 == op->verbose) && (! op->do_quiet)) {
        if (! sg_if_can2stderr("sg_write_x failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

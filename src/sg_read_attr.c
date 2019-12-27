/*
 * Copyright (c) 2016-2019 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <errno.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues the SCSI READ ATTRIBUTE command to the given SCSI device
 * and decodes the response. Based on spc5r08.pdf
 */

static const char * version_str = "1.13 20191220";

#define MAX_RATTR_BUFF_LEN (1024 * 1024)
#define DEF_RATTR_BUFF_LEN (1024 * 8)

#define SG_READ_ATTRIBUTE_CMD 0x8c
#define SG_READ_ATTRIBUTE_CMDLEN 16

#define RA_ATTR_VAL_SA 0x0
#define RA_ATTR_LIST_SA 0x1
#define RA_LV_LIST_SA 0x2
#define RA_PART_LIST_SA 0x3
#define RA_SMC2_SA 0x4
#define RA_SUP_ATTR_SA 0x5
#define RA_HIGHEST_SA 0x5

#define RA_FMT_BINARY 0x0
#define RA_FMT_ASCII 0x1
#define RA_FMT_TEXT 0x2         /* takes into account locale */
#define RA_FMT_RES 0x3          /* reserved */


#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

struct opts_t {
    bool cache;
    bool enumerate;
    bool do_raw;
    bool o_readonly;
    bool verbose_given;
    bool version_given;
    int elem_addr;
    int filter;
    int fai;
    int do_hex;
    int lvn;
    int maxlen;
    int pn;
    int quiet;
    int sa;
    int verbose;
};

struct acron_nv_t {
    const char * acron;
    const char * name;
    int val;
};

struct attr_name_info_t {
    int id;
    const char * name;  /* tab ('\t') suggest line break */
    int format;         /* RA_FMT_BINARY and friends, -1 --> unknown */
    int len;            /* -1 --> not fixed (variable) */
    int process;        /* 0 --> print decimal if binary, 1 --> print hex,
                         * 2 --> further processing */
};

static struct option long_options[] = {
    {"cache", no_argument, 0, 'c'},
    {"enumerate", no_argument, 0, 'e'},
    {"element", required_argument, 0, 'E'},   /* SMC-3 element address */
    {"filter", required_argument, 0, 'f'},
    {"first", required_argument, 0, 'F'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"in", required_argument, 0, 'i'},
    {"lvn", required_argument, 0, 'l'},
    {"maxlen", required_argument, 0, 'm'},
    {"partition", required_argument, 0, 'p'},
    {"quiet", required_argument, 0, 'q'},
    {"raw", no_argument, 0, 'r'},
    {"readonly", no_argument, 0, 'R'},
    {"sa", required_argument, 0, 's'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},   /* sentinel */
};

static struct acron_nv_t sa_acron_arr[] = {
    {"av", "attribute values", 0},
    {"al", "attribute list", 1},
    {"lvl", "logical volume list", 2},
    {"pl", "partition list", 3},
    {"smc", "SMC-2 should define this", 4},
    {"sa", "supported attributes", 5},
    {NULL, NULL, -1},           /* sentinel */
};

static struct attr_name_info_t attr_name_arr[] = {
/* Device type attributes */
    {0x0, "Remaining capacity in partition [MiB]", RA_FMT_BINARY, 8, 0},
    {0x1, "Maximum capacity in partition [MiB]", RA_FMT_BINARY, 8, 0},
    {0x2, "TapeAlert flags", RA_FMT_BINARY, 8, 0},   /* SSC-4 */
    {0x3, "Load count", RA_FMT_BINARY, 8, 0},
    {0x4, "MAM space remaining [B]", RA_FMT_BINARY, 8, 0},
    {0x5, "Assigning organization", RA_FMT_ASCII, 8, 0}, /* SSC-4 */
    {0x6, "Format density code", RA_FMT_BINARY, 1, 1},    /* SSC-4 */
    {0x7, "Initialization count", RA_FMT_BINARY, 2, 0},
    {0x8, "Volume identifier", RA_FMT_ASCII, 32, 0},
    {0x9, "Volume change reference", RA_FMT_BINARY, -1, 1}, /* SSC-4 */
    {0x20a, "Density vendor/serial number at last load", RA_FMT_ASCII, 40, 0},
    {0x20b, "Density vendor/serial number at load-1", RA_FMT_ASCII, 40, 0},
    {0x20c, "Density vendor/serial number at load-2", RA_FMT_ASCII, 40, 0},
    {0x20d, "Density vendor/serial number at load-3", RA_FMT_ASCII, 40, 0},
    {0x220, "Total MiB written in medium life", RA_FMT_BINARY, 8, 0},
    {0x221, "Total MiB read in medium life", RA_FMT_BINARY, 8, 0},
    {0x222, "Total MiB written in current/last load", RA_FMT_BINARY, 8, 0},
    {0x223, "Total MiB read in current/last load", RA_FMT_BINARY, 8, 0},
    {0x224, "Logical position of first encrypted block", RA_FMT_BINARY, 8, 2},
    {0x225, "Logical position of first unencrypted block\tafter first "
     "encrypted block", RA_FMT_BINARY, 8, 2},
    {0x340, "Medium usage history", RA_FMT_BINARY, 90, 2},
    {0x341, "Partition usage history", RA_FMT_BINARY, 60, 2},

/* Medium type attributes */
    {0x400, "Medium manufacturer", RA_FMT_ASCII, 8, 0},
    {0x401, "Medium serial number", RA_FMT_ASCII, 32, 0},
    {0x402, "Medium length [m]", RA_FMT_BINARY, 4, 0},      /* SSC-4 */
    {0x403, "Medium width [0.1 mm]", RA_FMT_BINARY, 4, 0},  /* SSC-4 */
    {0x404, "Assigning organization", RA_FMT_ASCII, 8, 0},  /* SSC-4 */
    {0x405, "Medium density code", RA_FMT_BINARY, 1, 1},    /* SSC-4 */
    {0x406, "Medium manufacture date", RA_FMT_ASCII, 8, 0},
    {0x407, "MAM capacity [B]", RA_FMT_BINARY, 8, 0},
    {0x408, "Medium type", RA_FMT_BINARY, 1, 1},
    {0x409, "Medium type information", RA_FMT_BINARY, 2, 1},
    {0x40a, "Numeric medium serial number", -1, -1, 1},

/* Host type attributes */
    {0x800, "Application vendor", RA_FMT_ASCII, 8, 0},
    {0x801, "Application name", RA_FMT_ASCII, 32, 0},
    {0x802, "Application version", RA_FMT_ASCII, 8, 0},
    {0x803, "User medium text label", RA_FMT_TEXT, 160, 0},
    {0x804, "Date and time last written", RA_FMT_ASCII, 12, 0},
    {0x805, "Text localization identifier", RA_FMT_BINARY, 1, 0},
    {0x806, "Barcode", RA_FMT_ASCII, 32, 0},
    {0x807, "Owning host textual name", RA_FMT_TEXT, 80, 0},
    {0x808, "Media pool", RA_FMT_TEXT, 160, 0},
    {0x809, "Partition user text label", RA_FMT_ASCII, 16, 0},
    {0x80a, "Load/unload at partition", RA_FMT_BINARY, 1, 0},
    {0x80a, "Application format version", RA_FMT_ASCII, 16, 0},
    {0x80c, "Volume coherency information", RA_FMT_BINARY, -1, 1},
     /* SSC-5 */
    {0x820, "Medium globally unique identifier", RA_FMT_BINARY, 36, 1},
    {0x821, "Media pool globally unique identifier", RA_FMT_BINARY, 36, 1},

    {-1, NULL, -1, -1, 0},
};


static void
usage()
{
    pr2serr("Usage: sg_read_attr [--cache] [--element=EA] [--enumerate] "
            "[--filter=FL]\n"
            "                    [--first=FAI] [--help] [--hex] [--in=FN] "
            "[--lvn=LVN]\n"
            "                    [--maxlen=LEN] [--partition=PN] [--quiet] "
            "[--raw]\n"
            "                    [--readonly] [--sa=SA] [--verbose] "
            "[--version]\n"
            "                    DEVICE\n");
    pr2serr("  where:\n"
            "    --cache|-c         set CACHE bit in cdn (def: clear)\n"
            "    --enumerate|-e     enumerate known attributes and service "
            "actions\n"
            "    --element=EA|-E EA    EA is placed in 'element address' "
            "field in\n"
            "                          cdb [SMC-3] (def: 0)\n"
            "    --filter=FL|-f FL    FL is parameter code to match (def: "
            "-1 -> all)\n"
            "    --first=FAI|-F FAI    FAI is placed in 'first attribute "
            "identifier'\n"
            "                          field in cdb (def: 0)\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           output response in hexadecimal; used "
            "twice\n"
            "                       shows decoded values in hex\n"
            "    --in=FN|-i FN      FN is a filename containing attribute "
            "values in\n"
            "                       ASCII hex or binary if --raw also "
            "given\n"
            "    --lvn=LVN|-l LVN    logical volume number (LVN) (def:0)\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> 8192 bytes)\n"
            "    --partition=PN|-p PN    partition number (PN) (def:0)\n"
            "    --quiet|-q         reduce the amount of output, can use "
            "more than once\n"
            "    --raw|-r           output response in binary\n"
            "    --readonly|-R      open DEVICE read-only (def: read-write)\n"
            "    --sa=SA|-s SA      SA is service action (def: 0)\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n\n"
            "Performs a SCSI READ ATTRIBUTE command. Even though it is "
            "defined in\nSPC-3 and later it is typically used on tape "
            "systems.\n");
}

/* Invokes a SCSI READ ATTRIBUTE command (SPC+SMC).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_read_attr(int sg_fd, void * resp, int * residp, bool noisy,
                const struct opts_t * op)
{
    int ret, res, sense_cat;
    uint8_t ra_cdb[SG_READ_ATTRIBUTE_CMDLEN] =
          {SG_READ_ATTRIBUTE_CMD, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
           0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    ra_cdb[1] = 0x1f & op->sa;
    if (op->elem_addr)
        sg_put_unaligned_be16(op->elem_addr, ra_cdb + 2);
    if (op->lvn)
        ra_cdb[5] = 0xff & op->lvn;
    if (op->pn)
        ra_cdb[7] = 0xff & op->pn;
    if (op->fai)
        sg_put_unaligned_be16(op->fai, ra_cdb + 8);
    sg_put_unaligned_be32((uint32_t)op->maxlen, ra_cdb + 10);
    if (op->cache)
        ra_cdb[14] |= 0x1;
    if (op->verbose) {
        char b[128];

        pr2serr("    Read attribute cdb: %s\n",
                sg_get_command_str(ra_cdb, SG_READ_ATTRIBUTE_CMDLEN, false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, ra_cdb, sizeof(ra_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, op->maxlen);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, op->verbose);
    ret = sg_cmds_process_resp(ptvp, "read attribute", res, noisy,
                               op->verbose, &sense_cat);
    if (-1 == ret)
        ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
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
    } else
        ret = 0;
    if (residp)
        *residp = get_scsi_pt_resid(ptvp);
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

static int
find_sa_acron(const char * cp)
{
    int k;
    const struct acron_nv_t * anvp;
    const char * mp;

    for (anvp = sa_acron_arr; anvp->acron ; ++anvp) {
        for (mp = cp, k = 0; *mp; ++mp, ++k) {
            if (0 == anvp->acron[k])
                return anvp->val;
            if (tolower(*mp) != anvp->acron[k])
                break;
        }
        if ((0 == *mp) && (0 == anvp->acron[k]))
            return anvp->val;
    }
    return -1;  /* not found */
}

const char * a_format[] = {
    "binary",
    "ascii",
    "text",
    "format[0x3]",
};

static void
enum_attributes(void)
{
    const struct attr_name_info_t * anip;
    const char * cp;
    char b[32];

    printf("Attribute ID\tLength\tFormat\tName\n");
    printf("------------------------------------------\n");
    for (anip = attr_name_arr; anip->name ; ++anip) {
        if (anip->format < 0)
            snprintf(b, sizeof(b), "unknown");
        else
            snprintf(b, sizeof(b), "%s", a_format[0x3 & anip->format]);
        printf("  0x%04x:\t%d\t%s\t", anip->id, anip->len, b);
        cp = strchr(anip->name, '\t');
        if (cp ) {
            printf("%.*s\n", (int)(cp - anip->name), anip->name);
            printf("\t\t\t\t%s\n", cp + 1);
        } else
            printf("%s\n", anip->name);
    }
}

static void
enum_sa_acrons(void)
{
    const struct acron_nv_t * anvp;

    printf("SA_value\tAcronym\tDescription\n");
    printf("------------------------------------------\n");
    for (anvp = sa_acron_arr; anvp->acron ; ++anvp)
        printf("  %d:\t\t%s\t%s\n", anvp->val, anvp->acron, anvp->name);
}

/* Returns 1 if 'bp' all 0xff bytes, returns 2 is all 0xff bytes apart
 * from last being 0xfe; otherwise returns 0. */
static int
all_ffs_or_last_fe(const uint8_t * bp, int len)
{
    for ( ; len > 0; ++bp, --len) {
        if (*bp < 0xfe)
            return 0;
        if (0xfe == *bp)
            return (1 == len) ? 2 : 0;

    }
    return 1;
}

static char *
attr_id_lookup(unsigned int id, const struct attr_name_info_t ** anipp,
               int blen, char * b)
{
    const struct attr_name_info_t * anip;

    for (anip = attr_name_arr; anip->name; ++anip) {
        if (id == (unsigned int)anip->id)
            break;
    }
    if (anip->name) {
        snprintf(b, blen, "%s", anip->name);
        if (anipp)
            *anipp = anip;
        return b;
    }
    if (anipp)
        *anipp = NULL;
    if (id < 0x400)
        snprintf(b, blen, "Unknown device attribute 0x%x", id);
    else if (id < 0x800)
        snprintf(b, blen, "Unknown medium attribute 0x%x", id);
    else if (id < 0xc00)
        snprintf(b, blen, "Unknown host attribute 0x%x", id);
    else if (id < 0x1000)
        snprintf(b, blen, "Vendor specific device attribute 0x%x", id);
    else if (id < 0x1400)
        snprintf(b, blen, "Vendor specific medium attribute 0x%x", id);
    else if (id < 0x1800)
        snprintf(b, blen, "Vendor specific host attribute 0x%x", id);
    else
        snprintf(b, blen, "Reserved attribute 0x%x", id);
    return b;
}

static void
decode_attr_list(const uint8_t * alp, int len, bool supported,
                 const struct opts_t * op)
{
    int id;
    char b[160];
    char * cp;
    char * c2p;
    const char * leadin = supported ? "Supported a" : "A";

    if (op->verbose)
        printf("%sttribute list: [len=%d]\n", leadin, len);
    else if (0 == op->quiet)
        printf("%sttribute list:\n", leadin);
    if (op->do_hex) {
        hex2stdout(alp, len, 0);
        return;
    }
    for ( ; len > 0; alp += 2, len -= 2) {
        id = sg_get_unaligned_be16(alp + 0);
        if ((op->filter >= 0) && (op->filter != id))
            continue;
        if (op->verbose)
            printf("  0x%.4x:\t", id);
        cp = attr_id_lookup(id, NULL, sizeof(b), b);
        c2p = strchr(cp, '\t');
        if (c2p) {
            printf("  %.*s -\n", (int)(c2p - cp), cp);
            if (op->verbose)
                printf("\t\t      %s\n", c2p + 1);
            else
                printf("      %s\n", c2p + 1);
        } else
            printf("  %s\n", cp);
    }
}

static void
helper_full_attr(const uint8_t * alp, int len, int id,
                 const struct attr_name_info_t * anip,
                 const struct opts_t * op)
{
    int k;
    const uint8_t * bp;

    if (op->verbose)
        printf("[r%c] ", (0x80 & alp[2]) ? 'o' : 'w');
    if (op->verbose > 3)
        pr2serr("%s: id=0x%x, len=%d, anip->format=%d, anip->len=%d\n",
                __func__, id, len, anip->format, anip->len);
    switch (id) {
    case 0x224:         /* logical position of first encrypted block */
        k = all_ffs_or_last_fe(alp + 5, len - 5);
        if (1 == k)
            printf("<unknown> [ff]\n");
        else if (2 == k)
            printf("<unknown [fe]>\n");
        else {
            if ((len - 5) <= 8)
                printf("%" PRIx64, sg_get_unaligned_be(len - 5, alp + 5));
            else {
                printf("\n");
                hex2stdout((alp + 5), len - 5, 0);
            }
        }
        break;
    case 0x225:         /* logical position of first unencrypted block
                         * after first encrypted block */
        k = all_ffs_or_last_fe(alp + 5, len - 5);
        if (1 == k)
            printf("<unknown> [ff]\n");
        else if (2 == k)
            printf("<unknown [fe]>\n");
        else {
            if ((len - 5) <= 8)
                printf("%" PRIx64, sg_get_unaligned_be(len - 5, alp + 5));
            else {
                printf("\n");
                hex2stdout(alp + 5, len - 5, 0);
            }
        }
        break;
    case 0x340:         /* Medium Usage history */
        bp = alp + 5;
        printf("\n");
        if ((len - 5) < 90) {
            pr2serr("%s: expected 90 bytes, got %d\n", __func__, len - 5);
            break;
        }
        printf("    Current amount of data written [MiB]: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 0));
        printf("    Current write retry count: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 6));
        printf("    Current amount of data read [MiB]: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 12));
        printf("    Current read retry count: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 18));
        printf("    Previous amount of data written [MiB]: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 24));
        printf("    Previous write retry count: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 30));
        printf("    Previous amount of data read [MiB]: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 36));
        printf("    Previous read retry count: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 42));
        printf("    Total amount of data written [MiB]: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 48));
        printf("    Total write retry count: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 54));
        printf("    Total amount of data read [MiB]: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 60));
        printf("    Total read retry count: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 66));
        printf("    Load count: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 72));
        printf("    Total change partition count: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 78));
        printf("    Total partition initialization count: %" PRIu64 "\n",
               sg_get_unaligned_be48(bp + 84));
        break;
    case 0x341:         /* Partition Usage history */
        bp = alp + 5;
        printf("\n");
        if ((len - 5) < 60) {
            pr2serr("%s: expected 60 bytes, got %d\n", __func__, len - 5);
            break;
        }
        printf("    Current amount of data written [MiB]: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 0));
        printf("    Current write retry count: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 4));
        printf("    Current amount of data read [MiB]: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 8));
        printf("    Current read retry count: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 12));
        printf("    Previous amount of data written [MiB]: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 16));
        printf("    Previous write retry count: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 20));
        printf("    Previous amount of data read [MiB]: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 24));
        printf("    Previous read retry count: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 28));
        printf("    Total amount of data written [MiB]: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 32));
        printf("    Total write retry count: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 36));
        printf("    Total amount of data read [MiB]: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 40));
        printf("    Total read retry count: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 44));
        printf("    Load count: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 48));
        printf("    change partition count: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 52));
        printf("    partition initialization count: %" PRIu32 "\n",
               sg_get_unaligned_be32(bp + 56));
        break;
    default:
        pr2serr("%s: unknown attribute id: 0x%x\n", __func__, id);
        printf("  In hex:\n");
        hex2stdout(alp, len, 0);
        break;
    }
}

static void
decode_attr_vals(const uint8_t * alp, int len, const struct opts_t * op)
{
    int bump, id, alen;
    uint64_t ull;
    char * cp;
    char * c2p;
    const struct attr_name_info_t * anip;
    char b[160];

    if (op->verbose)
        printf("Attribute values: [len=%d]\n", len);
    else if (op->filter < 0) {
        if (0 == op->quiet)
            printf("Attribute values:\n");
        if (op->do_hex) {       /* only expect -HH to get through here */
            hex2stdout(alp, len, 0);
            return;
        }
    }
    for ( ; len > 4; alp += bump, len -= bump) {
        id = sg_get_unaligned_be16(alp + 0);
        bump = sg_get_unaligned_be16(alp + 3) + 5;
        alen = bump - 5;
        if ((op->filter >= 0) && (op->filter != id)) {
            if (id < op->filter)
                continue;
            else
                break;  /* Assume array is ascending id order */
        }
        anip = NULL;
        cp = attr_id_lookup(id, &anip, sizeof(b), b);
        if (op->quiet < 2) {
            c2p = strchr(cp, '\t');
            if (c2p) {
                printf("  %.*s -\n", (int)(c2p - cp), cp);
                printf("      %s: ", c2p + 1);
            } else
                printf("  %s: ", cp);
        }
        if (op->verbose)
            printf("[r%c] ", (0x80 & alp[2]) ? 'o' : 'w');
        if (anip) {
            if ((RA_FMT_BINARY == anip->format) && (bump <= 13)) {
                ull = sg_get_unaligned_be(alen, alp + 5);
                if (0 == anip->process)
                    printf("%" PRIu64 "\n", ull);
                else if (1 == anip->process)
                    printf("0x%" PRIx64 "\n", ull);
                else
                    helper_full_attr(alp, bump, id, anip, op);
                if (op->verbose) {
                    if ((anip->len > 0) && (alen > 0) && (alen != anip->len))
                        printf(" <<< T10 length (%d) differs from length in "
                               "response (%d) >>>\n", anip->len, alen);
                }
            } else if (RA_FMT_BINARY == anip->format) {
                if (2 == anip->process)
                    helper_full_attr(alp, bump, id, anip, op);
                else {
                    printf("\n");
                    hex2stdout(alp + 5, alen, 0);
                }
           } else {
                if (2 == anip->process)
                    helper_full_attr(alp, bump, id, anip, op);
                else {
                    printf("%.*s\n", alen, alp + 5);
                    if (op->verbose) {
                        if ((anip->len > 0) && (alen > 0) &&
                            (alen != anip->len))
                            printf(" <<< T10 length (%d) differs from length "
                                   "in response (%d) >>>\n", anip->len, alen);
                    }
                }
            }
        } else {
            if (op->verbose > 1)
                printf("Attribute id lookup failed, in hex:\n");
            else
                printf("\n");
            hex2stdout(alp + 5, alen, 0);
        }
    }
    if (op->verbose && (len > 0) && (len <= 4))
        pr2serr("warning: iterate of attributes should end a residual of "
                "%d\n", len);
}

static void
decode_all_sa_s(const uint8_t * rabp, int len, const struct opts_t * op)
{
    if (op->do_hex && (2 != op->do_hex)) {
        hex2stdout(rabp, len, ((1 == op->do_hex) ? 1 : -1));
        return;
    }
    switch (op->sa) {
    case RA_ATTR_VAL_SA:
        decode_attr_vals(rabp + 4, len - 4, op);
        break;
    case RA_ATTR_LIST_SA:
        decode_attr_list(rabp + 4, len - 4, false, op);
        break;
    case RA_LV_LIST_SA:
        if ((0 == op->quiet) || op->verbose)
            printf("Logical volume list:\n");
        if (len < 4) {
            pr2serr(">>> response length unexpectedly short: %d bytes\n",
                    len);
            break;
        }
        printf("  First logical volume number: %u\n", rabp[2]);
        printf("  Number of logical volumes available: %u\n", rabp[3]);
        break;
    case RA_PART_LIST_SA:
        if ((0 == op->quiet) || op->verbose)
            printf("Partition number list:\n");
        if (len < 4) {
            pr2serr(">>> response length unexpectedly short: %d bytes\n",
                    len);
            break;
        }
        printf("  First partition number: %u\n", rabp[2]);
        printf("  Number of partitions available: %u\n", rabp[3]);
        break;
    case RA_SMC2_SA:
        printf("Used by SMC-2, not information, output in hex:\n");
        hex2stdout(rabp, len, 0);
        break;
    case RA_SUP_ATTR_SA:
        decode_attr_list(rabp + 4, len - 4, true, op);
        break;
    default:
        printf("Unrecognized service action [0x%x], response in hex:\n",
               op->sa);
        hex2stdout(rabp, len, 0);
        break;
    }
}

int
main(int argc, char * argv[])
{
    int sg_fd, res, c, len, resid, rlen;
    unsigned int ra_len;
    int in_len = 0;
    int ret = 0;
    const char * device_name = NULL;
    const char * fname = NULL;
    uint8_t * rabp = NULL;
    uint8_t * free_rabp = NULL;
    struct opts_t opts;
    struct opts_t * op;
    char b[80];

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->filter = -1;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ceE:f:F:hHi:l:m:p:qrRs:vV",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            op->cache = true;
            break;
        case 'e':
            op->enumerate = true;
            break;
        case 'E':
           op->elem_addr = sg_get_num(optarg);
           if ((op->elem_addr < 0) || (op->elem_addr > 65535)) {
                pr2serr("bad argument to '--element=EA', expect 0 to 65535\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'f':
           op->filter = sg_get_num(optarg);
           if ((op->filter < -3) || (op->filter > 65535)) {
                pr2serr("bad argument to '--filter=FL', expect -3 to "
                        "65535\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'F':
           op->fai = sg_get_num(optarg);
           if ((op->fai < 0) || (op->fai > 65535)) {
                pr2serr("bad argument to '--first=FAI', expect 0 to 65535\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            fname = optarg;
            break;
        case 'l':
           op->lvn = sg_get_num(optarg);
           if ((op->lvn < 0) || (op->lvn > 255)) {
                pr2serr("bad argument to '--lvn=LVN', expect 0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'm':
            op->maxlen = sg_get_num(optarg);
            if ((op->maxlen < 0) || (op->maxlen > MAX_RATTR_BUFF_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or "
                        "less\n", MAX_RATTR_BUFF_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'p':
           op->pn = sg_get_num(optarg);
           if ((op->pn < 0) || (op->pn > 255)) {
                pr2serr("bad argument to '--pn=PN', expect 0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'q':
            ++op->quiet;
            break;
        case 'r':
            op->do_raw = true;
            break;
        case 'R':
            op->o_readonly = true;
            break;
        case 's':
           if (isdigit(*optarg)) {
               op->sa = sg_get_num(optarg);
               if ((op->sa < 0) || (op->sa > 63)) {
                    pr2serr("bad argument to '--sa=SA', expect 0 to 63\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                res = find_sa_acron(optarg);
                if (res < 0) {
                    enum_sa_acrons();
                    return SG_LIB_SYNTAX_ERROR;
                }
                op->sa = res;
            }
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
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
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if (op->enumerate) {
        enum_attributes();
        printf("\n");
        enum_sa_acrons();
        return 0;
    }

    if (fname && device_name) {
        pr2serr("since '--in=FN' given, ignoring DEVICE\n");
        device_name = NULL;
    }

    if (0 == op->maxlen)
        op->maxlen = DEF_RATTR_BUFF_LEN;
    rabp = (uint8_t *)sg_memalign(op->maxlen, 0, &free_rabp, op->verbose > 3);
    if (NULL == rabp) {
        pr2serr("unable to sg_memalign %d bytes\n", op->maxlen);
        return sg_convert_errno(ENOMEM);
    }

    if (NULL == device_name) {
        if (fname) {
            if ((ret = sg_f2hex_arr(fname, op->do_raw, false /* no space */,
                                    rabp, &in_len, op->maxlen)))
                goto clean_up;
            if (op->do_raw)
                op->do_raw = false;    /* can interfere on decode */
            if (in_len < 4) {
                pr2serr("--in=%s only decoded %d bytes (needs 4 at least)\n",
                        fname, in_len);
                ret = SG_LIB_SYNTAX_ERROR;
                goto clean_up;
            }
            decode_all_sa_s(rabp, in_len, op);
            goto clean_up;
        }
        pr2serr("missing device name!\n");
        usage();
        ret = SG_LIB_SYNTAX_ERROR;
        goto clean_up;
    }

    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
                goto clean_up;
        }
    }

    sg_fd = sg_cmds_open_device(device_name, op->o_readonly, op->verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto clean_up;
    }

    res = sg_ll_read_attr(sg_fd, rabp, &resid, op->verbose > 0, op);
    ret = res;
    if (0 == res) {
        rlen = op->maxlen - resid;
        if (rlen < 4) {
            pr2serr("Response length (%d) too short\n", rlen);
            ret = SG_LIB_CAT_MALFORMED;
            goto close_then_end;
        }
        if ((op->sa <= RA_HIGHEST_SA) && (op->sa != RA_SMC2_SA)) {
            ra_len = ((RA_LV_LIST_SA == op->sa) ||
                      (RA_PART_LIST_SA == op->sa)) ?
                        (unsigned int)sg_get_unaligned_be16(rabp + 0) :
                        sg_get_unaligned_be32(rabp + 0) + 2;
            ra_len += 2;
        } else
            ra_len = rlen;
        if ((int)ra_len > rlen) {
            if (op->verbose)
                pr2serr("ra_len available is %d, response length is %d\n",
                        ra_len, rlen);
            len = rlen;
        } else
            len = (int)ra_len;
        if (op->do_raw) {
            dStrRaw((const char *)rabp, len);
            goto close_then_end;
        }
        decode_all_sa_s(rabp, len, op);
    } else if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("Read attribute command not supported\n");
    else {
        sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
        pr2serr("Read attribute command: %s\n", b);
    }

close_then_end:
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            ret = sg_convert_errno(-res);
    }
clean_up:
    if (free_rabp)
        free(free_rabp);
    if (0 == op->verbose) {
        if (! sg_if_can2stderr("sg_read_attr failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

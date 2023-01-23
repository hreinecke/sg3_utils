/*
 * Copyright (c) 2016-2019 Douglas Gilbert.
 * Copyright (c) 2022-2023 Boris Fox.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <assert.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 * This program issues the SCSI WRITE ATTRIBUTE command to the given SCSI
 * device and decodes the response. Based on spc5r19.pdf
 */

static const char * version_str = "1.03 20230121";

#define MAX_ATTR_VALUE_LEN SG_LIB_UNBOUNDED_16BIT
#define MAX_ATTR_BUFF_LEN (1024 * 1024)

#define ATTR_LIST_ITEM_HEADER_LEN (2+1+2)
#define ATTR_LIST_HEADER_LEN (4)

#define SG_WRITE_ATTRIBUTE_CMD 0x8d
#define SG_WRITE_ATTRIBUTE_CMDLEN 16

#define RA_FMT_BINARY 0x0
#define RA_FMT_ASCII 0x1
#define RA_FMT_TEXT 0x2         /* takes into account locale */
#define RA_FMT_RES 0x3          /* reserved */

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */

struct opts_t {
    bool do_raw;
    bool do_hex;
    bool enumerate;
    bool verbose_given;
    bool version_given;
    bool wtc;
    int elem_addr;
    int lvn;
    int pn;
    int verbose;
};

struct acron_nv_t {
    uint8_t val;
    const char * acronym;
    const char * name;
};

struct attr_name_info_t {
    int id;
    const char * acronym; /* attribute acronym name */
    const char * name;  /* tab ('\t') suggest line break */
    int format;         /* RA_FMT_BINARY and friends, -1 --> unknown */
    int len;            /* -1 --> not fixed (variable) */
    int process;        /* 0 --> print decimal if binary, 1 --> print hex,
                         * 2 --> further processing */
    const struct acron_nv_t * val_acronyms; /* attribute value acronyms */
};

struct attr_value_pair_t {
    int     id;
    const char * name;
    int     format;
    int     len;                /* -1 is variable */
    int     val_len;
    uint8_t value[MAX_ATTR_VALUE_LEN];
};

static struct option long_options[] = {
    {"enumerate", no_argument, 0, 'e'},
    {"element", required_argument, 0, 'E'},   /* SMC-3 element address */
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"in", required_argument, 0, 'i'},
    {"lvn", required_argument, 0, 'l'},
    {"partition", required_argument, 0, 'p'},
    {"raw", no_argument, 0, 'r'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"wtc", no_argument, 0, 'c'},
    {0, 0, 0, 0},   /* sentinel */
};

/* Attribute value acronyms currently implemented for single-byte values
 * only */
static struct acron_nv_t tli_acron_arr[] = {
/* Text localization identifier. Acronyms must match charset names supported
 * by iconv library */
        { 0x00, "ascii", "No code specified (ASCII)" },
        { 0x01, "iso-8859-1", "ISO/IEC 8859-1 (Europe, Latin America)" },
        { 0x02, "iso-8859-2", "ISO/IEC 8859-2 (Eastern Europe)" },
        { 0x03, "iso-8859-3", "ISO/IEC 8859-3 (SE Europe/miscellaneous)" },
        { 0x04, "iso-8859-4", "ISO/IEC 8859-4 (Scandinavia/Baltic)" },
        { 0x05, "iso-8859-5", "ISO/IEC 8859-5 (Cyrillic)" },
        { 0x06, "iso-8859-6", "ISO/IEC 8859-6 (Arabic)" },
        { 0x07, "iso-8859-7", "ISO/IEC 8859-7 (Greek)" },
        { 0x08, "iso-8859-8", "ISO/IEC 8859-8 (Hebrew)" },
        { 0x09, "iso-8859-9", "ISO/IEC 8859-9 (Latin 5)" },
        { 0x0A, "iso-8859-10", "ISO/IEC 8859-10 (Latin 6)" },
        /* 0Bh to 7Fh Reserved */
        { 0x80, "ucs-2be", "ISO/IEC 10646-1 (UCS-2BE)" },
        { 0x81, "utf-8", "ISO/IEC 10646-1 (UTF-8)" },
        /* 82h to FFh Reserved */
        { 0xff, NULL, NULL }
};

/* Only Host type attributes are writable in most devices */
static struct attr_name_info_t attr_name_arr[] = {
/* Device type attributes */
    {0x0, NULL, "Remaining capacity in partition [MiB]", RA_FMT_BINARY, 8, 0,
     NULL},
    {0x1, NULL, "Maximum capacity in partition [MiB]", RA_FMT_BINARY, 8, 0,
     NULL},
    {0x2, NULL, "TapeAlert flags", RA_FMT_BINARY, 8, 0, NULL},   /* SSC-4 */
    {0x3, NULL, "Load count", RA_FMT_BINARY, 8, 0, NULL},
    {0x4, NULL, "MAM space remaining [B]", RA_FMT_BINARY, 8, 0, NULL},
    {0x5, NULL, "Assigning organization", RA_FMT_ASCII, 8, 0,
     NULL}, /* SSC-4 */
    {0x6, NULL, "Format density code", RA_FMT_BINARY, 1, 1, NULL}, /* SSC-4 */
    {0x7, NULL, "Initialization count", RA_FMT_BINARY, 2, 0, NULL},
    {0x8, NULL, "Volume identifier", RA_FMT_ASCII, 32, 0, NULL},
    {0x9, NULL, "Volume change reference", RA_FMT_BINARY, -1, 1,
     NULL}, /* SSC-4 */
    {0x20a, NULL, "Density vendor/serial number at last load", RA_FMT_ASCII,
     40, 0, NULL},
    {0x20b, NULL, "Density vendor/serial number at load-1", RA_FMT_ASCII,
     40, 0, NULL},
    {0x20c, NULL, "Density vendor/serial number at load-2", RA_FMT_ASCII,
     40, 0, NULL},
    {0x20d, NULL, "Density vendor/serial number at load-3", RA_FMT_ASCII,
     40, 0, NULL},
    {0x220, NULL, "Total MiB written in medium life", RA_FMT_BINARY, 8, 0,
     NULL},
    {0x221, NULL, "Total MiB read in medium life", RA_FMT_BINARY, 8, 0, NULL},
    {0x222, NULL, "Total MiB written in current/last load", RA_FMT_BINARY, 8,
     0, NULL},
    {0x223, NULL, "Total MiB read in current/last load", RA_FMT_BINARY, 8, 0,
     NULL},
    {0x224, NULL, "Logical position of first encrypted block", RA_FMT_BINARY,
     8, 2, NULL},
    {0x225, NULL, "Logical position of first unencrypted block\tafter first "
     "encrypted block", RA_FMT_BINARY, 8, 2, NULL},
    {0x340, NULL, "Medium usage history", RA_FMT_BINARY, 90, 2, NULL},
    {0x341, NULL, "Partition usage history", RA_FMT_BINARY, 60, 2, NULL},

/* Medium type attributes */
    {0x400, NULL, "Medium manufacturer", RA_FMT_ASCII, 8, 0, NULL},
    {0x401, NULL, "Medium serial number", RA_FMT_ASCII, 32, 0, NULL},
    {0x402, NULL, "Medium length [m]", RA_FMT_BINARY, 4, 0, NULL}, /* SSC-4 */
    {0x403, NULL, "Medium width [0.1 mm]", RA_FMT_BINARY, 4, 0,
     NULL},  /* SSC-4 */
    {0x404, NULL, "Assigning organization", RA_FMT_ASCII, 8, 0,
     NULL},  /* SSC-4 */
    {0x405, NULL, "Medium density code", RA_FMT_BINARY, 1, 1,
     NULL},    /* SSC-4 */
    {0x406, NULL, "Medium manufacture date", RA_FMT_ASCII, 8, 0, NULL},
    {0x407, NULL, "MAM capacity [B]", RA_FMT_BINARY, 8, 0, NULL},
    {0x408, NULL, "Medium type", RA_FMT_BINARY, 1, 1, NULL},
    {0x409, NULL, "Medium type information", RA_FMT_BINARY, 2, 1, NULL},
    {0x40a, NULL, "Numeric medium serial number", -1, -1, 1, NULL},

/* Host type attributes */
    {0x800, "AppVendor", "Application vendor", RA_FMT_ASCII, 8, 0, NULL},
    {0x801, "AppName", "Application name", RA_FMT_ASCII, 32, 0, NULL},
    {0x802, "AppVersion", "Application version", RA_FMT_ASCII, 8, 0, NULL},
    {0x803, "UserLabel", "User medium text label", RA_FMT_TEXT, 160, 0, NULL},
    {0x804, "LastWritten", "Date and time last written", RA_FMT_ASCII, 12, 0,
     NULL},
    {0x805, "LocaleId", "Text localization identifier", RA_FMT_BINARY, 1, 0,
     tli_acron_arr},
    {0x806, "Barcode", "Barcode", RA_FMT_ASCII, 32, 0, NULL},
    {0x807, "OwningHost", "Owning host textual name", RA_FMT_TEXT, 80, 0,
     NULL},
    {0x808, "MediaPoolName", "Media pool name", RA_FMT_TEXT, 160, 0, NULL},
    {0x809, "PartUserLabel", "Partition user text label", RA_FMT_ASCII, 16,
     0, NULL},
    {0x80a, "LUatPart", "Load/unload at partition", RA_FMT_BINARY, 1, 0,
     NULL},
    {0x80b, "AppFmtVersion", "Application format version", RA_FMT_ASCII, 16,
     0, NULL},
    {0x80c, "VCI", "Volume coherency information", RA_FMT_BINARY, -1, 1,
     NULL},
     /* SSC-5 */
    {0x820, "MediumGUID", "Medium globally unique identifier", RA_FMT_BINARY,
     36, 1, NULL},
    {0x821, "MediaPoolGUID", "Media pool globally unique identifier",
     RA_FMT_BINARY, 36, 1, NULL},

    {-1, NULL, NULL, -1, -1, 0, NULL},
};

static const char * iavp_s = "in attribute-value pair";


static void
usage()
{
    pr2serr("Usage: sg_write_attr [--element=EA] [--enumerate] [--help] "
            "[--hex]\n"
            "                     [--in=FN] [--lvn=LVN] [--partition=PN] "
            "[--raw]\n"
            "                     [--verbose] [--version] [--wtc] DEVICE\n"
            "                     [attr=value [attr=value ...]]\n");
    pr2serr("  where:\n"
            "    --enumerate|-e     enumerate known attributes and service "
            "actions\n"
            "    --element=EA|-E EA    EA is placed in 'element address' "
            "field in\n"
            "                          cdb [SMC-3] (def: 0)\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           input file contains attribute list in "
            "hex format\n"
            "    --in=FN|-i FN      FN is a filename containing "
            "attribute-value pairs\n"
            "                       or attribute list in binary/hex format\n"
            "                       if used with --raw or --hex\n"
            "    --lvn=LVN|-l LVN        logical volume number (LVN) "
            "(def:0)\n"
            "    --partition=PN|-p PN    partition number (PN) (def:0)\n"
            "    --raw|-r           input file contains binary attribute "
            "list\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n"
            "    --wtc|-c           set WRITE THROUGH CACHE bit in cdn (def: "
            "clear)\n\n"
            "Performs a SCSI WRITE ATTRIBUTE command. Even though it is "
            "defined in\nSPC-3 and later it is typically used on tape "
            "systems.\n");
}

/* Invokes a SCSI WRITE ATTRIBUTE command (SPC+SMC).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_write_attr(const int sg_fd, const void * data, const int data_len,
                 const bool noisy, const struct opts_t * op)
{
    int ret, res, sense_cat;
    uint8_t ra_cdb[SG_WRITE_ATTRIBUTE_CMDLEN] =
          {SG_WRITE_ATTRIBUTE_CMD, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
           0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (op->wtc)
        ra_cdb[1] |= 0x1;
    if (op->elem_addr)
        sg_put_unaligned_be16(op->elem_addr, ra_cdb + 2);
    if (op->lvn)
        ra_cdb[5] = 0xff & op->lvn;
    if (op->pn)
        ra_cdb[7] = 0xff & op->pn;
    sg_put_unaligned_be32((uint32_t)data_len, ra_cdb + 10);
    if (op->verbose) {
        char b[128];

        pr2serr("Write attribute cdb: %s\n",
                sg_get_command_str(ra_cdb, SG_WRITE_ATTRIBUTE_CMDLEN, false,
                                   sizeof(b), b));
        pr2serr("Write attribute list:\n");
        hex2stderr((const uint8_t *)data, data_len, 0);
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, ra_cdb, SG_WRITE_ATTRIBUTE_CMDLEN);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (const uint8_t *)data, data_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, op->verbose);
    ret = sg_cmds_process_resp(ptvp, "write attribute", res, noisy,
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
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static const struct attr_name_info_t *
find_attr_by_acronym(const char * cp)
{
    int k;
    const struct attr_name_info_t * anip;
    const char * mp;

    for (anip = attr_name_arr; anip->name ; ++anip) {
        if (NULL == anip->acronym)
            continue;
        for (mp = cp, k = 0; *mp; ++mp, ++k) {
            if (tolower(*mp) != tolower(anip->acronym[k]))
                break;
        }
        if ((0 == *mp) && (0 == anip->acronym[k]))
            return anip;
    }
    return NULL;  /* not found */
}

static const struct attr_name_info_t *
find_attr_by_id(const char * cp)
{
    unsigned long id;
    const struct attr_name_info_t * anip;
    char *endptr;

    /* Try to decode as hexadecimal numerical id, validate against the
     * supported list */
    errno = 0;
    id = strtoul(cp, &endptr, 0);
    if (0 == errno && '\0' == *endptr) {
        for (anip = attr_name_arr; anip->name ; ++anip) {
            if (id == (unsigned long)anip->id)
                return anip;
        }
    }
    return NULL;  /* not found */
}

static const struct acron_nv_t *
find_value_by_acronym(const char * cp, const struct acron_nv_t * anvp)
{
    int k;
    const char * mp;

    if (NULL == anvp)
        return NULL;
    for (; anvp->name; ++anvp) {
        if (NULL == anvp->acronym)
            continue;
        for (mp = cp, k = 0; *mp; ++mp, ++k) {
            if (tolower(*mp) != tolower(anvp->acronym[k]))
                break;
        }
        if ((0 == *mp) && (0 == anvp->acronym[k]))
            return anvp;
    }
    return NULL;  /* not found */
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
    const struct acron_nv_t * anvp;
    const char * cp;
    char b[32];
    int has_acronyms = 0;

    printf("Attribute ID\tLength\tFormat\tAcronym\t\tName\n");
    printf("-------------------------------------------------------------\n");
    for (anip = attr_name_arr; anip->name ; ++anip) {
        if (anip->format < 0)
            snprintf(b, sizeof(b), "unknown");
        else
            snprintf(b, sizeof(b), "%s", a_format[0x3 & anip->format]);
        printf("  0x%04x:\t%d\t%s\t%-13s\t", anip->id, anip->len, b,
               anip->acronym != NULL ? anip->acronym : "");
        cp = strchr(anip->name, '\t');
        if (cp) {
            printf("%.*s\n", (int)(cp - anip->name), anip->name);
            printf("\t\t\t\t\t\t%s\n", cp + 1);
        } else
            printf("%s\n", anip->name);
        if (anip->val_acronyms)
            has_acronyms = 1;
    }

    if (has_acronyms) {
        printf("\nAttribute Value acronyms\n");
        printf("    Value\tAcronym\t\tName\n");
        printf("-----------------------------------------------------------"
               "--\n");
        for (anip = attr_name_arr; anip->name ; ++anip) {
            if (anip->val_acronyms) {
                printf("0x%04x %s:\n", anip->id, anip->name);
                for (anvp = anip->val_acronyms; anvp->name; ++anvp)
                    printf("    0x%02x:\t%-13s\t%s\n", anvp->val,
                           anvp->acronym, anvp->name);
            }
        }
    }
}

/* Read hex numbers from command or file line (comma separated list).
 * Can also be (single) space separated list but needs to be quoted on the
 * command line. Returns 0 if ok, or 1 if error. */
static int
parse_hex_string(const char * inp, uint8_t * arr, int * arr_len,
                 int max_arr_len)
{
        int in_len, k;
        unsigned int h;
        const char * lcp;
        char * cp;
        char * c2p;

        if ((NULL == inp) || (NULL == arr) || (NULL == arr_len))
                return SG_LIB_LOGIC_ERROR;
        lcp = inp;
        in_len = strlen(inp);
        if (0 == in_len) {
                *arr_len = 0;
                return 0;
        }
    /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfF, ");
        if (in_len != k) {
                pr2serr("%s: error at pos %d\n", __func__, k + 1);
                return SG_LIB_SYNTAX_ERROR;
        }
        for (k = 0; k < max_arr_len; ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                        if (h > 0xff) {
                                pr2serr("%s: hex number larger than 0xff at "
                                        "pos %d\n", __func__,
                                        (int)(lcp - inp + 1));
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        arr[k] = h;
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
        *arr_len = k + 1;
        if (k == max_arr_len) {
                pr2serr("%s: array length exceeded\n", __func__);
                return SG_LIB_LBA_OUT_OF_RANGE;
        }
        return 0;
}

static int
sg_nbytes(unsigned long long x)
{
    int n = 0;

    do {
        x >>= 8;
        n++;
    } while(x);

    return n;
}

static void
sg_put_unaligned_be(void *dst, const void *src, const size_t len)
{
    const uint8_t *psrc = (const uint8_t *)src;
    uint8_t *pdst = (uint8_t *)dst;

    switch (len) {
        case 0:
            break;
        case sizeof(uint8_t):
            *pdst = *psrc;
            break;
        case sizeof(uint16_t):
            sg_put_unaligned_be16(*((uint16_t *)src), dst);
            break;
        case sizeof(uint32_t):
            sg_put_unaligned_be32(*((uint32_t *)src), dst);
            break;
        case sizeof(uint64_t):
            sg_put_unaligned_be64(*((uint64_t *)src), dst);
            break;
        default:
#if defined(__LITTLE_ENDIAN__) || (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
            pdst += len-1;
            for (size_t i = 0; i < len; i++)
                *pdst-- = *psrc++;
#elif defined(__BIG_ENDIAN__) || (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)
            memcpy(dst, src, len);
#endif
    }
}

/* Parse attribute value according to format */
static int
parse_attr_value(const char * attr_value, const bool do_hex,
                 const int attr_no, struct attr_value_pair_t * avp,
                 const struct attr_name_info_t * anip)
{
    const char * format = anip->format == RA_FMT_BINARY ?
                         "Binary" : (RA_FMT_ASCII ? "ASCII" :
                                     (RA_FMT_TEXT ? "Text" : "Reserved"));
    const struct acron_nv_t * anvp;
    unsigned long l, vl;
    unsigned long long ull;
    char *endptr;
    int ret;

    if (do_hex) {
        ret = parse_hex_string(attr_value, avp->value, &avp->val_len,
                               sizeof avp->value);
        if (0 != ret)
            return ret;
    } else {
        switch (anip->format) {
            case RA_FMT_BINARY:
                /* try numerical format first (up to the longest type size
                 * available), then acronym for 1-byte attributes */
                errno = 0;
                ull = strtoull(attr_value, &endptr, 0);
                if (0 == errno && '\0' == *endptr) {
                    l = sizeof(ull);
                    vl = sg_nbytes(ull);
                    if (vl > sizeof avp->value) {
                        pr2serr("%s: %s attribute id 0x%04x %s #%d value "
                                "too long (%lu > %zu bytes max)\n",
                                __func__, format, anip->id, iavp_s, attr_no,
                                vl, sizeof(avp->value));
                        return SG_LIB_LBA_OUT_OF_RANGE;
                    }
                    if (-1 != avp->len) {
                        if (l < (unsigned long) avp->len) {
                            pr2serr("%s: %s attribute id 0x%04x %s #%d "
                                    "numerical value length too small (%lu "
                                    "< %d bytes), use hex sequence format\n",
                                    __func__, format, anip->id, iavp_s,
                                    attr_no, l, avp->len);
                            return SG_LIB_SYNTAX_ERROR;
                        }
                        if (vl > (unsigned long) avp->len) {
                            pr2serr("%s: %s attribute id 0x%04x %s #%d "
                                    "numerical value length too large (%lu "
                                    "> %d bytes)\n", __func__, format,
                                    anip->id, iavp_s, attr_no, vl, avp->len);
                            return SG_LIB_SYNTAX_ERROR;
                        }
                        l = avp->len;
                    } else
                        l = vl;
                    sg_put_unaligned_be(avp->value, &ull, l);
                    avp->val_len = l;
                } else {
                    anvp = find_value_by_acronym(attr_value,
                                                 anip->val_acronyms);
                    if (NULL == anvp) {
                        pr2serr("%s: %s attribute id 0x%04x %s #%d value "
                                "'%s' is neither valid number nor acronym\n",
                                __func__, format, anip->id, iavp_s, attr_no,
                                attr_value);
                        return SG_LIB_SYNTAX_ERROR;
                    } else {
                        /* length check will be enforced below */
                        avp->value[0] = anvp->val;
                        avp->val_len = sizeof(anvp->val);
                    }
                }

                break;
            case RA_FMT_ASCII:
            case RA_FMT_TEXT:
                /* ASCII or text string */
                l = strlen(attr_value);
                if (l > sizeof avp->value) {
                    pr2serr("%s: %s attribute id 0x%04x %s #%d value too "
                            "long (%lu > %zu bytes max)\n", __func__, format,
                            anip->id, iavp_s, attr_no, l, sizeof(avp->value));
                    return SG_LIB_LBA_OUT_OF_RANGE;
                }
                memcpy(avp->value, attr_value, l);
                avp->val_len = l;
                break;
            default:
                assert(false);
        }
    }
    /* see SCP-5 clause 4.3.1 ASCII data field requirements */
    if (RA_FMT_ASCII == anip->format &&
        (avp->val_len != sg_first_non_printable(avp->value, avp->val_len))) {
        pr2serr("%s: ASCII attribute id 0x%04x %s #%d contains non-printable "
                "or non-ASCII characters\n", __func__, anip->id, iavp_s,
                attr_no);
        return SG_LIB_SYNTAX_ERROR;
    }
    if ((RA_FMT_ASCII == anip->format || RA_FMT_TEXT == anip->format) &&
        -1 != avp->len && avp->val_len < avp->len) {
        memset(&avp->value[avp->val_len],
               RA_FMT_ASCII == anip->format ? ' ' : '\0',
               avp->len - avp->val_len);
        avp->val_len = avp->len;
    }
    if (-1 != avp->len) {
        if (RA_FMT_BINARY == anip->format) {
            if (avp->val_len != avp->len) {
                pr2serr("%s: %s attribute id 0x%04x %s #%d value length (%d) "
                        "does not match attribute length (%d)\n", __func__,
                        format, anip->id, iavp_s, attr_no, avp->val_len,
                        avp->len);
                return SG_LIB_LBA_OUT_OF_RANGE;
            }

        } else {
            if (avp->val_len > avp->len) {
                pr2serr("%s: %s attribute id 0x%04x %s #%d value length (%d) "
                        "exceeds attribute length (%d)\n", __func__, format,
                        anip->id, iavp_s, attr_no,
                        avp->val_len, avp->len);
                return SG_LIB_LBA_OUT_OF_RANGE;
            }
        }
    }
    return 0;
}

/* Parse attribute-value pair delimited by an equal sign '=' or a colon ':'.
 * Attribute can be either acronym or numerical id in hexadecimal form.
 * Value is a text string for text or ASCII format attributes,
 * or comma- or space-delimited hexadecimal string for binary attributes
 * or with colon attribute-value delimiter.
 * Unicode text strings are supported only in the UTF-8 character set.
 * It's recommended to set Text Localization Identifier attribute
 * when text values contains characters beyond ASCII.
 * Text and ASCII format values will be left-aligned padded by blanks (ASCII)
 * or nulls (Text) to their designated length.
 * Value length for binary attributes must match attribute length exactly,
 * unless attribute has variable length.
 * Empty value ("attribute=" or "attribute:") deletes attribute.
 * Fills in avp structure. Returns 0 on success and 1 on errors.
 */
static int
parse_attribute(char * const inp, const int attr_no,
                struct attr_value_pair_t * avp)
{
    char *attr_name, *attr_value, *dc;
    const struct attr_name_info_t * anip;
    bool do_hex;

    /* delimiters: = is for ascii/text string or numerical value, : is for
     * hex sequence */
    dc = strpbrk(inp, "=:");
    if (NULL == dc) {
        pr2serr("%s: attribute-value pair #%d must be separated by '=' or "
                "':' sign\n", __func__, attr_no);
        return SG_LIB_SYNTAX_ERROR;
    }
    do_hex = ':' == *dc;
    *dc++ = '\0';
    attr_name = inp;
    attr_value = dc;

    if (0 == strlen(attr_name)) {
        pr2serr("%s: no attribute id or acronym %s #%d\n", __func__, iavp_s,
                attr_no);
        return SG_LIB_SYNTAX_ERROR;
    }

    anip = find_attr_by_id(attr_name);
    if (NULL == anip)
        anip = find_attr_by_acronym(attr_name);
    if (NULL == anip) {
        pr2serr("%s: unknown attribute id or acronym '%s' %s #%d\n", __func__,
                attr_name, iavp_s, attr_no);
        return SG_LIB_SYNTAX_ERROR;
    }

    avp->id = anip->id;
    avp->name = anip->name;
    avp->format = anip->format;
    avp->len = anip->len;

    /* zero-length value deletes the attribute */
    if (0 == strlen(attr_value)) {
        avp->val_len = 0;
        return 0;
    }

    return parse_attr_value(attr_value, do_hex, attr_no, avp, anip);
}

/* pack attribute list */
static int
pack_attribute_list(const struct attr_value_pair_t * avps, const int avpc,
                    uint8_t * buf, int * buf_len, const int max_buf_len)
{
    uint32_t remained_size = max_buf_len;
    uint32_t item_len;
    uint8_t * ptr;
    int i;

    if (remained_size < ATTR_LIST_HEADER_LEN) {
        pr2serr("%s: attribute list buffer size (%d bytes) is too small to "
                "store attribute list header of %d bytes\n", __func__,
                remained_size, ATTR_LIST_HEADER_LEN);
        return SG_LIB_LBA_OUT_OF_RANGE;
    }
    remained_size -= ATTR_LIST_HEADER_LEN;
    ptr = buf + ATTR_LIST_HEADER_LEN;
    for (i = 0, *buf_len = 0; i < avpc;
         i++, avps++, ptr += item_len, *buf_len += item_len,
                remained_size -= item_len) {
        item_len = avps->val_len + ATTR_LIST_ITEM_HEADER_LEN;
        if (remained_size < item_len) {
            pr2serr("%s: attribute list remained buffer size (%d of %d "
                    "bytes) is too small to store attribute #%d 0x%04x (%s) "
                    "of %d bytes\n", __func__, remained_size, max_buf_len,
                    i+1, avps->id, avps->name, item_len);
            return SG_LIB_LBA_OUT_OF_RANGE;
        }
        sg_put_unaligned_be16(avps->id, ptr);
        ptr[2] = avps->format;
        sg_put_unaligned_be16(avps->val_len, ptr+3);
        memcpy(ptr+5, avps->value, avps->val_len);
    }
    sg_put_unaligned_be32(*buf_len, buf);
    *buf_len += ATTR_LIST_HEADER_LEN;
    return 0;
}

/* Find duplicate attributes in the sorted array */
static int
find_duplicates(const struct attr_value_pair_t * avps, const int avpc)
{
    int last_dup_id = -1;

    for (int i = 1; i < avpc; i++) {
        if (avps[i].id == avps[i-1].id && avps[i].id != last_dup_id){
            pr2serr("Duplicate attribute #%d: 0x%04x (%s)\n", i, avps[i].id,
                    avps[i].name);
            last_dup_id = avps[i].id;
        }
    }
    return last_dup_id != -1 ? SG_LIB_SYNTAX_ERROR : 0;
}

static int
compare_attributes(const struct attr_value_pair_t * a,
                   const struct attr_value_pair_t * b)
{
    return a->id - b->id;
}

/* sort attributes by id in ascending order, find duplicates, pack attribute
 * list */
static int
post_process_attributes(struct attr_value_pair_t * avps, const int avps_num,
                        uint8_t * wabp, int * buf_len, const int maxlen)
{
    int r;

    /* sort by attribute id in ascending order */
    qsort(avps, avps_num, sizeof(struct attr_value_pair_t),
          (int (*)(const void *, const void *)) compare_attributes);
    /* find duplicates */
    r = find_duplicates(avps, avps_num);
    if (!r)
        r = pack_attribute_list(avps, avps_num, wabp, buf_len, maxlen);
    return r;
}

static int
parse_attributes(char *argv[], const int argc, uint8_t * wabp, int * buf_len,
                 const int maxlen)
{
    struct attr_value_pair_t * avps;
    int r;

    avps = (struct attr_value_pair_t *)
                calloc(argc, sizeof(struct attr_value_pair_t));
    if (NULL == avps) {
        pr2serr("%s: out of memory allocating %u bytes\n", __func__,
                (unsigned int)(argc * sizeof(struct attr_value_pair_t)));
        return sg_convert_errno(ENOMEM);
    }
    /* parse attribute-value pairs */
    for (int i = 0; i < argc; i++) {
        r = parse_attribute(argv[i], i + 1, &avps[i]);
        if (r)
            goto cleanup;
    }
    r = post_process_attributes(avps, argc, wabp, buf_len, maxlen);
cleanup:
    free (avps);
    return r;
}

/* Read attribute-value pairs from input file line by line */
static int
parse_attributes_from_file(const char * fname, const struct opts_t * op,
                           uint8_t * mp_arr, int * mp_arr_len,
                           const int maxlen)
{
    bool has_stdin;
    int fn_len, err;
    int ret = 0;
    char * lcp, * end;
    FILE * fp;
    char line[512];
    const char whitespace[] = " \f\n\r\t\v";
    struct attr_value_pair_t * avps = NULL;
    int avps_num = 0;
    static const size_t avp_sz = sizeof(struct attr_value_pair_t);

    if ((NULL == fname) || (NULL == op) || (NULL == mp_arr) ||
        (NULL == mp_arr_len)) {
        pr2ws("%s: bad arguments\n", __func__);
        return SG_LIB_LOGIC_ERROR;
    }
    fn_len = strlen(fname);
    if (0 == fn_len)
        return SG_LIB_SYNTAX_ERROR;
    has_stdin = ((1 == fn_len) && ('-' == fname[0]));   /* read from stdin */

    /* So read the file as ASCII one attribute-value pair per line */
    if (has_stdin)
        fp = stdin;
    else {
        fp = fopen(fname, "r");
        if (NULL == fp) {
            err = errno;
            pr2ws("Unable to open %s for reading: %s\n", fname,
                  safe_strerror(err));
            ret = sg_convert_errno(err);
            goto fini;
        }
    }

    for (;;) {
        if (NULL == fgets(line, sizeof(line), fp))
            break;

        /* Trim leading and  trailing space and newline */
        lcp = line + strspn(line, whitespace);
        end = lcp + strlen(lcp) - 1;
        while(end > lcp && isspace(*end)) end--;
        end[1] = '\0';
        if ('\0' == *lcp || '#' == *lcp)
            continue;

        avps = (struct attr_value_pair_t *) realloc(avps,
                                                    (avps_num+1) * avp_sz);
        if (NULL == avps) {
            pr2serr("%s: out of memory allocating %zu bytes\n", __func__,
                    (avps_num+1) * avp_sz);
            ret = sg_convert_errno(ENOMEM);
            goto fini;
        }
        ret = parse_attribute(lcp, avps_num+1, &avps[avps_num]);
        if (ret)
            goto fini;
        avps_num++;
    }
    if (avps)
        ret = post_process_attributes(avps, avps_num, mp_arr, mp_arr_len,
                                      maxlen);
fini:
    if (fp && (stdin != fp))
        fclose(fp);
    if (avps)
        free(avps);
    return ret;
}

int
main(int argc, char * argv[])
{
    int sg_fd, res, c;
    int in_len = 0;
    int ret = 0;
    int avps_num = 0;
    const int maxlen = MAX_ATTR_BUFF_LEN;
    const char * device_name = NULL;
    const char * fname = NULL;
    char ** avps = NULL;
    uint8_t * wabp = NULL;
    uint8_t * free_wabp = NULL;
    struct opts_t opts;
    struct opts_t * op;
    char b[80];

    op = &opts;
    memset(op, 0, sizeof(opts));
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ceE:hHi:l:p:qrt:vV",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            op->wtc = true;
            break;
        case 'e':
            op->enumerate = true;
            break;
        case 'E':
           op->elem_addr = sg_get_num(optarg);
           if ((op->elem_addr < 0) || (op->elem_addr > 65535)) {
                pr2serr("bad argument to '--element=EA', expect 0 to "
                        "65535\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            op->do_hex = true;
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
        case 'p':
           op->pn = sg_get_num(optarg);
           if ((op->pn < 0) || (op->pn > 255)) {
                pr2serr("bad argument to '--pn=PN', expect 0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            op->do_raw = true;
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
    if (optind < argc && NULL == device_name) {
        device_name = argv[optind];
        ++optind;
    }
    if (optind < argc) {
        avps = &argv[optind];
        avps_num = argc - optind;
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
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    wabp = (uint8_t *)sg_memalign(maxlen, 0, &free_wabp, op->verbose > 3);
    if (NULL == wabp) {
        pr2serr("unable to sg_memalign %d bytes\n", maxlen);
        return sg_convert_errno(ENOMEM);
    }

    if (fname) {
        if (avps) {
            pr2serr("since '--in=FN' given, ignoring attribute-value pairs "
                    "arguments\n");
            avps = NULL;
        }
        if (op->do_raw || op->do_hex) {
            if (op->do_raw && op->do_hex)
                pr2serr("both '--raw' and '--hex' given, assuming binary "
                        "(raw) format\n");
            if ((ret = sg_f2hex_arr(fname, op->do_raw, false /* no space */,
                                    wabp, &in_len, maxlen)))
                goto fini;
            if (in_len < 4) {
                pr2serr("--in=%s only decoded %d bytes (needs 4 at least)\n",
                        fname, in_len);
                ret = SG_LIB_SYNTAX_ERROR;
            }
        } else
            ret = parse_attributes_from_file(fname, op, wabp, &in_len,
                                             maxlen);
    } else {
        if (NULL == avps) {
            pr2serr("missing attribute-value pairs!\n");
            usage();
            ret = SG_LIB_SYNTAX_ERROR;
        } else
            ret = parse_attributes(avps, avps_num, wabp, &in_len, maxlen);
    }
    if (0 != ret)
        goto fini;

    sg_fd = sg_cmds_open_device(device_name, false /* read-write */,
                                op->verbose);
    if (sg_fd < 0) {
        pr2serr("open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto clean_up;
    }
    res = sg_ll_write_attr(sg_fd, wabp, in_len, op->verbose > 0, op);
    ret = res;
    if (0 != res) {
        if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr("Write attribute command not supported\n");
        else {
            sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
            pr2serr("Write attribute command: %s\n", b);
        }
    }

    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            ret = sg_convert_errno(-res);
    }
clean_up:
    if (0 == op->verbose) {
        if (! sg_if_can2stderr("sg_write_attr failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' or '-vv' for "
                    "more information\n");
    }
fini:
    if (free_wabp)
        free(free_wabp);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

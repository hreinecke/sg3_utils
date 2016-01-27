/*
 * Copyright (c) 1999-2016 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

/* NOTICE:
 *    On 5th October 2004 (v1.00) this file name was changed from sg_err.c
 *    to sg_lib.c and the previous GPL was changed to a FreeBSD license.
 *    The intention is to maintain this file and the related sg_lib.h file
 *    as open source and encourage their unencumbered use.
 *
 * CONTRIBUTIONS:
 *    This file started out as a copy of SCSI opcodes, sense keys and
 *    additional sense codes (ASC/ASCQ) kept in the Linux SCSI subsystem
 *    in the kernel source file: drivers/scsi/constant.c . That file
 *    bore this notice: "Copyright (C) 1993, 1994, 1995 Eric Youngdale"
 *    and a GPL notice.
 *
 *    Much of the data in this file is derived from SCSI draft standards
 *    found at http://www.t10.org with the "SCSI Primary Commands-4" (SPC-4)
 *    being the central point of reference.
 *
 *    Contributions:
 *      sense key specific field decoding [Trent Piepho 20031116]
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_unaligned.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* sg_lib_version_str (and datestamp) defined in sg_lib_data.c file */

#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d  /* corresponding ASC is 0 */

FILE * sg_warnings_strm = NULL;        /* would like to default to stderr */

#ifdef __GNUC__
static int pr2ws(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
static int pr2ws(const char * fmt, ...);
#endif


static int
pr2ws(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(sg_warnings_strm ? sg_warnings_strm : stderr, fmt, args);
    va_end(args);
    return n;
}

#ifdef __GNUC__
static int my_snprintf(char * cp, int cp_max_len, const char * fmt, ...)
                       __attribute__ ((format (printf, 3, 4)));
#else
static int my_snprintf(char * cp, int cp_max_len, const char * fmt, ...);
#endif

/* Want safe, 'n += snprintf(b + n, blen - n, ...)' style sequence of
 * functions. Returns number number of chars placed in cp excluding the
 * trailing null char. So for cp_max_len > 0 the return value is always
 * < cp_max_len; for cp_max_len <= 1 the return value is 0 and no chars
 * are written to cp. Note this means that when cp_max_len = 1, this
 * function assumes that cp[0] is the null character and does nothing
 * (and returns 0).  */
static int
my_snprintf(char * cp, int cp_max_len, const char * fmt, ...)
{
    va_list args;
    int n;

    if (cp_max_len < 2)
        return 0;
    va_start(args, fmt);
    n = vsnprintf(cp, cp_max_len, fmt, args);
    va_end(args);
    return (n < cp_max_len) ? n : (cp_max_len - 1);
}

/* Searches 'arr' for match on 'value' then 'peri_type'. If matches
   'value' but not 'peri_type' then yields first 'value' match entry.
   Last element of 'arr' has NULL 'name'. If no match returns NULL. */
static const struct sg_lib_value_name_t *
get_value_name(const struct sg_lib_value_name_t * arr, int value,
               int peri_type)
{
    const struct sg_lib_value_name_t * vp = arr;
    const struct sg_lib_value_name_t * holdp;

    for (; vp->name; ++vp) {
        if (value == vp->value) {
            if (peri_type == vp->peri_dev_type)
                return vp;
            holdp = vp;
            while ((vp + 1)->name && (value == (vp + 1)->value)) {
                ++vp;
                if (peri_type == vp->peri_dev_type)
                    return vp;
            }
            return holdp;
        }
    }
    return NULL;
}

/* If this function is not called, sg_warnings_strm will be NULL and all users
 * (mainly fprintf() ) need to check and substitute stderr as required */
void
sg_set_warnings_strm(FILE * warnings_strm)
{
    sg_warnings_strm = warnings_strm;
}

#define CMD_NAME_LEN 128

void
sg_print_command(const unsigned char * command)
{
    int k, sz;
    char buff[CMD_NAME_LEN];

    sg_get_command_name(command, 0, CMD_NAME_LEN, buff);
    buff[CMD_NAME_LEN - 1] = '\0';

    pr2ws("%s [", buff);
    if (SG_VARIABLE_LENGTH_CMD == command[0])
        sz = command[7] + 8;
    else
        sz = sg_get_command_size(command[0]);
    for (k = 0; k < sz; ++k)
        pr2ws("%02x ", command[k]);
    pr2ws("]\n");
}

void
sg_get_scsi_status_str(int scsi_status, int buff_len, char * buff)
{
    const char * ccp = NULL;
    int unknown = 0;

    if ((NULL == buff) || (buff_len < 1))
        return;
    else if (1 ==  buff_len) {
        buff[0] = '\0';
        return;
    }
    scsi_status &= 0x7e; /* sanitize as much as possible */
    switch (scsi_status) {
        case 0: ccp = "Good"; break;
        case 0x2: ccp = "Check Condition"; break;
        case 0x4: ccp = "Condition Met"; break;
        case 0x8: ccp = "Busy"; break;
        case 0x10: ccp = "Intermediate (obsolete)"; break;
        case 0x14: ccp = "Intermediate-Condition Met (obsolete)"; break;
        case 0x18: ccp = "Reservation Conflict"; break;
        case 0x22: ccp = "Command Terminated (obsolete)"; break;
        case 0x28: ccp = "Task set Full"; break;
        case 0x30: ccp = "ACA Active"; break;
        case 0x40: ccp = "Task Aborted"; break;
        default:
            unknown = 1;
            break;
    }
    if (unknown)
        my_snprintf(buff, buff_len, "Unknown status [0x%x]", scsi_status);
    else
        my_snprintf(buff, buff_len, "%s", ccp);
}

void
sg_print_scsi_status(int scsi_status)
{
    char buff[128];

    sg_get_scsi_status_str(scsi_status, sizeof(buff) - 1, buff);
    buff[sizeof(buff) - 1] = '\0';
    pr2ws("%s ", buff);
}

/* Get sense key from sense buffer. If successful returns a sense key value
 * between 0 and 15. If sense buffer cannot be decode, returns -1 . */
int
sg_get_sense_key(const unsigned char * sensep, int sense_len)
{
    if ((NULL == sensep) || (sense_len < 2))
        return -1;
    switch (sensep[0] & 0x7f) {
    case 0x70:
    case 0x71:
        return (sense_len < 3) ? -1 : (sensep[2] & 0xf);
    case 0x72:
    case 0x73:
        return sensep[1] & 0xf;
    default:
        return -1;
    }
}

/* Yield string associated with sense_key value. Returns 'buff'. */
char *
sg_get_sense_key_str(int sense_key, int buff_len, char * buff)
{
    if (1 == buff_len) {
        buff[0] = '\0';
        return buff;
    }
    if ((sense_key >= 0) && (sense_key < 16))
         my_snprintf(buff, buff_len, "%s", sg_lib_sense_key_desc[sense_key]);
    else
         my_snprintf(buff, buff_len, "invalid value: 0x%x", sense_key);
    return buff;
}

/* Yield string associated with ASC/ASCQ values. Returns 'buff'. */
char *
sg_get_asc_ascq_str(int asc, int ascq, int buff_len, char * buff)
{
    int k, num, rlen;
    int found = 0;
    struct sg_lib_asc_ascq_t * eip;
    struct sg_lib_asc_ascq_range_t * ei2p;

    if (1 == buff_len) {
        buff[0] = '\0';
        return buff;
    }
    for (k = 0; sg_lib_asc_ascq_range[k].text; ++k) {
        ei2p = &sg_lib_asc_ascq_range[k];
        if ((ei2p->asc == asc) &&
            (ascq >= ei2p->ascq_min)  &&
            (ascq <= ei2p->ascq_max)) {
            found = 1;
            num = my_snprintf(buff, buff_len, "Additional sense: ");
            rlen = buff_len - num;
            num += my_snprintf(buff + num, ((rlen > 0) ? rlen : 0),
                               ei2p->text, ascq);
        }
    }
    if (found)
        return buff;

    for (k = 0; sg_lib_asc_ascq[k].text; ++k) {
        eip = &sg_lib_asc_ascq[k];
        if (eip->asc == asc &&
            eip->ascq == ascq) {
            found = 1;
            my_snprintf(buff, buff_len, "Additional sense: %s", eip->text);
        }
    }
    if (! found) {
        if (asc >= 0x80)
            my_snprintf(buff, buff_len, "vendor specific ASC=%02x, "
                        "ASCQ=%02x (hex)", asc, ascq);
        else if (ascq >= 0x80)
            my_snprintf(buff, buff_len, "ASC=%02x, vendor specific "
                        "qualification ASCQ=%02x (hex)", asc, ascq);
        else
            my_snprintf(buff, buff_len, "ASC=%02x, ASCQ=%02x (hex)", asc,
                        ascq);
    }
    return buff;
}

/* Attempt to find the first SCSI sense data descriptor that matches the
 * given 'desc_type'. If found return pointer to start of sense data
 * descriptor; otherwise (including fixed format sense data) returns NULL. */
const unsigned char *
sg_scsi_sense_desc_find(const unsigned char * sensep, int sense_len,
                        int desc_type)
{
    int add_sb_len, add_d_len, desc_len, k;
    const unsigned char * descp;

    if ((sense_len < 8) || (0 == (add_sb_len = sensep[7])))
        return NULL;
    if ((sensep[0] < 0x72) || (sensep[0] > 0x73))
        return NULL;
    add_sb_len = (add_sb_len < (sense_len - 8)) ?
                         add_sb_len : (sense_len - 8);
    descp = &sensep[8];
    for (desc_len = 0, k = 0; k < add_sb_len; k += desc_len) {
        descp += desc_len;
        add_d_len = (k < (add_sb_len - 1)) ? descp[1]: -1;
        desc_len = add_d_len + 2;
        if (descp[0] == desc_type)
            return descp;
        if (add_d_len < 0) /* short descriptor ?? */
            break;
    }
    return NULL;
}

/* Returns 1 if valid bit set, 0 if valid bit clear. Irrespective the
 * information field is written out via 'info_outp' (except when it is
 * NULL). Handles both fixed and descriptor sense formats. */
int
sg_get_sense_info_fld(const unsigned char * sensep, int sb_len,
                      uint64_t * info_outp)
{
    const unsigned char * ucp;
    uint64_t ull;

    if (info_outp)
        *info_outp = 0;
    if (sb_len < 7)
        return 0;
    switch (sensep[0] & 0x7f) {
    case 0x70:
    case 0x71:
        if (info_outp)
            *info_outp = sg_get_unaligned_be32(sensep + 3);
        return (sensep[0] & 0x80) ? 1 : 0;
    case 0x72:
    case 0x73:
        ucp = sg_scsi_sense_desc_find(sensep, sb_len, 0 /* info desc */);
        if (ucp && (0xa == ucp[1])) {
            ull = sg_get_unaligned_be64(ucp + 4);
            if (info_outp)
                *info_outp = ull;
            return !!(ucp[2] & 0x80);   /* since spc3r23 should be set */
        } else
            return 0;
    default:
        return 0;
    }
}

/* Returns 1 if any of the 3 bits (i.e. FILEMARK, EOM or ILI) are set.
 * In descriptor format if the stream commands descriptor not found
 * then returns 0. Writes 1 or 0 corresponding to these bits to the
 * last three arguments if they are non-NULL. */
int
sg_get_sense_filemark_eom_ili(const unsigned char * sensep, int sb_len,
                              int * filemark_p, int * eom_p, int * ili_p)
{
    const unsigned char * ucp;

    if (sb_len < 7)
        return 0;
    switch (sensep[0] & 0x7f) {
    case 0x70:
    case 0x71:
        if (sensep[2] & 0xe0) {
            if (filemark_p)
                *filemark_p = !!(sensep[2] & 0x80);
            if (eom_p)
                *eom_p = !!(sensep[2] & 0x40);
            if (ili_p)
                *ili_p = !!(sensep[2] & 0x20);
            return 1;
        } else
            return 0;
    case 0x72:
    case 0x73:
       /* Look for stream commands sense data descriptor */
        ucp = sg_scsi_sense_desc_find(sensep, sb_len, 4);
        if (ucp && (ucp[1] >= 2)) {
            if (ucp[3] & 0xe0) {
                if (filemark_p)
                    *filemark_p = !!(ucp[3] & 0x80);
                if (eom_p)
                    *eom_p = !!(ucp[3] & 0x40);
                if (ili_p)
                    *ili_p = !!(ucp[3] & 0x20);
                return 1;
            }
        }
        return 0;
    default:
        return 0;
    }
}

/* Returns 1 if SKSV is set and sense key is NO_SENSE or NOT_READY. Also
 * returns 1 if progress indication sense data descriptor found. Places
 * progress field from sense data where progress_outp points. If progress
 * field is not available returns 0 and *progress_outp is unaltered. Handles
 * both fixed and descriptor sense formats.
 * Hint: if 1 is returned *progress_outp may be multiplied by 100 then
 * divided by 65536 to get the percentage completion. */
int
sg_get_sense_progress_fld(const unsigned char * sensep, int sb_len,
                          int * progress_outp)
{
    const unsigned char * ucp;
    int sk, sk_pr;

    if (sb_len < 7)
        return 0;
    switch (sensep[0] & 0x7f) {
    case 0x70:
    case 0x71:
        sk = (sensep[2] & 0xf);
        if ((sb_len < 18) ||
            ((SPC_SK_NO_SENSE != sk) && (SPC_SK_NOT_READY != sk)))
            return 0;
        if (sensep[15] & 0x80) {        /* SKSV bit set */
            if (progress_outp)
                *progress_outp = sg_get_unaligned_be16(sensep + 16);
            return 1;
        } else
            return 0;
    case 0x72:
    case 0x73:
        /* sense key specific progress (0x2) or progress descriptor (0xa) */
        sk = (sensep[1] & 0xf);
        sk_pr = (SPC_SK_NO_SENSE == sk) || (SPC_SK_NOT_READY == sk);
        if (sk_pr && ((ucp = sg_scsi_sense_desc_find(sensep, sb_len, 2))) &&
            (0x6 == ucp[1]) && (0x80 & ucp[4])) {
            if (progress_outp)
                *progress_outp = sg_get_unaligned_be16(ucp + 5);
            return 1;
        } else if (((ucp = sg_scsi_sense_desc_find(sensep, sb_len, 0xa))) &&
                   ((0x6 == ucp[1]))) {
            if (progress_outp)
                *progress_outp = sg_get_unaligned_be16(ucp + 6);
            return 1;
        } else
            return 0;
    default:
        return 0;
    }
}

char *
sg_get_pdt_str(int pdt, int buff_len, char * buff)
{
    if ((pdt < 0) || (pdt > 31))
        my_snprintf(buff, buff_len, "bad pdt");
    else
        my_snprintf(buff, buff_len, "%s", sg_lib_pdt_strs[pdt]);
    return buff;
}

int
sg_lib_pdt_decay(int pdt)
{
    if ((pdt < 0) || (pdt > 31))
        return pdt;
    return sg_lib_pdt_decay_arr[pdt];
}

char *
sg_get_trans_proto_str(int tpi, int buff_len, char * buff)
{
    if ((tpi < 0) || (tpi > 15))
        my_snprintf(buff, buff_len, "bad tpi");
    else
        my_snprintf(buff, buff_len, "%s", sg_lib_transport_proto_strs[tpi]);
    return buff;
}

static const char * desig_code_set_str_arr[] =
{
    "Reserved [0x0]",
    "Binary",
    "ASCII",
    "UTF-8",
    "Reserved [0x4]", "Reserved [0x5]", "Reserved [0x6]", "Reserved [0x7]",
    "Reserved [0x8]", "Reserved [0x9]", "Reserved [0xa]", "Reserved [0xb]",
    "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};

const char *
sg_get_desig_code_set_str(int val)
{
    if ((val >= 0) && (val < 16))
        return desig_code_set_str_arr[val];
    else
        return NULL;
}

static const char * desig_assoc_str_arr[] =
{
    "Addressed logical unit",
    "Target port",      /* that received request; unless SCSI ports VPD */
    "Target device that contains addressed lu",
    "Reserved [0x3]",
};

const char *
sg_get_desig_assoc_str(int val)
{
    if ((val >= 0) && (val < 4))
        return desig_assoc_str_arr[val];
    else
        return NULL;
}

static const char * desig_type_str_arr[] =
{
    "vendor specific [0x0]",
    "T10 vendor identification",
    "EUI-64 based",
    "NAA",
    "Relative target port",
    "Target port group",        /* spc4r09: _primary_ target port group */
    "Logical unit group",
    "MD5 logical unit identifier",
    "SCSI name string",
    "Protocol specific port identifier",        /* spc4r36 */
    "UUID identifier",          /* spc5r08 */
    "Reserved [0xb]",
    "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};

const char *
sg_get_desig_type_str(int val)
{
    if ((val >= 0) && (val < 16))
        return desig_type_str_arr[val];
    else
        return NULL;
}

int
sg_get_designation_descriptor_str(const char * leadin,
                                  const unsigned char * ddp, int dd_len,
                                  int print_assoc, int do_long, int blen,
                                  char * b)
{
    int m, p_id, piv, c_set, assoc, desig_type, ci_off, c_id, d_id, naa;
    int vsi, k, n, dlen;
    const unsigned char * ip;
    uint64_t vsei;
    uint64_t id_ext;
    char e[64];
    const char * cp;
    const char * lip = "";

    n = 0;
    if (leadin)
        lip = leadin;
    if (dd_len < 4) {
        n += my_snprintf(b + n, blen - n, "%sdesignator desc too short: "
                         "got length of %d want 4 or more\n", lip, dd_len);
        return n;
    }
    dlen = ddp[3];
    if (dlen > (dd_len - 4)) {
        n += my_snprintf(b + n, blen - n, "%sdesignator too long: says it "
                         "is %d bytes, but given %d bytes\n", lip, dlen,
                         dd_len - 4);
        return n;
    }
    ip = ddp + 4;
    p_id = ((ddp[0] >> 4) & 0xf);
    c_set = (ddp[0] & 0xf);
    piv = ((ddp[1] & 0x80) ? 1 : 0);
    assoc = ((ddp[1] >> 4) & 0x3);
    desig_type = (ddp[1] & 0xf);
    if (print_assoc && ((cp = sg_get_desig_assoc_str(assoc))))
        n += my_snprintf(b + n, blen - n, "%s  %s:\n", lip, cp);
    n += my_snprintf(b + n, blen - n, "%s    designator type: ", lip);
    cp = sg_get_desig_type_str(desig_type);
    if (cp)
        n += my_snprintf(b + n, blen - n, "%s", cp);
    n += my_snprintf(b + n, blen - n, ",  code set: ");
    cp = sg_get_desig_code_set_str(c_set);
    if (cp)
        n += my_snprintf(b + n, blen - n, "%s", cp);
    n += my_snprintf(b + n, blen - n, "\n");
    if (piv && ((1 == assoc) || (2 == assoc)))
        n += my_snprintf(b + n, blen - n, "%s     transport: %s\n", lip,
                         sg_get_trans_proto_str(p_id, sizeof(e), e));
    /* printf("    associated with the %s\n", sdparm_assoc_arr[assoc]); */
    switch (desig_type) {
    case 0: /* vendor specific */
        k = 0;
        if ((1 == c_set) || (2 == c_set)) { /* ASCII or UTF-8 */
            for (k = 0; (k < dlen) && isprint(ip[k]); ++k)
                ;
            if (k >= dlen)
                k = 1;
        }
        if (k)
            n += my_snprintf(b + n, blen - n, "%s      vendor specific: "
                             "%.*s\n", lip, dlen, ip);
        else {
            n += my_snprintf(b + n, blen - n, "%s      vendor specific:\n",
                             lip);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
        }
        break;
    case 1: /* T10 vendor identification */
        n += my_snprintf(b + n, blen - n, "%s      vendor id: %.8s\n", lip,
                         ip);
        if (dlen > 8) {
            if ((2 == c_set) || (3 == c_set)) { /* ASCII or UTF-8 */
                n += my_snprintf(b + n, blen - n, "%s      vendor specific: "
                                 "%.*s\n", lip, dlen - 8, ip + 8);
            } else {
                n += my_snprintf(b + n, blen - n, "%s      vendor specific: "
                                 "0x", lip);
                for (m = 8; m < dlen; ++m)
                    n += my_snprintf(b + n, blen - n, "%02x",
                                     (unsigned int)ip[m]);
                n += my_snprintf(b + n, blen - n, "\n");
            }
        }
        break;
    case 2: /* EUI-64 based */
        if (! do_long) {
            if ((8 != dlen) && (12 != dlen) && (16 != dlen)) {
                n += my_snprintf(b + n, blen - n, "%s      << expect 8, 12 "
                                 "and 16 byte EUI, got %d >>\n", lip, dlen);
                 n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n,
                                 b + n);
                break;
            }
            n += my_snprintf(b + n, blen - n, "%s      0x", lip);
            for (m = 0; m < dlen; ++m)
                n += my_snprintf(b + n, blen - n, "%02x", (unsigned int)ip[m]);
            n += my_snprintf(b + n, blen - n, "\n");
            break;
        }
        n += my_snprintf(b + n, blen - n, "%s      EUI-64 based %d byte "
                         "identifier\n", lip, dlen);
        if (1 != c_set) {
            n += my_snprintf(b + n, blen - n, "%s      << expected binary "
                             "code_set (1) >>\n", lip);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
            break;
        }
        ci_off = 0;
        if (16 == dlen) {
            ci_off = 8;
            id_ext = sg_get_unaligned_be64(ip);
            n += my_snprintf(b + n, blen - n, "%s      Identifier extension: "
                             "0x%" PRIx64 "\n", lip, id_ext);
        } else if ((8 != dlen) && (12 != dlen)) {
            n += my_snprintf(b + n, blen - n, "%s      << can only decode 8, "
                             "12 and 16 byte ids >>\n", lip);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
            break;
        }
        c_id = sg_get_unaligned_be24(ip + ci_off);
        n += my_snprintf(b + n, blen - n, "%s      IEEE Company_id: 0x%x\n",
                         lip, c_id);
        vsei = 0;
        for (m = 0; m < 5; ++m) {
            if (m > 0)
                vsei <<= 8;
            vsei |= ip[ci_off + 3 + m];
        }
        n += my_snprintf(b + n, blen - n, "%s      Vendor Specific Extension "
                         "Identifier: 0x%" PRIx64 "\n", lip, vsei);
        if (12 == dlen) {
            d_id = sg_get_unaligned_be32(ip + 8);
            n += my_snprintf(b + n, blen - n, "%s      Directory ID: 0x%x\n",
                             lip, d_id);
        }
        break;
    case 3: /* NAA <n> */
        if (1 != c_set) {
            n += my_snprintf(b + n, blen - n, "%s      << unexpected code "
                             "set %d for NAA >>\n", lip, c_set);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
            break;
        }
        naa = (ip[0] >> 4) & 0xff;
        switch (naa) {
        case 2:         /* NAA 2: IEEE Extended */
            if (8 != dlen) {
                n += my_snprintf(b + n, blen - n, "%s      << unexpected NAA "
                                 "2 identifier length: 0x%x >>\n", lip, dlen);
                n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n,
                                b + n);
                break;
            }
            d_id = (((ip[0] & 0xf) << 8) | ip[1]);
            c_id = sg_get_unaligned_be24(ip + 2);
            vsi = sg_get_unaligned_be24(ip + 5);
            if (do_long) {
                n += my_snprintf(b + n, blen - n, "%s      NAA 2, vendor "
                                 "specific identifier A: 0x%x\n", lip, d_id);
                n += my_snprintf(b + n, blen - n, "%s      IEEE Company_id: "
                                 "0x%x\n", lip, c_id);
                n += my_snprintf(b + n, blen - n, "%s      vendor specific "
                                 "identifier B: 0x%x\n", lip, vsi);
                n += my_snprintf(b + n, blen - n, "%s      [0x", lip);
                for (m = 0; m < 8; ++m)
                    n += my_snprintf(b + n, blen - n, "%02x",
                                     (unsigned int)ip[m]);
                n += my_snprintf(b + n, blen - n, "]\n");
            }
            n += my_snprintf(b + n, blen - n, "%s      0x", lip);
            for (m = 0; m < 8; ++m)
                n += my_snprintf(b + n, blen - n, "%02x", (unsigned int)ip[m]);
            n += my_snprintf(b + n, blen - n, "\n");
            break;
        case 3:         /* NAA 3: Locally assigned */
            if (8 != dlen) {
                n += my_snprintf(b + n, blen - n, "%s      << unexpected NAA "
                                 "3 identifier length: 0x%x >>\n", lip, dlen);
                n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n,
                                b + n);
                break;
            }
            if (do_long)
                n += my_snprintf(b + n, blen - n, "%s      NAA 3, Locally "
                                 "assigned:\n", lip);
            n += my_snprintf(b + n, blen - n, "%s      0x", lip);
            for (m = 0; m < 8; ++m)
                n += my_snprintf(b + n, blen - n, "%02x", (unsigned int)ip[m]);
            n += my_snprintf(b + n, blen - n, "\n");
            break;
        case 5:         /* NAA 5: IEEE Registered */
            if (8 != dlen) {
                n += my_snprintf(b + n, blen - n, "%s      << unexpected NAA "
                                 "5 identifier length: 0x%x >>\n", lip, dlen);
                n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n,
                                b + n);
                break;
            }
            c_id = (((ip[0] & 0xf) << 20) | (ip[1] << 12) |
                    (ip[2] << 4) | ((ip[3] & 0xf0) >> 4));
            vsei = ip[3] & 0xf;
            for (m = 1; m < 5; ++m) {
                vsei <<= 8;
                vsei |= ip[3 + m];
            }
            if (do_long) {
                n += my_snprintf(b + n, blen - n, "%s      NAA 5, IEEE "
                                 "Company_id: 0x%x\n", lip, c_id);
                n += my_snprintf(b + n, blen - n, "%s      Vendor Specific "
                                 "Identifier: 0x%" PRIx64 "\n", lip, vsei);
                n += my_snprintf(b + n, blen - n, "%s      [0x", lip);
                for (m = 0; m < 8; ++m)
                    n += my_snprintf(b + n, blen - n, "%02x",
                                     (unsigned int)ip[m]);
                n += my_snprintf(b + n, blen - n, "]\n");
            } else {
                n += my_snprintf(b + n, blen - n, "%s      0x", lip);
                for (m = 0; m < 8; ++m)
                    n += my_snprintf(b + n, blen - n, "%02x",
                                     (unsigned int)ip[m]);
                n += my_snprintf(b + n, blen - n, "\n");
            }
            break;
        case 6:         /* NAA 6: IEEE Registered extended */
            if (16 != dlen) {
                n += my_snprintf(b + n, blen - n, "%s      << unexpected NAA "
                                 "6 identifier length: 0x%x >>\n", lip, dlen);
                n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n,
                                b + n);
                break;
            }
            c_id = (((ip[0] & 0xf) << 20) | (ip[1] << 12) |
                    (ip[2] << 4) | ((ip[3] & 0xf0) >> 4));
            vsei = ip[3] & 0xf;
            for (m = 1; m < 5; ++m) {
                vsei <<= 8;
                vsei |= ip[3 + m];
            }
            if (do_long) {
                n += my_snprintf(b + n, blen - n, "%s      NAA 6, IEEE "
                                 "Company_id: 0x%x\n", lip, c_id);
                n += my_snprintf(b + n, blen - n, "%s      Vendor Specific "
                                 "Identifier: 0x%" PRIx64 "\n", lip, vsei);
                vsei = sg_get_unaligned_be64(ip + 8);
                n += my_snprintf(b + n, blen - n, "%s      Vendor Specific "
                                 "Identifier Extension: 0x%" PRIx64 "\n", lip,
                                 vsei);
                n += my_snprintf(b + n, blen - n, "%s      [0x", lip);
                for (m = 0; m < 16; ++m)
                    n += my_snprintf(b + n, blen - n, "%02x",
                                     (unsigned int)ip[m]);
                n += my_snprintf(b + n, blen - n, "]\n");
            } else {
                n += my_snprintf(b + n, blen - n, "%s      0x", lip);
                for (m = 0; m < 16; ++m)
                    n += my_snprintf(b + n, blen - n, "%02x",
                                     (unsigned int)ip[m]);
                n += my_snprintf(b + n, blen - n, "\n");
            }
            break;
        default:
            n += my_snprintf(b + n, blen - n, "%s      << unexpected NAA "
                             "[0x%x] >>\n", lip, naa);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
            break;
        }
        break;
    case 4: /* Relative target port */
        if ((1 != c_set) || (1 != assoc) || (4 != dlen)) {
            n += my_snprintf(b + n, blen - n, "%s      << expected binary "
                             "code_set, target port association, length 4 "
                             ">>\n", lip);
            n += dStrHexStr((const char *)ip, dlen, "", 0, blen - n, b + n);
            break;
        }
        d_id = sg_get_unaligned_be16(ip + 2);
        n += my_snprintf(b + n, blen - n, "%s      Relative target port: "
                         "0x%x\n", lip, d_id);
        break;
    case 5: /* (primary) Target port group */
        if ((1 != c_set) || (1 != assoc) || (4 != dlen)) {
            n += my_snprintf(b + n, blen - n, "%s      << expected binary "
                             "code_set, target port association, length 4 "
                             ">>\n", lip);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
            break;
        }
        d_id = sg_get_unaligned_be16(ip + 2);
        n += my_snprintf(b + n, blen - n, "%s      Target port group: 0x%x\n",
                         lip, d_id);
        break;
    case 6: /* Logical unit group */
        if ((1 != c_set) || (0 != assoc) || (4 != dlen)) {
            n += my_snprintf(b + n, blen - n, "%s      << expected binary "
                             "code_set, logical unit association, length "
                             "4 >>\n", lip);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
            break;
        }
        d_id = sg_get_unaligned_be16(ip + 2);
        n += my_snprintf(b + n, blen - n, "%s      Logical unit group: "
                         "0x%x\n", lip, d_id);
        break;
    case 7: /* MD5 logical unit identifier */
        if ((1 != c_set) || (0 != assoc)) {
            n += my_snprintf(b + n, blen - n, "%s      << expected binary "
                             "code_set, logical unit association >>\n", lip);
            n += dStrHexStr((const char *)ip, dlen, "", 0, blen - n, b + n);
            break;
        }
        n += my_snprintf(b + n, blen - n, "%s      MD5 logical unit "
                         "identifier:\n", lip);
        n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
        break;
    case 8: /* SCSI name string */
        if (3 != c_set) {
            n += my_snprintf(b + n, blen - n, "%s      << expected UTF-8 "
                             "code_set >>\n", lip);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
            break;
        }
        n += my_snprintf(b + n, blen - n, "%s      SCSI name string:\n", lip);
        /* does %s print out UTF-8 ok??
         * Seems to depend on the locale. Looks ok here with my
         * locale setting: en_AU.UTF-8
         */
        n += my_snprintf(b + n, blen - n, "%s      %s\n", lip,
                         (const char *)ip);
        break;
    case 9: /* Protocol specific port identifier */
        /* added in spc4r36, PIV must be set, proto_id indicates */
        /* whether UAS (USB) or SOP (PCIe) or ... */
        if (! piv)
            n += my_snprintf(b + n, blen - n, " %s      >>>> Protocol "
                             "specific port identifier expects protocol\n"
                             "%s           identifier to be valid and it is "
                             "not\n", lip, lip);
        if (TPROTO_UAS == p_id) {
            n += my_snprintf(b + n, blen - n, "%s      USB device address: "
                             "0x%x\n", lip, 0x7f & ip[0]);
            n += my_snprintf(b + n, blen - n, "%s      USB interface number: "
                             "0x%x\n", lip, ip[2]);
        } else if (TPROTO_SOP == p_id) {
            n += my_snprintf(b + n, blen - n, "%s      PCIe routing ID, bus "
                             "number: 0x%x\n", lip, ip[0]);
            n += my_snprintf(b + n, blen - n, "%s          function number: "
                             "0x%x\n", lip, ip[1]);
            n += my_snprintf(b + n, blen - n, "%s          [or device "
                             "number: 0x%x, function number: 0x%x]\n", lip,
                             (0x1f & (ip[1] >> 3)), 0x7 & ip[1]);
        } else
            n += my_snprintf(b + n, blen - n, "%s      >>>> unexpected "
                             "protocol indentifier: %s\n%s           with "
                             "Protocol specific port identifier\n", lip,
                   sg_get_trans_proto_str(p_id, sizeof(e), e), lip);
        break;
    case 0xa: /* UUID identifier */
        if (1 != c_set) {
            n += my_snprintf(b + n, blen - n, "%s      << expected binary "
                             "code_set >>\n", lip);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
            break;
        }
        if ((1 != ((ip[0] >> 4) & 0xf)) || (18 != dlen)) {
            n += my_snprintf(b + n, blen - n, "%s      << expected locally "
                             "assigned UUID, 16 bytes long >>\n", lip);
            n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
            break;
        }
        n += my_snprintf(b + n, blen - n, "%s      Locally assigned UUID: ",
                         lip);
        for (m = 0; m < 16; ++m) {
            if ((4 == m) || (6 == m) || (8 == m) || (10 == m))
                n += my_snprintf(b + n, blen - n, "-");
            n += my_snprintf(b + n, blen - n, "%02x", (unsigned int)ip[2 + m]);
        }
        n += my_snprintf(b + n, blen - n, "\n");
        if (do_long) {
            n += my_snprintf(b + n, blen - n, "%s      [0x", lip);
            for (m = 0; m < 16; ++m)
                n += my_snprintf(b + n, blen - n, "%02x",
                                 (unsigned int)ip[2 + m]);
            n += my_snprintf(b + n, blen - n, "]\n");
        }
        break;
    default: /* reserved */
        n += my_snprintf(b + n, blen - n, "%s      reserved "
                         "designator=0x%x\n", lip, desig_type);
        n += dStrHexStr((const char *)ip, dlen, lip, 0, blen - n, b + n);
        break;
    }
    return n;
}

static int
decode_sks(const char * leadin, const unsigned char * descp, int add_d_len,
           int sense_key, int * processedp, int blen, char * b)
{
    int progress, pr, rem, n;
    const char * lip = "";

    n = 0;
    if (leadin)
        lip = leadin;
    switch (sense_key) {
    case SPC_SK_ILLEGAL_REQUEST:
        if (add_d_len < 6) {
            n += my_snprintf(b + n, blen - n, "Field pointer: ");
            goto too_short;
        }
        /* abbreviate to fit on one line */
        n += my_snprintf(b + n, blen - n, "Field pointer:\n");
        n += my_snprintf(b + n, blen - n, "%s        Error in %s: byte %d",
                         lip, (descp[4] & 0x40) ? "Command" :
                                                  "Data parameters",
                         sg_get_unaligned_be16(descp + 5));
        if (descp[4] & 0x08) {
            n += my_snprintf(b + n, blen - n, " bit %d\n",
                             descp[4] & 0x07);
        } else
            n += my_snprintf(b + n, blen - n, "\n");
        break;
    case SPC_SK_HARDWARE_ERROR:
    case SPC_SK_MEDIUM_ERROR:
    case SPC_SK_RECOVERED_ERROR:
        n += my_snprintf(b + n, blen - n, "Actual retry count: ");
        if (add_d_len < 6)
            goto too_short;
        n += my_snprintf(b + n, blen - n,"%u\n",
                         sg_get_unaligned_be16(descp + 5));
        break;
    case SPC_SK_NO_SENSE:
    case SPC_SK_NOT_READY:
        n += my_snprintf(b + n, blen - n, "Progress indication: ");
        if (add_d_len < 6)
            goto too_short;
        progress = sg_get_unaligned_be16(descp + 5);
        pr = (progress * 100) / 65536;
        rem = ((progress * 100) % 65536) / 656;
        n += my_snprintf(b + n, blen - n, "%d.%02d%%\n", pr, rem);
        break;
    case SPC_SK_COPY_ABORTED:
        n += my_snprintf(b + n, blen - n, "Segment pointer:\n");
        if (add_d_len < 6)
            goto too_short;
        n += my_snprintf(b + n, blen - n, "%s        Relative to start of "
                         "%s, byte %d", lip,
                         (descp[4] & 0x20) ? "segment descriptor" :
                                             "parameter list",
                         sg_get_unaligned_be16(descp + 5));
        if (descp[4] & 0x08)
            n += my_snprintf(b + n, blen - n, " bit %d\n",
                             descp[4] & 0x07);
        else
            n += my_snprintf(b + n, blen - n, "\n");
        break;
    case SPC_SK_UNIT_ATTENTION:
        n += my_snprintf(b + n, blen - n, "Unit attention condition "
                         "queue:\n");
        n += my_snprintf(b + n, blen - n, "%s        overflow flag is %d\n",
                         lip, !!(descp[4] & 0x1));
        break;
    default:
        n += my_snprintf(b + n, blen - n, "Sense_key: 0x%x "
                         "unexpected\n", sense_key);
        *processedp = 0;
        break;
    }
    return n;

too_short:
    n += my_snprintf(b + n, blen - n, "%s\n", "   >> descriptor too short");
    *processedp = 0;
    return n;
}

#define TPGS_STATE_OPTIMIZED 0x0
#define TPGS_STATE_NONOPTIMIZED 0x1
#define TPGS_STATE_STANDBY 0x2
#define TPGS_STATE_UNAVAILABLE 0x3
#define TPGS_STATE_OFFLINE 0xe
#define TPGS_STATE_TRANSITIONING 0xf

static int
decode_tpgs_state(int st, char * b, int blen)
{
    switch (st) {
    case TPGS_STATE_OPTIMIZED:
        return my_snprintf(b, blen, "active/optimized");
    case TPGS_STATE_NONOPTIMIZED:
        return my_snprintf(b, blen, "active/non optimized");
    case TPGS_STATE_STANDBY:
        return my_snprintf(b, blen, "standby");
    case TPGS_STATE_UNAVAILABLE:
        return my_snprintf(b, blen, "unavailable");
    case TPGS_STATE_OFFLINE:
        return my_snprintf(b, blen, "offline");
    case TPGS_STATE_TRANSITIONING:
        return my_snprintf(b, blen, "transitioning between states");
    default:
        return my_snprintf(b, blen, "unknown: 0x%x", st);
    }
}

static int
uds_referral_descriptor_str(char * b, int blen, const unsigned char * dp,
                            int alen, const char * leadin)
{
    int n = 0;
    int dlen = alen - 2;
    int k, j, g, f, tpgd;
    const unsigned char * tp;
    uint64_t ull;
    char c[40];
    const char * lip = "";

    if (leadin)
        lip = leadin;
    n += my_snprintf(b + n, blen - n, "%s   Not all referrals: %d\n", lip,
                     !!(dp[2] & 0x1));
    dp += 4;
    for (k = 0, f = 1; (k + 4) < dlen; k += g, dp += g, ++f) {
        tpgd = dp[3];
        g = (tpgd * 4) + 20;
        n += my_snprintf(b + n, blen - n, "%s    Descriptor %d\n", lip, f);
        if ((k + g) > dlen) {
            n += my_snprintf(b + n, blen - n, "%s      truncated descriptor, "
                             "stop\n", lip);
            return n;
        }
        ull = sg_get_unaligned_be64(dp + 4);
        n += my_snprintf(b + n, blen - n, "%s      first uds LBA: 0x%" PRIx64
                         "\n", lip, ull);
        ull = sg_get_unaligned_be64(dp + 12);
        n += my_snprintf(b + n, blen - n, "%s      last uds LBA:  0x%" PRIx64
                         "\n", lip, ull);
        for (j = 0; j < tpgd; ++j) {
            tp = dp + 20 + (j * 4);
            decode_tpgs_state(tp[0] & 0xf, c, sizeof(c));
            n += my_snprintf(b + n, blen - n, "%s        tpg: %d  state: "
                             "%s\n", lip, sg_get_unaligned_be16(tp + 2), c);
        }
    }
    return n;
}

static const char * dd_usage_reason_str_arr[] = {
    "Unknown",
    "resend this and further commands to:",
    "resend this command to:",
    "new subsiduary lu added to this administrative lu:",
    "administrative lu associated with a preferred binding:",
   };


/* Decode descriptor format sense descriptors (assumes sense buffer is
 * in descriptor format) */
int
sg_get_sense_descriptors_str(const char * leadin,
                             const unsigned char * sense_buffer, int sb_len,
                             int blen, char * b)
{
    int add_sb_len, add_d_len, desc_len, k, j, sense_key, processed;
    int n, progress, pr, rem;
    const unsigned char * descp;
    const char * lip = "";
    const char * dtsp = "   >> descriptor too short";
    const char * eccp = "Extended copy command";
    const char * ddp = "destination device";
    char z[64];

    if ((NULL == b) || (blen <= 0))
        return 0;
    b[0] = '\0';
    if (leadin) {
        lip = leadin;
        snprintf(z, sizeof(z), "%.60s  ", lip);
    } else
         snprintf(z, sizeof(z), "  ");
    if ((sb_len < 8) || (0 == (add_sb_len = sense_buffer[7])))
        return 0;
    add_sb_len = (add_sb_len < (sb_len - 8)) ? add_sb_len : (sb_len - 8);
    sense_key = (sense_buffer[1] & 0xf);

    for (descp = (sense_buffer + 8), k = 0, n = 0;
         (k < add_sb_len) && (n < blen);
         k += desc_len, descp += desc_len) {
        add_d_len = (k < (add_sb_len - 1)) ? descp[1] : -1;
        if ((k + add_d_len + 2) > add_sb_len)
            add_d_len = add_sb_len - k - 2;
        desc_len = add_d_len + 2;
        n += my_snprintf(b + n, blen - n, "%s  Descriptor type: ", lip);
        processed = 1;
        switch (descp[0]) {
        case 0:
            n += my_snprintf(b + n, blen - n, "Information: ");
            if ((add_d_len >= 10) && (0x80 & descp[2])) {
                n += my_snprintf(b + n, blen - n, "0x");
                for (j = 0; j < 8; ++j)
                    n += my_snprintf(b + n, blen - n, "%02x", descp[4 + j]);
                n += my_snprintf(b + n, blen - n, "\n");
            } else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 1:
            n += my_snprintf(b + n, blen - n, "Command specific: ");
            if (add_d_len >= 10) {
                n += my_snprintf(b + n, blen - n, "0x");
                for (j = 0; j < 8; ++j)
                    n += my_snprintf(b + n, blen - n, "%02x", descp[4 + j]);
                n += my_snprintf(b + n, blen - n, "\n");
            } else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 2:         /* Sense Key Specific */
            n += my_snprintf(b + n, blen - n, "Sense key specific: ");
            n += decode_sks(lip, descp, add_d_len, sense_key, &processed,
                            blen - n, b + n);
            break;
        case 3:
            n += my_snprintf(b + n, blen - n, "Field replaceable unit code: ");
            if (add_d_len >= 2)
                n += my_snprintf(b + n, blen - n, "0x%x\n", descp[3]);
            else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 4:
            n += my_snprintf(b + n, blen - n, "Stream commands: ");
            if (add_d_len >= 2) {
                if (descp[3] & 0x80)
                    n += my_snprintf(b + n, blen - n, "FILEMARK");
                if (descp[3] & 0x40)
                    n += my_snprintf(b + n, blen - n, "End Of Medium (EOM)");
                if (descp[3] & 0x20)
                    n += my_snprintf(b + n, blen - n, "Incorrect Length "
                                     "Indicator (ILI)");
                n += my_snprintf(b + n, blen - n, "\n");
            } else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 5:
            n += my_snprintf(b + n, blen - n, "Block commands: ");
            if (add_d_len >= 2)
                n += my_snprintf(b + n, blen - n, "Incorrect Length "
                                 "Indicator (ILI) %s\n",
                                 (descp[3] & 0x20) ? "set" : "clear");
            else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 6:
            n += my_snprintf(b + n, blen - n, "OSD object identification\n");
            processed = 0;
            break;
        case 7:
            n += my_snprintf(b + n, blen - n, "OSD response integrity check "
                             "value\n");
            processed = 0;
            break;
        case 8:
            n += my_snprintf(b + n, blen - n, "OSD attribute "
                             "identification\n");
            processed = 0;
            break;
        case 9:         /* this is defined in SAT (SAT-2) */
            n += my_snprintf(b + n, blen - n, "ATA Status Return: ");
            if (add_d_len >= 12) {
                int extend, count;

                extend = descp[2] & 1;
                count = descp[5] + (extend ? (descp[4] << 8) : 0);
                n += my_snprintf(b + n, blen - n, "extend=%d error=0x%x "
                                 "\n%s        count=0x%x ", extend,
                                 descp[3], lip, count);
                if (extend)
                    n += my_snprintf(b + n, blen - n,
                                     "lba=0x%02x%02x%02x%02x%02x%02x ",
                                     descp[10], descp[8], descp[6],
                                     descp[11], descp[9], descp[7]);
                else
                    n += my_snprintf(b + n, blen - n,
                                     "lba=0x%02x%02x%02x ",
                                     descp[11], descp[9], descp[7]);
                n += my_snprintf(b + n, blen - n, "device=0x%x status=0x%x\n",
                                 descp[12], descp[13]);
            } else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 0xa:
           /* Added in SPC-4 rev 17, became 'Another ...' in rev 34 */
            n += my_snprintf(b + n, blen - n, "Another progress "
                             "indication: ");
            if (add_d_len < 6) {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
                break;
            }
            progress = sg_get_unaligned_be16(descp + 6);
            pr = (progress * 100) / 65536;
            rem = ((progress * 100) % 65536) / 656;
            n += my_snprintf(b + n, blen - n, "%d.02%d%%\n", pr, rem);
            n += my_snprintf(b + n, blen - n, "%s        [sense_key=0x%x "
                             "asc,ascq=0x%x,0x%x]\n", lip, descp[2], descp[3],
                             descp[4]);
            break;
        case 0xb:       /* Added in SPC-4 rev 23, defined in SBC-3 rev 22 */
            n += my_snprintf(b + n, blen - n, "User data segment referral: ");
            if (add_d_len < 2) {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
                break;
            }
            n += my_snprintf(b + n, blen - n, "\n");
            n += uds_referral_descriptor_str(b + n, blen - n, descp,
                                             add_d_len, lip);
            break;
        case 0xc:       /* Added in SPC-4 rev 28 */
            n += my_snprintf(b + n, blen - n, "Forwarded sense data\n");
            if (add_d_len < 2) {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
                break;
            }
            n += my_snprintf(b + n, blen - n, "%s    FSDT: %s\n", lip,
                             (descp[2] & 0x80) ? "set" : "clear");
            j = descp[2] & 0xf;
            n += my_snprintf(b + n, blen - n, "%s    Sense data source: ",
                             lip);
            switch (j) {
            case 0:
                n += my_snprintf(b + n, blen - n, "%s source device\n", eccp);
                break;
            case 1:
            case 2:
            case 3:
            case 4:
            case 5:
            case 6:
            case 7:
                n += my_snprintf(b + n, blen - n, "%s %s %d\n", eccp, ddp,
                                 j - 1);
                break;
            default:
                n += my_snprintf(b + n, blen - n, "unknown [%d]\n", j);
            }
            {
                char c[480];

                sg_get_scsi_status_str(descp[3], sizeof(c) - 1, c);
                c[sizeof(c) - 1] = '\0';
                n += my_snprintf(b + n, blen - n, "%s    Forwarded status: "
                                 "%s\n", lip, c);
                if (add_d_len > 2) {
                    /* recursing; hope not to get carried away */
                    n += my_snprintf(b + n, blen - n, "%s vvvvvvvvvvvvvvvv\n",
                                     lip);
                    sg_get_sense_str(lip, descp + 4, add_d_len - 2, 0,
                                     sizeof(c), c);
                    n += my_snprintf(b + n, blen - n, "%s", c);
                    n += my_snprintf(b + n, blen - n, "%s ^^^^^^^^^^^^^^^^\n",
                                     lip);
                }
            }
            break;
        case 0xd:       /* Added in SBC-3 rev 36d */
            /* this descriptor combines descriptors 0, 1, 2 and 3 */
            n += my_snprintf(b + n, blen - n, "Direct-access block device\n");
            if (add_d_len < 28) {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
                break;
            }
            if (0x20 & descp[2])
                n += my_snprintf(b + n, blen - n, "%s    ILI (incorrect "
                                 "length indication) set\n", lip);
            if (0x80 & descp[4]) {
                n += my_snprintf(b + n, blen - n, "%s    Sense key "
                                 "specific: ", lip);
                n += decode_sks(lip, descp, add_d_len, sense_key, &processed,
                                blen - n, b + n);
            }
            n += my_snprintf(b + n, blen - n, "%s    Field replaceable unit "
                             "code: 0x%x\n", lip, descp[7]);
            if (0x80 & descp[2]) {
                n += my_snprintf(b + n, blen - n, "%s    Information: 0x",
                                 lip);
                for (j = 0; j < 8; ++j)
                    n += my_snprintf(b + n, blen - n, "%02x", descp[8 + j]);
                n += my_snprintf(b + n, blen - n, "\n");
            }
            n += my_snprintf(b + n, blen - n, "%s    Command specific: 0x",
                             lip);
            for (j = 0; j < 8; ++j)
                n += my_snprintf(b + n, blen - n, "%02x", descp[16 + j]);
            n += my_snprintf(b + n, blen - n, "\n");
            break;
        case 0xe:       /* Added in SPC-5 rev 6 (for bind/unbind) */
            n += my_snprintf(b + n, blen - n, "Device designation\n");
            j = (int)(sizeof(dd_usage_reason_str_arr) /
                      sizeof(dd_usage_reason_str_arr[0]));
            if (descp[3] < j)
                n += my_snprintf(b + n, blen - n, "%s    Usage reason: %s\n",
                                 lip, dd_usage_reason_str_arr[descp[3]]);
            else
                n += my_snprintf(b + n, blen - n, "%s    Usage reason: "
                                 "reserved[%d]\n", lip, descp[3]);
            n += sg_get_designation_descriptor_str(z, descp + 4, descp[1] - 2,
                                                   1, 0, blen - n, b + n);
            break;
        default:
            if (descp[0] >= 0x80)
                n += my_snprintf(b + n, blen - n, "Vendor specific [0x%x]\n",
                                 descp[0]);
            else
                n += my_snprintf(b + n, blen - n, "Unknown [0x%x]\n",
                                 descp[0]);
            processed = 0;
            break;
        }
        if (! processed) {
            if (add_d_len > 0) {
                n += my_snprintf(b + n, blen - n, "%s    ", lip);
                for (j = 0; j < add_d_len; ++j) {
                    if ((j > 0) && (0 == (j % 24)))
                        n += my_snprintf(b + n, blen - n, "\n%s    ", lip);
                    n += my_snprintf(b + n, blen - n, "%02x ", descp[j + 2]);
                }
                n += my_snprintf(b + n, blen - n, "\n");
            }
        }
        if (add_d_len < 0)
            n += my_snprintf(b + n, blen - n, "%s    short descriptor\n", lip);
    }
    return n;
}

/* Decode SAT ATA PASS-THROUGH fixed format sense */
static int
sg_get_sense_sat_pt_fixed_str(const char * leadin, const unsigned char * sp,
                              int slen, int blen, char * b)
{
    int n = 0;
    const char * lip = "";

    if ((blen < 1) || (slen < 12))
        return n;
    if (leadin)
        lip = leadin;
    if (SPC_SK_RECOVERED_ERROR != (0xf & sp[2]))
        n += my_snprintf(b + n, blen - n, "%s  >> expected Sense key: "
                         "Recovered Error ??\n", lip);
    n += my_snprintf(b + n, blen - n, "%s  error=0x%x, status=0x%x, "
                     "device=0x%x, sector_count(7:0)=0x%x%c\n", lip, sp[3],
                     sp[4], sp[5], sp[6], ((0x40 & sp[8]) ? '+' : ' '));
    n += my_snprintf(b + n, blen - n, "%s  extend=%d, log_index=0x%x, "
                     "lba_high,mid,low(7:0)=0x%x,0x%x,0x%x%c\n", lip,
                     (!!(0x80 & sp[8])), (0xf & sp[8]), sp[9], sp[10], sp[11],
                     ((0x20 & sp[8]) ? '+' : ' '));
    return n;
}

/* Fetch sense information */
int
sg_get_sense_str(const char * leadin, const unsigned char * sense_buffer,
                 int sb_len, int raw_sinfo, int buff_len, char * buff)
{
    int len, valid, progress, n, r, pr, rem, blen;
    unsigned int info;
    int descriptor_format = 0;
    int sdat_ovfl = 0;
    const char * ebp = NULL;
    char error_buff[64];
    char b[256];
    struct sg_scsi_sense_hdr ssh;
    const char * lip = "";

    if ((NULL == buff) || (buff_len <= 0))
        return 0;
    else if (1 == buff_len) {
        buff[0] = '\0';
        return 0;
    }
    blen = sizeof(b);
    n = 0;
    if (leadin)
        lip = leadin;
    if ((NULL == sense_buffer) || (sb_len < 1)) {
            n += my_snprintf(buff, buff_len, "%s >>> sense buffer empty\n",
                             lip);
            return n;
    }
    len = sb_len;
    if (sg_scsi_normalize_sense(sense_buffer, sb_len, &ssh)) {
        switch (ssh.response_code) {
        case 0x70:      /* fixed, current */
            ebp = "Fixed format, current";
            len = (sb_len > 7) ? (sense_buffer[7] + 8) : sb_len;
            len = (len > sb_len) ? sb_len : len;
            sdat_ovfl = (len > 2) ? !!(sense_buffer[2] & 0x10) : 0;
            break;
        case 0x71:      /* fixed, deferred */
            /* error related to a previous command */
            ebp = "Fixed format, <<<deferred>>>";
            len = (sb_len > 7) ? (sense_buffer[7] + 8) : sb_len;
            len = (len > sb_len) ? sb_len : len;
            sdat_ovfl = (len > 2) ? !!(sense_buffer[2] & 0x10) : 0;
            break;
        case 0x72:      /* descriptor, current */
            descriptor_format = 1;
            ebp = "Descriptor format, current";
            sdat_ovfl = (sb_len > 4) ? !!(sense_buffer[4] & 0x80) : 0;
            break;
        case 0x73:      /* descriptor, deferred */
            descriptor_format = 1;
            ebp = "Descriptor format, <<<deferred>>>";
            sdat_ovfl = (sb_len > 4) ? !!(sense_buffer[4] & 0x80) : 0;
            break;
        case 0x0:
            ebp = "Response code: 0x0 (?)";
            break;
        default:
            my_snprintf(error_buff, sizeof(error_buff),
                        "Unknown response code: 0x%x", ssh.response_code);
            ebp = error_buff;
            break;
        }
        n += my_snprintf(buff + n, buff_len - n, "%s%s; Sense key: %s\n",
                         lip, ebp, sg_lib_sense_key_desc[ssh.sense_key]);
        if (sdat_ovfl)
            n += my_snprintf(buff + n, buff_len - n, "%s<<<Sense data "
                             "overflow>>>\n", lip);
        if (descriptor_format) {
            n += my_snprintf(buff + n, buff_len - n, "%s%s\n", lip,
                             sg_get_asc_ascq_str(ssh.asc, ssh.ascq,
                                                 sizeof(b), b));
            n += sg_get_sense_descriptors_str(lip, sense_buffer, len,
                                              buff_len - n, buff + n);
        } else if ((len > 12) && (0 == ssh.asc) &&
                   (ASCQ_ATA_PT_INFO_AVAILABLE == ssh.ascq)) {
            /* SAT ATA PASS-THROUGH fixed format */
            n += my_snprintf(buff + n, buff_len - n, "%s%s\n", lip,
                             sg_get_asc_ascq_str(ssh.asc, ssh.ascq,
                             sizeof(b), b));
            n += sg_get_sense_sat_pt_fixed_str(lip, sense_buffer, len,
                                               buff_len - n, buff + n);
        } else if (len > 2) {   /* fixed format */
            if (len > 12)
                n += my_snprintf(buff + n, buff_len - n, "%s%s\n", lip,
                                 sg_get_asc_ascq_str(ssh.asc, ssh.ascq,
                                                     sizeof(b), b));
            r = 0;
            valid = sense_buffer[0] & 0x80;
            if (strlen(lip) > 0)
                r += my_snprintf(b + r, blen - r, "%s", lip);
            if (len > 6) {
                info = sg_get_unaligned_be32(sense_buffer + 3);
                if (valid)
                    r += my_snprintf(b + r, blen - r, "  Info fld=0x%x [%u] ",
                                     info, info);
                else if (info > 0)
                    r += my_snprintf(b + r, blen - r, "  Valid=0, Info "
                                     "fld=0x%x [%u] ", info, info);
            } else
                info = 0;
            if (sense_buffer[2] & 0xe0) {
                if (sense_buffer[2] & 0x80)
                   r += my_snprintf(b + r, blen - r, " FMK");
                            /* current command has read a filemark */
                if (sense_buffer[2] & 0x40)
                   r += my_snprintf(b + r, blen - r, " EOM");
                            /* end-of-medium condition exists */
                if (sense_buffer[2] & 0x20)
                   r += my_snprintf(b + r, blen - r, " ILI");
                            /* incorrect block length requested */
                r += my_snprintf(b + r, blen - r, "\n");
            } else if (valid || (info > 0))
                r += my_snprintf(b + r, blen - r, "\n");
            if ((len >= 14) && sense_buffer[14])
                r += my_snprintf(b + r, blen - r, "%s  Field replaceable unit "
                                 "code: %d\n", lip, sense_buffer[14]);
            if ((len >= 18) && (sense_buffer[15] & 0x80)) {
                /* sense key specific decoding */
                switch (ssh.sense_key) {
                case SPC_SK_ILLEGAL_REQUEST:
                    r += my_snprintf(b + r, blen - r, "%s  Sense Key "
                                     "Specific: Error in %s: byte %d", lip,
                             ((sense_buffer[15] & 0x40) ? "Command" :
                                                          "Data parameters"),
                             sg_get_unaligned_be16(sense_buffer + 16));
                    if (sense_buffer[15] & 0x08)
                        r += my_snprintf(b + r, blen - r, " bit %d\n",
                                         sense_buffer[15] & 0x07);
                    else
                        r += my_snprintf(b + r, blen - r, "\n");
                    break;
                case SPC_SK_NO_SENSE:
                case SPC_SK_NOT_READY:
                    progress = sg_get_unaligned_be16(sense_buffer + 16);
                    pr = (progress * 100) / 65536;
                    rem = ((progress * 100) % 65536) / 656;
                    r += my_snprintf(b + r, blen - r, "%s  Progress "
                                     "indication: %d.%02d%%\n", lip, pr, rem);
                    break;
                case SPC_SK_HARDWARE_ERROR:
                case SPC_SK_MEDIUM_ERROR:
                case SPC_SK_RECOVERED_ERROR:
                    r += my_snprintf(b + r, blen - r, "%s  Actual retry "
                                     "count: " "0x%02x%02x\n", lip,
                                     sense_buffer[16], sense_buffer[17]);
                    break;
                case SPC_SK_COPY_ABORTED:
                    r += my_snprintf(b + r, blen - r, "%s  Segment pointer: ",
                                     lip);
                    r += my_snprintf(b + r, blen - r, "Relative to start of "
                                     "%s, byte %d",
                                     ((sense_buffer[15] & 0x20) ?
                                      "segment descriptor" : "parameter list"),
                                     sg_get_unaligned_be16(sense_buffer + 16));
                    if (sense_buffer[15] & 0x08)
                        r += my_snprintf(b + r, blen - r, " bit %d\n",
                                         sense_buffer[15] & 0x07);
                    else
                        r += my_snprintf(b + r, blen - r, "\n");
                    break;
                case SPC_SK_UNIT_ATTENTION:
                    r += my_snprintf(b + r, blen - r, "%s  Unit attention "
                                     "condition queue: ", lip);
                    r += my_snprintf(b + r, blen - r, "overflow flag is %d\n",
                                     !!(sense_buffer[15] & 0x1));
                    break;
                default:
                    r += my_snprintf(b + r, blen - r, "%s  Sense_key: 0x%x "
                                     "unexpected\n", lip, ssh.sense_key);
                    break;
                }
            }
            if (r > 0)
                n += my_snprintf(buff + n, buff_len - n, "%s", b);
        } else
            n += my_snprintf(buff + n, buff_len - n, "%s fixed descriptor "
                             "length too short, len=%d\n", lip, len);
    } else {    /* non-extended SCSI-1 sense data ?? */
        if (sb_len < 4) {
            n += my_snprintf(buff + n, buff_len - n, "%ssense buffer too "
                             "short (4 byte minimum)\n", lip);
            return n;
        }
        r = 0;
        if (strlen(lip) > 0)
            r += my_snprintf(b + r, blen - r, "%s", lip);
        r += my_snprintf(b + r, blen - r, "Probably uninitialized data.\n%s  "
                         "Try to view as SCSI-1 non-extended sense:\n", lip);
        r += my_snprintf(b + r, blen - r, "  AdValid=%d  Error class=%d  "
                         "Error code=%d\n", !!(sense_buffer[0] & 0x80),
                         ((sense_buffer[0] >> 4) & 0x7),
                         (sense_buffer[0] & 0xf));
        if (sense_buffer[0] & 0x80)
            r += my_snprintf(b + r, blen - r, "%s  lba=0x%x\n", lip,
                     sg_get_unaligned_be24(sense_buffer + 1) & 0x1fffff);
        n += my_snprintf(buff + n, buff_len - n, "%s\n", b);
        len = sb_len;
        if (len > 32)
            len = 32;   /* trim in case there is a lot of rubbish */
    }
    if (raw_sinfo) {
        char z[64];

        n += my_snprintf(buff + n, buff_len - n, "%s Raw sense data (in hex):"
                         "\n", lip);
        if (n >= (buff_len - 1))
            return n;
        snprintf(z, sizeof(z), "%.50s        ", lip);
        n += dStrHexStr((const char *)sense_buffer, len, z,  0,
                        buff_len - n, buff + n);
    }
    return n;
}

/* Print sense information */
void
sg_print_sense(const char * leadin, const unsigned char * sense_buffer,
               int sb_len, int raw_sinfo)
{
    char b[2048];

    sg_get_sense_str(leadin, sense_buffer, sb_len, raw_sinfo, sizeof(b), b);
    pr2ws("%s", b);
}

/* See description in sg_lib.h header file */
int
sg_scsi_normalize_sense(const unsigned char * sensep, int sb_len,
                        struct sg_scsi_sense_hdr * sshp)
{
    if (sshp)
        memset(sshp, 0, sizeof(struct sg_scsi_sense_hdr));
    if ((NULL == sensep) || (0 == sb_len) || (0x70 != (0x70 & sensep[0])))
        return 0;
    if (sshp) {
        sshp->response_code = (0x7f & sensep[0]);
        if (sshp->response_code >= 0x72) {  /* descriptor format */
            if (sb_len > 1)
                sshp->sense_key = (0xf & sensep[1]);
            if (sb_len > 2)
                sshp->asc = sensep[2];
            if (sb_len > 3)
                sshp->ascq = sensep[3];
            if (sb_len > 7)
                sshp->additional_length = sensep[7];
        } else {                              /* fixed format */
            if (sb_len > 2)
                sshp->sense_key = (0xf & sensep[2]);
            if (sb_len > 7) {
                sb_len = (sb_len < (sensep[7] + 8)) ? sb_len :
                                                      (sensep[7] + 8);
                if (sb_len > 12)
                    sshp->asc = sensep[12];
                if (sb_len > 13)
                    sshp->ascq = sensep[13];
            }
        }
    }
    return 1;
}

/* Returns a SG_LIB_CAT_* value. If cannot decode sense_buffer or a less
 * common sense key then return SG_LIB_CAT_SENSE .*/
int
sg_err_category_sense(const unsigned char * sense_buffer, int sb_len)
{
    struct sg_scsi_sense_hdr ssh;

    if ((sense_buffer && (sb_len > 2)) &&
        (sg_scsi_normalize_sense(sense_buffer, sb_len, &ssh))) {
        switch (ssh.sense_key) {        /* 0 to 0x1f */
        case SPC_SK_NO_SENSE:
            return SG_LIB_CAT_NO_SENSE;
        case SPC_SK_RECOVERED_ERROR:
            return SG_LIB_CAT_RECOVERED;
        case SPC_SK_NOT_READY:
            return SG_LIB_CAT_NOT_READY;
        case SPC_SK_MEDIUM_ERROR:
        case SPC_SK_HARDWARE_ERROR:
        case SPC_SK_BLANK_CHECK:
            return SG_LIB_CAT_MEDIUM_HARD;
        case SPC_SK_UNIT_ATTENTION:
            return SG_LIB_CAT_UNIT_ATTENTION;
            /* used to return SG_LIB_CAT_MEDIA_CHANGED when ssh.asc==0x28 */
        case SPC_SK_ILLEGAL_REQUEST:
            if ((0x20 == ssh.asc) && (0x0 == ssh.ascq))
                return SG_LIB_CAT_INVALID_OP;
            else
                return SG_LIB_CAT_ILLEGAL_REQ;
            break;
        case SPC_SK_ABORTED_COMMAND:
            if (0x10 == ssh.asc)
                return SG_LIB_CAT_PROTECTION;
            else
                return SG_LIB_CAT_ABORTED_COMMAND;
        case SPC_SK_MISCOMPARE:
            return SG_LIB_CAT_MISCOMPARE;
        case SPC_SK_DATA_PROTECT:
            return SG_LIB_CAT_DATA_PROTECT;
        case SPC_SK_COPY_ABORTED:
            return SG_LIB_CAT_COPY_ABORTED;
        case SPC_SK_COMPLETED:
        case SPC_SK_VOLUME_OVERFLOW:
            return SG_LIB_CAT_SENSE;
        default:
            ;   /* reserved and vendor specific sense keys fall through */
        }
    }
    return SG_LIB_CAT_SENSE;
}

/* Beware: gives wrong answer for variable length command (opcode=0x7f) */
int
sg_get_command_size(unsigned char opcode)
{
    switch ((opcode >> 5) & 0x7) {
    case 0:
        return 6;
    case 1: case 2: case 6: case 7:
        return 10;
    case 3: case 5:
        return 12;
        break;
    case 4:
        return 16;
    default:
        return 10;
    }
}

void
sg_get_command_name(const unsigned char * cmdp, int peri_type, int buff_len,
                    char * buff)
{
    int service_action;

    if ((NULL == buff) || (buff_len < 1))
        return;
    else if (1 == buff_len) {
        buff[0] = '\0';
        return;
    }
    if (NULL == cmdp) {
        my_snprintf(buff, buff_len, "%s", "<null> command pointer");
        return;
    }
    service_action = (SG_VARIABLE_LENGTH_CMD == cmdp[0]) ?
                     sg_get_unaligned_be16(cmdp + 8) : (cmdp[1] & 0x1f);
    sg_get_opcode_sa_name(cmdp[0], service_action, peri_type, buff_len, buff);
}

struct op_code2sa_t {
    int op_code;
    struct sg_lib_value_name_t * arr;
    const char * prefix;
};

static struct op_code2sa_t op_code2sa_arr[] = {
    {SG_VARIABLE_LENGTH_CMD, sg_lib_variable_length_arr, NULL},
    {SG_MAINTENANCE_IN, sg_lib_maint_in_arr, NULL},
    {SG_MAINTENANCE_OUT, sg_lib_maint_out_arr, NULL},
    {SG_SERVICE_ACTION_IN_12, sg_lib_serv_in12_arr, NULL},
    {SG_SERVICE_ACTION_OUT_12, sg_lib_serv_out12_arr, NULL},
    {SG_SERVICE_ACTION_IN_16, sg_lib_serv_in16_arr, NULL},
    {SG_SERVICE_ACTION_OUT_16, sg_lib_serv_out16_arr, NULL},
    {SG_SERVICE_ACTION_BIDI, sg_lib_serv_bidi_arr, NULL},
    {SG_PERSISTENT_RESERVE_IN, sg_lib_pr_in_arr, "Persistent reserve in"},
    {SG_PERSISTENT_RESERVE_OUT, sg_lib_pr_out_arr, "Persistent reserve out"},
    {SG_3PARTY_COPY_OUT, sg_lib_xcopy_sa_arr, NULL},
    {SG_3PARTY_COPY_IN, sg_lib_rec_copy_sa_arr, NULL},
    {SG_READ_BUFFER, sg_lib_read_buff_arr, "Read buffer"},
    {SG_READ_ATTRIBUTE, sg_lib_read_attr_arr, "Read attribute"},
    {SG_SANITIZE, sg_lib_sanitize_sa_arr, "Sanitize"},
    {SG_WRITE_BUFFER, sg_lib_write_buff_arr, "Write buffer"},
    {SG_ZONING_IN, sg_lib_zoning_in_arr, NULL},
    {SG_ZONING_OUT, sg_lib_zoning_out_arr, NULL},
    {0xffff, NULL, NULL},
};

void
sg_get_opcode_sa_name(unsigned char cmd_byte0, int service_action,
                      int peri_type, int buff_len, char * buff)
{
    const struct sg_lib_value_name_t * vnp;
    const struct op_code2sa_t * osp;
    char b[80];

    if ((NULL == buff) || (buff_len < 1))
        return;
    else if (1 == buff_len) {
        buff[0] = '\0';
        return;
    }

    for (osp = op_code2sa_arr; osp->arr; ++osp) {
        if ((int)cmd_byte0 == osp->op_code) {
            vnp = get_value_name(osp->arr, service_action, peri_type);
            if (vnp) {
                if (osp->prefix)
                    my_snprintf(buff, buff_len, "%s, %s", osp->prefix,
                                vnp->name);
                else
                    my_snprintf(buff, buff_len, "%s", vnp->name);
            } else {
                sg_get_opcode_name(cmd_byte0, peri_type, sizeof(b), b);
                my_snprintf(buff, buff_len, "%s service action=0x%x",
                            b, service_action);
            }
            return;
        }
    }

    sg_get_opcode_name(cmd_byte0, peri_type, buff_len, buff);
}

void
sg_get_opcode_name(unsigned char cmd_byte0, int peri_type, int buff_len,
                   char * buff)
{
    const struct sg_lib_value_name_t * vnp;
    int grp;

    if ((NULL == buff) || (buff_len < 1))
        return;
    else if (1 == buff_len) {
        buff[0] = '\0';
        return;
    }
    if (SG_VARIABLE_LENGTH_CMD == cmd_byte0) {
        my_snprintf(buff, buff_len, "%s", "Variable length");
        return;
    }
    grp = (cmd_byte0 >> 5) & 0x7;
    switch (grp) {
    case 0:
    case 1:
    case 2:
    case 4:
    case 5:
        vnp = get_value_name(sg_lib_normal_opcodes, cmd_byte0, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Opcode=0x%x", (int)cmd_byte0);
        break;
    case 3:
        my_snprintf(buff, buff_len, "Reserved [0x%x]", (int)cmd_byte0);
        break;
    case 6:
    case 7:
        my_snprintf(buff, buff_len, "Vendor specific [0x%x]", (int)cmd_byte0);
        break;
    default:
        my_snprintf(buff, buff_len, "Opcode=0x%x", (int)cmd_byte0);
        break;
    }
}

/* Iterates to next designation descriptor in the device identification
 * VPD page. The 'initial_desig_desc' should point to start of first
 * descriptor with 'page_len' being the number of valid bytes in that
 * and following descriptors. To start, 'off' should point to a negative
 * value, thereafter it should point to the value yielded by the previous
 * call. If 0 returned then 'initial_desig_desc + *off' should be a valid
 * descriptor; returns -1 if normal end condition and -2 for an abnormal
 * termination. Matches association, designator_type and/or code_set when
 * any of those values are greater than or equal to zero. */
int
sg_vpd_dev_id_iter(const unsigned char * initial_desig_desc, int page_len,
                   int * off, int m_assoc, int m_desig_type, int m_code_set)
{
    const unsigned char * ucp;
    int k, c_set, assoc, desig_type;

    for (k = *off, ucp = initial_desig_desc ; (k + 3) < page_len; ) {
        k = (k < 0) ? 0 : (k + ucp[k + 3] + 4);
        if ((k + 4) > page_len)
            break;
        c_set = (ucp[k] & 0xf);
        if ((m_code_set >= 0) && (m_code_set != c_set))
            continue;
        assoc = ((ucp[k + 1] >> 4) & 0x3);
        if ((m_assoc >= 0) && (m_assoc != assoc))
            continue;
        desig_type = (ucp[k + 1] & 0xf);
        if ((m_desig_type >= 0) && (m_desig_type != desig_type))
            continue;
        *off = k;
        return 0;
    }
    return (k == page_len) ? -1 : -2;
}

static const char * bad_sense_cat = "Bad sense category";

/* Yield string associated with sense++ category. Returns 'buff' (or pointer
 * to "Bad sense category" if 'buff' is NULL). If sense_cat unknown then
 * yield "Sense category: <sense_cat>" string. */
const char *
sg_get_category_sense_str(int sense_cat, int buff_len, char * buff,
                          int verbose)
{
    int n;

    if (NULL == buff)
        return bad_sense_cat;
    if (buff_len <= 0)
        return buff;
    switch (sense_cat) {
    case SG_LIB_CAT_CLEAN:              /* 0 */
        snprintf(buff, buff_len, "No errors");
        break;
    case SG_LIB_SYNTAX_ERROR:           /* 1 */
        snprintf(buff, buff_len, "Syntax error");
        break;
    case SG_LIB_CAT_NOT_READY:          /* 2 */
        n = snprintf(buff, buff_len, "Not ready");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key");
        break;
    case SG_LIB_CAT_MEDIUM_HARD:        /* 3 */
        n = snprintf(buff, buff_len, "Medium or hardware error");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key (plus blank check)");
        break;
    case SG_LIB_CAT_ILLEGAL_REQ:        /* 5 */
        n = snprintf(buff, buff_len, "Illegal request");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key, apart from Invalid "
                     "opcode");
        break;
    case SG_LIB_CAT_UNIT_ATTENTION:     /* 6 */
        n = snprintf(buff, buff_len, "Unit attention");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key");
        break;
    case SG_LIB_CAT_DATA_PROTECT:       /* 7 */
        n = snprintf(buff, buff_len, "Data protect");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key, write protected "
                     "media?");
        break;
    case SG_LIB_CAT_INVALID_OP:         /* 9 */
        n = snprintf(buff, buff_len, "Illegal request, invalid opcode");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key");
        break;
    case SG_LIB_CAT_COPY_ABORTED:       /* 10 */
        n = snprintf(buff, buff_len, "Copy aborted");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key");
        break;
    case SG_LIB_CAT_ABORTED_COMMAND:    /* 11 */
        n = snprintf(buff, buff_len, "Aborted command");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key, other than "
                     "protection related (asc=0x10)");
        break;
    case SG_LIB_CAT_MISCOMPARE:         /* 14 */
        n = snprintf(buff, buff_len, "Miscompare");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key");
        break;
    case SG_LIB_FILE_ERROR:             /* 15 */
        snprintf(buff, buff_len, "File error");
        break;
    case SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO:  /* 17 */
        snprintf(buff, buff_len, "Illegal request with info");
        break;
    case SG_LIB_CAT_MEDIUM_HARD_WITH_INFO:  /* 18 */
        snprintf(buff, buff_len, "Medium or hardware error with info");
        break;
    case SG_LIB_CAT_NO_SENSE:           /* 20 */
        n = snprintf(buff, buff_len, "No sense key");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " probably additional sense "
                     "information");
        break;
    case SG_LIB_CAT_RECOVERED:          /* 21 */
        n = snprintf(buff, buff_len, "Recovered error");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " sense key");
        break;
    case SG_LIB_CAT_RES_CONFLICT:       /* 24 */
        n = snprintf(buff, buff_len, "Reservation conflict");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " SCSI status");
        break;
    case SG_LIB_CAT_CONDITION_MET:      /* 25 */
        n = snprintf(buff, buff_len, "Condition met");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " SCSI status");
        break;
    case SG_LIB_CAT_BUSY:               /* 26 */
        n = snprintf(buff, buff_len, "Busy");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " SCSI status");
        break;
    case SG_LIB_CAT_TS_FULL:            /* 27 */
        n = snprintf(buff, buff_len, "Task set full");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " SCSI status");
        break;
    case SG_LIB_CAT_ACA_ACTIVE:         /* 28 */
        n = snprintf(buff, buff_len, "ACA active");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " SCSI status");
        break;
    case SG_LIB_CAT_TASK_ABORTED:       /* 29 */
        n = snprintf(buff, buff_len, "Task aborted");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " SCSI status");
        break;
    case SG_LIB_CAT_TIMEOUT:            /* 33 */
        snprintf(buff, buff_len, "SCSI command timeout");
        break;
    case SG_LIB_CAT_PROTECTION:         /* 40 */
        n = snprintf(buff, buff_len, "Aborted command, protection");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " information (PI) problem");
        break;
    case SG_LIB_CAT_PROTECTION_WITH_INFO: /* 41 */
        n = snprintf(buff, buff_len, "Aborted command with info, protection");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " information (PI) problem");
        break;
    case SG_LIB_CAT_MALFORMED:          /* 97 */
        n = snprintf(buff, buff_len, "Malformed response");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, " to SCSI command");
        break;
    case SG_LIB_CAT_SENSE:              /* 98 */
        n = snprintf(buff, buff_len, "Some other sense data problem");
        if (verbose && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, ", try '-v' option for more "
                     "information");
        break;
    case SG_LIB_CAT_OTHER:              /* 99 */
        n = snprintf(buff, buff_len, "Some other error/warning has occurred");
        if ((0 == verbose) && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, ", possible transport of driver "
                     "issue");
        break;
    default:
        n = snprintf(buff, buff_len, "Sense category: %d", sense_cat);
        if ((0 == verbose) && (n < (buff_len - 1)))
            snprintf(buff + n, buff_len - n, ", try '-v' option for more "
                     "information");
        break;
    }
    return buff;
}

/* safe_strerror() contributed by Clayton Weaver <cgweav at email dot com>
 * Allows for situation in which strerror() is given a wild value (or the
 * C library is incomplete) and returns NULL. Still not thread safe.
 */

static char safe_errbuf[64] = {'u', 'n', 'k', 'n', 'o', 'w', 'n', ' ',
                               'e', 'r', 'r', 'n', 'o', ':', ' ', 0};

char *
safe_strerror(int errnum)
{
    size_t len;
    char * errstr;

    if (errnum < 0)
        errnum = -errnum;
    errstr = strerror(errnum);
    if (NULL == errstr) {
        len = strlen(safe_errbuf);
        my_snprintf(safe_errbuf + len, sizeof(safe_errbuf) - len, "%i",
                    errnum);
        return safe_errbuf;
    }
    return errstr;
}

static void
trimTrailingSpaces(char * b)
{
    int k;

    for (k = ((int)strlen(b) - 1); k >= 0; --k) {
        if (' ' != b[k])
            break;
    }
    if ('\0' != b[k + 1])
        b[k + 1] = '\0';
}

/* Note the ASCII-hex output goes to stdout. [Most other output from functions
 * in this file go to sg_warnings_strm (default stderr).]
 * 'no_ascii' allows for 3 output types:
 *     > 0     each line has address then up to 16 ASCII-hex bytes
 *     = 0     in addition, the bytes are listed in ASCII to the right
 *     < 0     only the ASCII-hex bytes are listed (i.e. without address) */
static void
dStrHexFp(const char* str, int len, int no_ascii, FILE * fp)
{
    const char * p = str;
    const char * formatstr;
    unsigned char c;
    char buff[82];
    int a = 0;
    int bpstart = 5;
    const int cpstart = 60;
    int cpos = cpstart;
    int bpos = bpstart;
    int i, k, blen;

    if (len <= 0)
        return;
    blen = (int)sizeof(buff);
    if (0 == no_ascii)  /* address at left and ASCII at right */
        formatstr = "%.76s\n";
    else if (no_ascii > 0)
        formatstr = "%s\n";     /* was: "%.58s\n" */
    else /* negative: no address at left and no ASCII at right */
        formatstr = "%s\n";     /* was: "%.48s\n"; */
    memset(buff, ' ', 80);
    buff[80] = '\0';
    if (no_ascii < 0) {
        bpstart = 0;
        bpos = bpstart;
        for (k = 0; k < len; k++) {
            c = *p++;
            if (bpos == (bpstart + (8 * 3)))
                bpos++;
            my_snprintf(&buff[bpos], blen - bpos, "%.2x",
                        (int)(unsigned char)c);
            buff[bpos + 2] = ' ';
            if ((k > 0) && (0 == ((k + 1) % 16))) {
                trimTrailingSpaces(buff);
                fprintf(fp, formatstr, buff);
                bpos = bpstart;
                memset(buff, ' ', 80);
            } else
                bpos += 3;
        }
        if (bpos > bpstart) {
            buff[bpos + 2] = '\0';
            trimTrailingSpaces(buff);
            fprintf(fp, "%s\n", buff);
        }
        return;
    }
    /* no_ascii>=0, start each line with address (offset) */
    k = my_snprintf(buff + 1, blen - 1, "%.2x", a);
    buff[k + 1] = ' ';

    for (i = 0; i < len; i++) {
        c = *p++;
        bpos += 3;
        if (bpos == (bpstart + (9 * 3)))
            bpos++;
        my_snprintf(&buff[bpos], blen - bpos, "%.2x", (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
        if (no_ascii)
            buff[cpos++] = ' ';
        else {
            if ((c < ' ') || (c >= 0x7f))
                c = '.';
            buff[cpos++] = c;
        }
        if (cpos > (cpstart + 15)) {
            if (no_ascii)
                trimTrailingSpaces(buff);
            fprintf(fp, formatstr, buff);
            bpos = bpstart;
            cpos = cpstart;
            a += 16;
            memset(buff, ' ', 80);
            k = my_snprintf(buff + 1, blen - 1, "%.2x", a);
            buff[k + 1] = ' ';
        }
    }
    if (cpos > cpstart) {
        buff[cpos] = '\0';
        if (no_ascii)
            trimTrailingSpaces(buff);
        fprintf(fp, "%s\n", buff);
    }
}

void
dStrHex(const char* str, int len, int no_ascii)
{
    dStrHexFp(str, len, no_ascii, stdout);
}

void
dStrHexErr(const char* str, int len, int no_ascii)
{
    dStrHexFp(str, len, no_ascii,
              (sg_warnings_strm ? sg_warnings_strm : stderr));
}

/* Read 'len' bytes from 'str' and output as ASCII-Hex bytes (space
 * separated) to 'b' not to exceed 'b_len' characters. Each line
 * starts with 'leadin' (NULL for no leadin) and there are 16 bytes
 * per line with an extra space between the 8th and 9th bytes. 'format'
 * is unused (currently), set to 0 . Returns number of bytes written
 * to 'b' excluding the trailing '\0'. */
int
dStrHexStr(const char* str, int len, const char * leadin, int format,
           int b_len, char * b)
{
    const char * p = str;
    unsigned char c;
    char buff[122];
    int bpstart, bpos, k, n;

    if (len <= 0) {
        if (b_len > 0)
            b[0] = '\0';
        return 0;
    }
    if (0 != format) {
        ;       /* do nothing different for now */
    }
    if (leadin) {
        bpstart = strlen(leadin);
        /* Cap leadin at 60 characters */
        if (bpstart > 60)
            bpstart = 60;
    } else
        bpstart = 0;
    bpos = bpstart;
    n = 0;
    memset(buff, ' ', 120);
    buff[120] = '\0';
    if (bpstart > 0)
        memcpy(buff, leadin, bpstart);
    for (k = 0; k < len; k++) {
        c = *p++;
        if (bpos == (bpstart + (8 * 3)))
            bpos++;
        my_snprintf(&buff[bpos], (int)sizeof(buff) - bpos, "%.2x",
                    (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
        if ((k > 0) && (0 == ((k + 1) % 16))) {
            trimTrailingSpaces(buff);
            n += my_snprintf(b + n, b_len - n, "%s\n", buff);
            if (n >= (b_len - 1))
                return n;
            bpos = bpstart;
            memset(buff, ' ', 120);
            if (bpstart > 0)
                memcpy(buff, leadin, bpstart);
        } else
            bpos += 3;
    }
    if (bpos > bpstart) {
        trimTrailingSpaces(buff);
        n += my_snprintf(b + n, b_len - n, "%s\n", buff);
    }
    return n;
}

/* Returns 1 when executed on big endian machine; else returns 0.
 * Useful for displaying ATA identify words (which need swapping on a
 * big endian machine). */
int
sg_is_big_endian()
{
    union u_t {
        unsigned short s;
        unsigned char c[sizeof(unsigned short)];
    } u;

    u.s = 0x0102;
    return (u.c[0] == 0x01);     /* The lowest address contains
                                    the most significant byte */
}

static unsigned short
swapb_ushort(unsigned short u)
{
    unsigned short r;

    r = (u >> 8) & 0xff;
    r |= ((u & 0xff) << 8);
    return r;
}

/* Note the ASCII-hex output goes to stdout. [Most other output from functions
 * in this file go to sg_warnings_strm (default stderr).]
 * 'no_ascii' allows for 3 output types:
 *     > 0     each line has address then up to 8 ASCII-hex 16 bit words
 *     = 0     in addition, the ASCI bytes pairs are listed to the right
 *     = -1    only the ASCII-hex words are listed (i.e. without address)
 *     = -2    only the ASCII-hex words, formatted for "hdparm --Istdin"
 *     < -2    same as -1
 * If 'swapb' non-zero then bytes in each word swapped. Needs to be set
 * for ATA IDENTIFY DEVICE response on big-endian machines. */
void
dWordHex(const unsigned short* words, int num, int no_ascii, int swapb)
{
    const unsigned short * p = words;
    unsigned short c;
    char buff[82];
    unsigned char upp, low;
    int a = 0;
    const int bpstart = 3;
    const int cpstart = 52;
    int cpos = cpstart;
    int bpos = bpstart;
    int i, k, blen;

    if (num <= 0)
        return;
    blen = (int)sizeof(buff);
    memset(buff, ' ', 80);
    buff[80] = '\0';
    if (no_ascii < 0) {
        for (k = 0; k < num; k++) {
            c = *p++;
            if (swapb)
                c = swapb_ushort(c);
            bpos += 5;
            my_snprintf(&buff[bpos], blen - bpos, "%.4x", (unsigned int)c);
            buff[bpos + 4] = ' ';
            if ((k > 0) && (0 == ((k + 1) % 8))) {
                if (-2 == no_ascii)
                    printf("%.39s\n", buff +8);
                else
                    printf("%.47s\n", buff);
                bpos = bpstart;
                memset(buff, ' ', 80);
            }
        }
        if (bpos > bpstart) {
            if (-2 == no_ascii)
                printf("%.39s\n", buff +8);
            else
                printf("%.47s\n", buff);
        }
        return;
    }
    /* no_ascii>=0, start each line with address (offset) */
    k = my_snprintf(buff + 1, blen - 1, "%.2x", a);
    buff[k + 1] = ' ';

    for (i = 0; i < num; i++) {
        c = *p++;
        if (swapb)
            c = swapb_ushort(c);
        bpos += 5;
        my_snprintf(&buff[bpos], blen - bpos, "%.4x", (unsigned int)c);
        buff[bpos + 4] = ' ';
        if (no_ascii) {
            buff[cpos++] = ' ';
            buff[cpos++] = ' ';
            buff[cpos++] = ' ';
        } else {
            upp = (c >> 8) & 0xff;
            low = c & 0xff;
            if ((upp < 0x20) || (upp >= 0x7f))
                upp = '.';
            buff[cpos++] = upp;
            if ((low < 0x20) || (low >= 0x7f))
                low = '.';
            buff[cpos++] = low;
            buff[cpos++] = ' ';
        }
        if (cpos > (cpstart + 23)) {
            printf("%.76s\n", buff);
            bpos = bpstart;
            cpos = cpstart;
            a += 8;
            memset(buff, ' ', 80);
            k = my_snprintf(buff + 1, blen - 1, "%.2x", a);
            buff[k + 1] = ' ';
        }
    }
    if (cpos > cpstart)
        printf("%.76s\n", buff);
}

/* If the number in 'buf' can be decoded or the multiplier is unknown
 * then -1 is returned. Accepts a hex prefix (0x or 0X) or a decimal
 * multiplier suffix (as per GNU's dd (since 2002: SI and IEC 60027-2)).
 * Main (SI) multipliers supported: K, M, G. Ignore leading spaces and
 * tabs; accept comma, space, tab and hash as terminator. */
int
sg_get_num(const char * buf)
{
    int res, num, n, len;
    unsigned int unum;
    char * cp;
    const char * b;
    char c = 'c';
    char c2, c3;
    char lb[16];

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    len = strlen(buf);
    n = strspn(buf, " \t");
    if (n > 0) {
        if (n == len)
            return -1;
        buf += n;
        len -=n;
    }
    /* following hack to keep C++ happy */
    cp = strpbrk((char *)buf, " \t,#");
    if (cp) {
        len = cp - buf;
        n = (int)sizeof(lb) - 1;
        len = (len < n) ? len : n;
        memcpy(lb, buf, len);
        lb[len] = '\0';
        b = lb;
    } else
        b = buf;
    if (('0' == b[0]) && (('x' == b[1]) || ('X' == b[1]))) {
        res = sscanf(b + 2, "%x", &unum);
        num = unum;
    } else if ('H' == toupper((int)b[len - 1])) {
        res = sscanf(b, "%x", &unum);
        num = unum;
    } else
        res = sscanf(b, "%d%c%c%c", &num, &c, &c2, &c3);
    if (res < 1)
        return -1LL;
    else if (1 == res)
        return num;
    else {
        if (res > 2)
            c2 = toupper((int)c2);
        if (res > 3)
            c3 = toupper((int)c3);
        switch (toupper((int)c)) {
        case 'C':
            return num;
        case 'W':
            return num * 2;
        case 'B':
            return num * 512;
        case 'K':
            if (2 == res)
                return num * 1024;
            if (('B' == c2) || ('D' == c2))
                return num * 1000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1024;
            return -1;
        case 'M':
            if (2 == res)
                return num * 1048576;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1048576;
            return -1;
        case 'G':
            if (2 == res)
                return num * 1073741824;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1073741824;
            return -1;
        case 'X':
            cp = (char *)strchr(b, 'x');
            if (NULL == cp)
                cp = (char *)strchr(b, 'X');
            if (cp) {
                n = sg_get_num(cp + 1);
                if (-1 != n)
                    return num * n;
            }
            return -1;
        default:
            pr2ws("unrecognized multiplier\n");
            return -1;
        }
    }
}

/* If the number in 'buf' can not be decoded then -1 is returned. Accepts a
 * hex prefix (0x or 0X) or a 'h' (or 'H') suffix; otherwise decimal is
 * assumed. Does not accept multipliers. Accept a comma (","), a whitespace
 * or newline as terminator. */
int
sg_get_num_nomult(const char * buf)
{
    int res, len, num;
    unsigned int unum;
    char * commap;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    len = strlen(buf);
    commap = (char *)strchr(buf + 1, ',');
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1]))) {
        res = sscanf(buf + 2, "%x", &unum);
        num = unum;
    } else if (commap && ('H' == toupper((int)*(commap - 1)))) {
        res = sscanf(buf, "%x", &unum);
        num = unum;
    } else if ((NULL == commap) && ('H' == toupper((int)buf[len - 1]))) {
        res = sscanf(buf, "%x", &unum);
        num = unum;
    } else
        res = sscanf(buf, "%d", &num);
    if (1 == res)
        return num;
    else
        return -1;
}

/* If the number in 'buf' can be decoded or the multiplier is unknown
 * then -1LL is returned. Accepts a hex prefix (0x or 0X) or a decimal
 * multiplier suffix (as per GNU's dd (since 2002: SI and IEC 60027-2)).
 * Main (SI) multipliers supported: K, M, G, T, P. Ignore leading spaces
 * and tabs; accept comma, space, tab and hash as terminator. */
int64_t
sg_get_llnum(const char * buf)
{
    int res, len, n;
    int64_t num, ll;
    uint64_t unum;
    char * cp;
    const char * b;
    char c = 'c';
    char c2, c3;
    char lb[32];

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1LL;
    len = strlen(buf);
    n = strspn(buf, " \t");
    if (n > 0) {
        if (n == len)
            return -1LL;
        buf += n;
        len -=n;
    }
    /* following hack to keep C++ happy */
    cp = strpbrk((char *)buf, " \t,#");
    if (cp) {
        len = cp - buf;
        n = (int)sizeof(lb) - 1;
        len = (len < n) ? len : n;
        memcpy(lb, buf, len);
        lb[len] = '\0';
        b = lb;
    } else
        b = buf;
    if (('0' == b[0]) && (('x' == b[1]) || ('X' == b[1]))) {
        res = sscanf(b + 2, "%" SCNx64 "", &unum);
        num = unum;
    } else if ('H' == toupper((int)b[len - 1])) {
        res = sscanf(b, "%" SCNx64 "", &unum);
        num = unum;
    } else
        res = sscanf(b, "%" SCNd64 "%c%c%c", &num, &c, &c2, &c3);
    if (res < 1)
        return -1LL;
    else if (1 == res)
        return num;
    else {
        if (res > 2)
            c2 = toupper((int)c2);
        if (res > 3)
            c3 = toupper((int)c3);
        switch (toupper((int)c)) {
        case 'C':
            return num;
        case 'W':
            return num * 2;
        case 'B':
            return num * 512;
        case 'K':
            if (2 == res)
                return num * 1024;
            if (('B' == c2) || ('D' == c2))
                return num * 1000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1024;
            return -1LL;
        case 'M':
            if (2 == res)
                return num * 1048576;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1048576;
            return -1LL;
        case 'G':
            if (2 == res)
                return num * 1073741824;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1073741824;
            return -1LL;
        case 'T':
            if (2 == res)
                return num * 1099511627776LL;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000000LL;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1099511627776LL;
            return -1LL;
        case 'P':
            if (2 == res)
                return num * 1099511627776LL * 1024;
            if (('B' == c2) || ('D' == c2))
                return num * 1000000000000LL * 1000;
            if (('I' == c2) && (4 == res) && ('B' == c3))
                return num * 1099511627776LL * 1024;
            return -1LL;
        case 'X':
            cp = (char *)strchr(b, 'x');
            if (NULL == cp)
                cp = (char *)strchr(b, 'X');
            if (cp) {
                ll = sg_get_llnum(cp + 1);
                if (-1LL != ll)
                    return num * ll;
            }
            return -1LL;
        default:
            pr2ws("unrecognized multiplier\n");
            return -1LL;
        }
    }
}

/* Extract character sequence from ATA words as in the model string
 * in a IDENTIFY DEVICE response. Returns number of characters
 * written to 'ochars' before 0 character is found or 'num' words
 * are processed. */
int
sg_ata_get_chars(const unsigned short * word_arr, int start_word,
                 int num_words, int is_big_endian, char * ochars)
{
    int k;
    unsigned short s;
    char a, b;
    char * op = ochars;

    for (k = start_word; k < (start_word + num_words); ++k) {
        s = word_arr[k];
        if (is_big_endian) {
            a = s & 0xff;
            b = (s >> 8) & 0xff;
        } else {
            a = (s >> 8) & 0xff;
            b = s & 0xff;
        }
        if (a == 0)
            break;
        *op++ = a;
        if (b == 0)
            break;
        *op++ = b;
    }
    return op - ochars;
}

const char *
sg_lib_version()
{
    return sg_lib_version_str;
}


#ifdef SG_LIB_MINGW
/* Non Unix OSes distinguish between text and binary files.
   Set text mode on fd. Does nothing in Unix. Returns negative number on
   failure. */

#include <unistd.h>
#include <fcntl.h>

int
sg_set_text_mode(int fd)
{
    return setmode(fd, O_TEXT);
}

/* Set binary mode on fd. Does nothing in Unix. Returns negative number on
   failure. */
int
sg_set_binary_mode(int fd)
{
    return setmode(fd, O_BINARY);
}

#else
/* For Unix the following functions are dummies. */
int
sg_set_text_mode(int fd)
{
    return fd;  /* fd should be >= 0 */
}

int
sg_set_binary_mode(int fd)
{
    return fd;
}

#endif

int
pr2serr(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

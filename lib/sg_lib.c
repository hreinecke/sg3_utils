/*
 * Copyright (c) 1999-2013 Douglas Gilbert.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* sg_lib_version_str (and datestamp) defined in sg_lib_data.c file */

#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d  /* corresponding ASC is 0 */

FILE * sg_warnings_strm = NULL;        /* would like to default to stderr */


static void dStrHexErr(const char* str, int len, int b_len, char * b);


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

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    fprintf(sg_warnings_strm, "%s [", buff);
    if (SG_VARIABLE_LENGTH_CMD == command[0])
        sz = command[7] + 8;
    else
        sz = sg_get_command_size(command[0]);
    for (k = 0; k < sz; ++k)
        fprintf(sg_warnings_strm, "%02x ", command[k]);
    fprintf(sg_warnings_strm, "]\n");
}

void
sg_get_scsi_status_str(int scsi_status, int buff_len, char * buff)
{
    const char * ccp;

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
        case 0x14: ccp = "Intermediate-Condition Met (obs)"; break;
        case 0x18: ccp = "Reservation Conflict"; break;
        case 0x22: ccp = "Command Terminated (obsolete)"; break;
        case 0x28: ccp = "Task set Full"; break;
        case 0x30: ccp = "ACA Active"; break;
        case 0x40: ccp = "Task Aborted"; break;
        default: ccp = "Unknown status"; break;
    }
    my_snprintf(buff, buff_len, "%s", ccp);
}

void
sg_print_scsi_status(int scsi_status)
{
    char buff[128];

    sg_get_scsi_status_str(scsi_status, sizeof(buff) - 1, buff);
    buff[sizeof(buff) - 1] = '\0';
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    fprintf(sg_warnings_strm, "%s ", buff);
}


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

int
sg_get_sense_info_fld(const unsigned char * sensep, int sb_len,
                      uint64_t * info_outp)
{
    int j;
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
            *info_outp = ((unsigned int)sensep[3] << 24) + (sensep[4] << 16) +
                         (sensep[5] << 8) + sensep[6];
        return (sensep[0] & 0x80) ? 1 : 0;
    case 0x72:
    case 0x73:
        ucp = sg_scsi_sense_desc_find(sensep, sb_len, 0 /* info desc */);
        if (ucp && (0xa == ucp[1])) {
            ull = 0;
            for (j = 0; j < 8; ++j) {
                if (j > 0)
                    ull <<= 8;
                ull |= ucp[4 + j];
            }
            if (info_outp)
                *info_outp = ull;
            return !!(ucp[2] & 0x80);   /* since spc3r23 should be set */
        } else
            return 0;
    default:
        return 0;
    }
}

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
 * field is not available returns 0. Handles both fixed and descriptor
 * sense formats. N.B. App should multiply by 100 and divide by 65536
 * to get percentage completion from given value. */
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
                *progress_outp = (sensep[16] << 8) + sensep[17];
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
                *progress_outp = (ucp[5] << 8) + ucp[6];
            return 1;
        } else if (((ucp = sg_scsi_sense_desc_find(sensep, sb_len, 0xa))) &&
                   ((0x6 == ucp[1]))) {
            if (progress_outp)
                *progress_outp = (ucp[6] << 8) + ucp[7];
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

char *
sg_get_trans_proto_str(int tpi, int buff_len, char * buff)
{
    if ((tpi < 0) || (tpi > 15))
        my_snprintf(buff, buff_len, "bad tpi");
    else
        my_snprintf(buff, buff_len, "%s", sg_lib_transport_proto_strs[tpi]);
    return buff;
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
                            int alen)
{
    int n = 0;
    int dlen = alen - 2;
    int k, j, g, f, tpgd;
    const unsigned char * tp;
    uint64_t ull;
    char c[40];

    n += my_snprintf(b + n, blen - n, "   Not all referrals: %d\n",
                     !!(dp[2] & 0x1));
    dp += 4;
    for (k = 0, f = 1; (k + 4) < dlen; k += g, dp += g, ++f) {
        tpgd = dp[3];
        g = (tpgd * 4) + 20;
        n += my_snprintf(b + n, blen - n, "    Descriptor %d\n", f);
        if ((k + g) > dlen) {
            n += my_snprintf(b + n, blen - n, "      truncated descriptor, "
                             "stop\n");
            return n;
        }
        ull = 0;
        for (j = 0; j < 8; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= dp[4 + j];
        }
        n += my_snprintf(b + n, blen - n, "      first uds LBA: 0x%"PRIx64
                         "\n", ull);
        ull = 0;
        for (j = 0; j < 8; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= dp[12 + j];
        }
        n += my_snprintf(b + n, blen - n, "      last uds LBA:  0x%"PRIx64
                         "\n", ull);
        for (j = 0; j < tpgd; ++j) {
            tp = dp + 20 + (j * 4);
            decode_tpgs_state(tp[0] & 0xf, c, sizeof(c));
            n += my_snprintf(b + n, blen - n, "        tpg: %d  state: %s\n",
                             (tp[2] << 8) + tp[3], c);
        }
    }
    return n;
}

static const char * sdata_src[] = {
    "unknown",
    "Extended Copy command source device",
    "Extended Copy command destination device",
    };


/* Decode descriptor format sense descriptors (assumes sense buffer is
   in descriptor format) */
static void
sg_get_sense_descriptors_str(const unsigned char * sense_buffer, int sb_len,
                             int blen, char * b)
{
    int add_sb_len, add_d_len, desc_len, k, j, sense_key, processed;
    int n, progress, pr, rem;
    const unsigned char * descp;
    const char * dtsp = "   >> descriptor too short";

    if ((NULL == b) || (blen <= 0))
        return;
    b[0] = '\0';
    if ((sb_len < 8) || (0 == (add_sb_len = sense_buffer[7])))
        return;
    add_sb_len = (add_sb_len < (sb_len - 8)) ? add_sb_len : (sb_len - 8);
    sense_key = (sense_buffer[1] & 0xf);

    for (descp = (sense_buffer + 8), k = 0, n = 0;
         (k < add_sb_len) && (n < blen);
         k += desc_len, descp += desc_len) {
        add_d_len = (k < (add_sb_len - 1)) ? descp[1] : -1;
        if ((k + add_d_len + 2) > add_sb_len)
            add_d_len = add_sb_len - k - 2;
        desc_len = add_d_len + 2;
        n += my_snprintf(b + n, blen - n, "  Descriptor type: ");
        processed = 1;
        switch (descp[0]) {
        case 0:
            n += my_snprintf(b + n, blen - n, "Information\n");
            if ((add_d_len >= 10) && (0x80 & descp[2])) {
                n += my_snprintf(b + n, blen - n, "    0x");
                for (j = 0; j < 8; ++j)
                    n += my_snprintf(b + n, blen - n, "%02x", descp[4 + j]);
                n += my_snprintf(b + n, blen - n, "\n");
            } else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 1:
            n += my_snprintf(b + n, blen - n, "Command specific\n");
            if (add_d_len >= 10) {
                n += my_snprintf(b + n, blen - n, "    0x");
                for (j = 0; j < 8; ++j)
                    n += my_snprintf(b + n, blen - n, "%02x", descp[4 + j]);
                n += my_snprintf(b + n, blen - n, "\n");
            } else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 2:
            n += my_snprintf(b + n, blen - n, "Sense key specific:");
            switch (sense_key) {
            case SPC_SK_ILLEGAL_REQUEST:
                n += my_snprintf(b + n, blen - n, " Field pointer\n");
                if (add_d_len < 6) {
                    n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                    processed = 0;
                    break;
                }
                n += my_snprintf(b + n, blen - n, "    Error in %s byte %d",
                                 (descp[4] & 0x40) ? "Command" : "Data",
                                 (descp[5] << 8) | descp[6]);
                if (descp[4] & 0x08) {
                    n += my_snprintf(b + n, blen - n, " bit %d\n",
                                     descp[4] & 0x07);
                } else
                    n += my_snprintf(b + n, blen - n, "\n");
                break;
            case SPC_SK_HARDWARE_ERROR:
            case SPC_SK_MEDIUM_ERROR:
            case SPC_SK_RECOVERED_ERROR:
                n += my_snprintf(b + n, blen - n, " Actual retry count\n");
                if (add_d_len < 6) {
                    n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                    processed = 0;
                    break;
                }
                n += my_snprintf(b + n, blen - n,"    0x%02x%02x\n", descp[5],
                                 descp[6]);
                break;
            case SPC_SK_NO_SENSE:
            case SPC_SK_NOT_READY:
                n += my_snprintf(b + n, blen - n, " Progress indication: ");
                if (add_d_len < 6) {
                    n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                    processed = 0;
                    break;
                }
                progress = (descp[5] << 8) + descp[6];
                pr = (progress * 100) / 65536;
                rem = ((progress * 100) % 65536) / 655;
                n += my_snprintf(b + n, blen - n, "%d.%02d%%\n", pr, rem);
                break;
            case SPC_SK_COPY_ABORTED:
                n += my_snprintf(b + n, blen - n, " Segment pointer\n");
                if (add_d_len < 6) {
                    n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                    processed = 0;
                    break;
                }
                n += my_snprintf(b + n, blen - n, " Relative to start of %s, "
                                 "byte %d",
                                 (descp[4] & 0x20) ? "segment descriptor" :
                                                     "parameter list",
                                 (descp[5] << 8) | descp[6]);
                if (descp[4] & 0x08)
                    n += my_snprintf(b + n, blen - n, " bit %d\n",
                                     descp[4] & 0x07);
                else
                    n += my_snprintf(b + n, blen - n, "\n");
                break;
            case SPC_SK_UNIT_ATTENTION:
                n += my_snprintf(b + n, blen - n, " Unit attention condition "
                                 "queue: ");
                n += my_snprintf(b + n, blen - n, "overflow flag is %d\n",
                             !!(descp[4] & 0x1));
                break;
            default:
                n += my_snprintf(b + n, blen - n, " Sense_key: 0x%x "
                                 "unexpected\n", sense_key);
                processed = 0;
                break;
            }
            break;
        case 3:
            n += my_snprintf(b + n, blen - n, "Field replaceable unit\n");
            if (add_d_len >= 2)
                n += my_snprintf(b + n, blen - n, "    code=0x%x\n",
                                 descp[3]);
            else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 4:
            n += my_snprintf(b + n, blen - n, "Stream commands\n");
            if (add_d_len >= 2) {
                if (descp[3] & 0x80)
                    n += my_snprintf(b + n, blen - n, "    FILEMARK");
                if (descp[3] & 0x40)
                    n += my_snprintf(b + n, blen - n, "    End Of Medium "
                                     "(EOM)");
                if (descp[3] & 0x20)
                    n += my_snprintf(b + n, blen - n, "    Incorrect Length "
                                     "Indicator (ILI)");
                n += my_snprintf(b + n, blen - n, "\n");
            } else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 5:
            n += my_snprintf(b + n, blen - n, "Block commands\n");
            if (add_d_len >= 2)
                n += my_snprintf(b + n, blen - n, "    Incorrect Length "
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
        case 9:         /* this is defined in SAT (and SAT-2) */
            n += my_snprintf(b + n, blen - n, "ATA Status Return\n");
            if (add_d_len >= 12) {
                int extend, sector_count;

                extend = descp[2] & 1;
                sector_count = descp[5] + (extend ? (descp[4] << 8) : 0);
                n += my_snprintf(b + n, blen - n, "    extend=%d  error=0x%x "
                                 " sector_count=0x%x\n", extend, descp[3],
                                 sector_count);
                if (extend)
                    n += my_snprintf(b + n, blen - n, "    "
                                     "lba=0x%02x%02x%02x%02x%02x%02x\n",
                                     descp[10], descp[8], descp[6],
                                     descp[11], descp[9], descp[7]);
                else
                    n += my_snprintf(b + n, blen - n, "    "
                                     "lba=0x%02x%02x%02x\n",
                                     descp[11], descp[9], descp[7]);
                n += my_snprintf(b + n, blen - n, "    device=0x%x  "
                                 "status=0x%x\n", descp[12], descp[13]);
            } else {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
            }
            break;
        case 0xa:
           /* Added in SPC-4 rev 17, became 'Another ...' in rev 34 */
            n += my_snprintf(b + n, blen - n, "Another progress "
                             "indication\n");
            if (add_d_len < 6) {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
                break;
            }
            progress = (descp[6] << 8) + descp[7];
            pr = (progress * 100) / 65536;
            rem = ((progress * 100) % 65536) / 655;
            n += my_snprintf(b + n, blen - n, "    %d.02%d%%", pr, rem);
            n += my_snprintf(b + n, blen - n, " [sense_key=0x%x "
                             "asc,ascq=0x%x,0x%x]\n",
                             descp[2], descp[3], descp[4]);
            break;
        case 0xb:       /* Added in SPC-4 rev 23, defined in SBC-3 rev 22 */
            n += my_snprintf(b + n, blen - n, "User data segment referral\n");
            if (add_d_len < 2) {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
                break;
            }
            n += uds_referral_descriptor_str(b + n, blen - n, descp,
                                             add_d_len);
            break;
        case 0xc:       /* Added in SPC-4 rev 28 */
            n += my_snprintf(b + n, blen - n, "Forwarded sense data\n");
            if (add_d_len < 2) {
                n += my_snprintf(b + n, blen - n, "%s\n", dtsp);
                processed = 0;
                break;
            }
            n += my_snprintf(b + n, blen - n, "    FSDT: %s\n",
                             (descp[2] & 0x80) ? "set" : "clear");
            j = descp[2] & 0xf;
            if (j < 3)
                n += my_snprintf(b + n, blen - n, "    Sense data source: "
                                 "%s\n", sdata_src[j]);
            else
                n += my_snprintf(b + n, blen - n, "    Sense data source: "
                                 "reserved [%d]\n", j);
            {
                char c[200];

                sg_get_scsi_status_str(descp[3], sizeof(c) - 1, c);
                c[sizeof(c) - 1] = '\0';
                n += my_snprintf(b + n, blen - n, "    Forwarded status: "
                                 "%s\n", c);
                if (add_d_len > 2) {
                    /* recursing; hope not to get carried away */
                    n += my_snprintf(b + n, blen - n, " vvvvvvvvvvvvvvvv\n");
                    sg_get_sense_str(NULL, descp + 4, add_d_len - 2, 0,
                                     sizeof(c), c);
                    n += my_snprintf(b + n, blen - n, "%s", c);
                    n += my_snprintf(b + n, blen - n, " ^^^^^^^^^^^^^^^^\n");
                }
            }
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
                n += my_snprintf(b + n, blen - n, "    ");
                for (j = 0; j < add_d_len; ++j) {
                    if ((j > 0) && (0 == (j % 24)))
                        n += my_snprintf(b + n, blen - n, "\n    ");
                    n += my_snprintf(b + n, blen - n, "%02x ", descp[j + 2]);
                }
                n += my_snprintf(b + n, blen - n, "\n");
            }
        }
        if (add_d_len < 0)
            n += my_snprintf(b + n, blen - n, "    short descriptor\n");
    }
}

/* Decode SAT ATA PASS-THROUGH fixed format sense */
static void
sg_get_sense_sat_pt_fixed_str(const unsigned char * sp, int slen, int blen,
                              char * b)
{
    int n = 0;

    slen = slen;        /* suppress warning */
    if (blen < 1)
        return;
    if (SPC_SK_RECOVERED_ERROR != (0xf & sp[2]))
        n += my_snprintf(b + n, blen - n, "  >> expected Sense key: "
                         "Recovered Error ??\n");
    n += my_snprintf(b + n, blen - n, "  error=0x%x, status=0x%x, "
                     "device=0x%x, sector_count(7:0)=0x%x%c\n", sp[3], sp[4],
                     sp[5], sp[6], ((0x40 & sp[8]) ? '+' : ' '));
    n += my_snprintf(b + n, blen - n, "  extend=%d, log_index=0x%x, "
                     "lba_high,mid,low(7:0)=0x%x,0x%x,0x%x%c\n",
                     (!!(0x80 & sp[8])), (0xf & sp[8]), sp[9], sp[10], sp[11],
                     ((0x20 & sp[8]) ? '+' : ' '));
}

/* Fetch sense information */
void
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

    if ((NULL == buff) || (buff_len <= 0))
        return;
    else if (1 == buff_len) {
        buff[0] = '\0';
        return;
    }
    blen = sizeof(b);
    n = 0;
    if (sb_len < 1) {
            my_snprintf(buff, buff_len, "sense buffer empty\n");
            return;
    }
    if (leadin)
        n += my_snprintf(buff + n, buff_len - n, "%s: ", leadin);
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
        n += my_snprintf(buff + n, buff_len - n, " %s;  Sense key: %s\n ",
                         ebp, sg_lib_sense_key_desc[ssh.sense_key]);
        if (sdat_ovfl)
            n += my_snprintf(buff + n, buff_len - n, "<<<Sense data "
                             "overflow>>>\n");
        if (descriptor_format) {
            n += my_snprintf(buff + n, buff_len - n, "%s\n",
                             sg_get_asc_ascq_str(ssh.asc, ssh.ascq,
                                                 sizeof(b), b));
            sg_get_sense_descriptors_str(sense_buffer, len, buff_len - n,
                                         buff + n);
            n = strlen(buff);
        } else if ((len > 12) && (0 == ssh.asc) &&
                   (ASCQ_ATA_PT_INFO_AVAILABLE == ssh.ascq)) {
            /* SAT ATA PASS-THROUGH fixed format */
            n += my_snprintf(buff + n, buff_len - n, "%s\n",
                             sg_get_asc_ascq_str(ssh.asc, ssh.ascq,
                             sizeof(b), b));
            sg_get_sense_sat_pt_fixed_str(sense_buffer, len, buff_len - n,
                                          buff + n);
            n = strlen(buff);
        } else if (len > 2) {   /* fixed format */
            if (len > 12)
                n += my_snprintf(buff + n, buff_len - n, "%s\n",
                                 sg_get_asc_ascq_str(ssh.asc, ssh.ascq,
                                                     sizeof(b), b));
            r = 0;
            valid = sense_buffer[0] & 0x80;
            if (len > 6) {
                info = (unsigned int)((sense_buffer[3] << 24) |
                        (sense_buffer[4] << 16) | (sense_buffer[5] << 8) |
                        sense_buffer[6]);
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
                r += my_snprintf(b + r, blen - r, "  Field replaceable unit "
                                 "code: %d\n", sense_buffer[14]);
            if ((len >= 18) && (sense_buffer[15] & 0x80)) {
                /* sense key specific decoding */
                switch (ssh.sense_key) {
                case SPC_SK_ILLEGAL_REQUEST:
                    r += my_snprintf(b + r, blen - r, "  Sense Key Specific: "
                             "Error in %s byte %d",
                             ((sense_buffer[15] & 0x40) ? "Command" : "Data"),
                             (sense_buffer[16] << 8) | sense_buffer[17]);
                    if (sense_buffer[15] & 0x08)
                        r += my_snprintf(b + r, blen - r, " bit %d\n",
                                         sense_buffer[15] & 0x07);
                    else
                        r += my_snprintf(b + r, blen - r, "\n");
                    break;
                case SPC_SK_NO_SENSE:
                case SPC_SK_NOT_READY:
                    progress = (sense_buffer[16] << 8) + sense_buffer[17];
                    pr = (progress * 100) / 65536;
                    rem = ((progress * 100) % 65536) / 655;
                    r += my_snprintf(b + r, blen - r, "  Progress "
                                     "indication: %d.%02d%%\n", pr, rem);
                    break;
                case SPC_SK_HARDWARE_ERROR:
                case SPC_SK_MEDIUM_ERROR:
                case SPC_SK_RECOVERED_ERROR:
                    r += my_snprintf(b + r, blen - r, "  Actual retry count: "
                                     "0x%02x%02x\n", sense_buffer[16],
                                     sense_buffer[17]);
                    break;
                case SPC_SK_COPY_ABORTED:
                    r += my_snprintf(b + r, blen - r, "  Segment pointer: ");
                    r += my_snprintf(b + r, blen - r, "Relative to start of "
                                     "%s, byte %d",
                                     ((sense_buffer[15] & 0x20) ?
                                      "segment descriptor" : "parameter list"),
                                     ((sense_buffer[16] << 8) +
                                      sense_buffer[17]));
                    if (sense_buffer[15] & 0x08)
                        r += my_snprintf(b + r, blen - r, " bit %d\n",
                                         sense_buffer[15] & 0x07);
                    else
                        r += my_snprintf(b + r, blen - r, "\n");
                    break;
                case SPC_SK_UNIT_ATTENTION:
                    r += my_snprintf(b + r, blen - r, "  Unit attention "
                                     "condition queue: ");
                    r += my_snprintf(b + r, blen - r, "overflow flag is %d\n",
                                     !!(sense_buffer[15] & 0x1));
                    break;
                default:
                    r += my_snprintf(b + r, blen - r, "  Sense_key: 0x%x "
                                     "unexpected\n", ssh.sense_key);
                    break;
                }
            }
            if (r > 0)
                n += my_snprintf(buff + n, buff_len - n, "%s", b);
        } else
            n += my_snprintf(buff + n, buff_len - n, " fixed descriptor "
                             "length too short, len=%d\n", len);
    } else {    /* non-extended SCSI-1 sense data ?? */
        if (sb_len < 4) {
            n += my_snprintf(buff + n, buff_len - n, "sense buffer too short "
                             "(4 byte minimum)\n");
            return;
        }
        r = 0;
        r += my_snprintf(b + r, blen - r, "Probably uninitialized data.\n  "
                         "Try to view as SCSI-1 non-extended sense:\n");
        r += my_snprintf(b + r, blen - r, "  AdValid=%d  Error class=%d  "
                         "Error code=%d\n", !!(sense_buffer[0] & 0x80),
                         ((sense_buffer[0] >> 4) & 0x7),
                         (sense_buffer[0] & 0xf));
        if (sense_buffer[0] & 0x80)
            r += my_snprintf(b + r, blen - r, "  lba=0x%x\n",
                             ((sense_buffer[1] & 0x1f) << 16) +
                             (sense_buffer[2] << 8) + sense_buffer[3]);
        n += my_snprintf(buff + n, buff_len - n, "%s\n", b);
        len = sb_len;
        if (len > 32)
            len = 32;   /* trim in case there is a lot of rubbish */
    }
    if (raw_sinfo) {
        n += my_snprintf(buff + n, buff_len - n, " Raw sense data (in hex):"
                         "\n");
        if (n >= (buff_len - 1))
            return;
        dStrHexErr((const char *)sense_buffer, len, buff_len - n, buff + n);
    }
}

/* Print sense information */
void
sg_print_sense(const char * leadin, const unsigned char * sense_buffer,
               int sb_len, int raw_sinfo)
{
    char b[2048];

    sg_get_sense_str(leadin, sense_buffer, sb_len, raw_sinfo, sizeof(b), b);
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    fprintf(sg_warnings_strm, "%s", b);
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
        switch (ssh.sense_key) {
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
            return SG_LIB_CAT_ABORTED_COMMAND;
        default:
            ;   /* drop through (SPC_SK_COMPLETED amongst others) */
        }
    }
    return SG_LIB_CAT_SENSE;
}

/* gives wrong answer for variable length command (opcode=0x7f) */
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
                     ((cmdp[8] << 8) | cmdp[9]) : (cmdp[1] & 0x1f);
    sg_get_opcode_sa_name(cmdp[0], service_action, peri_type, buff_len, buff);
}


void
sg_get_opcode_sa_name(unsigned char cmd_byte0, int service_action,
                      int peri_type, int buff_len, char * buff)
{
    const struct sg_lib_value_name_t * vnp;

    if ((NULL == buff) || (buff_len < 1))
        return;
    else if (1 == buff_len) {
        buff[0] = '\0';
        return;
    }
    switch ((int)cmd_byte0) {
    case SG_VARIABLE_LENGTH_CMD:
        vnp = get_value_name(sg_lib_variable_length_arr, service_action,
                             peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Variable length service action=0x%x",
                        service_action);
        break;
    case SG_MAINTENANCE_IN:
        vnp = get_value_name(sg_lib_maint_in_arr, service_action, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Maintenance in service action=0x%x",
                        service_action);
        break;
    case SG_MAINTENANCE_OUT:
        vnp = get_value_name(sg_lib_maint_out_arr, service_action, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Maintenance out service action=0x%x",
                        service_action);
        break;
    case SG_SERVICE_ACTION_IN_12:
        vnp = get_value_name(sg_lib_serv_in12_arr, service_action, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Service action in(12)=0x%x",
                        service_action);
        break;
    case SG_SERVICE_ACTION_OUT_12:
        vnp = get_value_name(sg_lib_serv_out12_arr, service_action, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Service action out(12)=0x%x",
                        service_action);
        break;
    case SG_SERVICE_ACTION_IN_16:
        vnp = get_value_name(sg_lib_serv_in16_arr, service_action, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Service action in(16)=0x%x",
                        service_action);
        break;
    case SG_SERVICE_ACTION_OUT_16:
        vnp = get_value_name(sg_lib_serv_out16_arr, service_action, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Service action out(16)=0x%x",
                        service_action);
        break;
    case SG_PERSISTENT_RESERVE_IN:
        vnp = get_value_name(sg_lib_pr_in_arr, service_action, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Persistent reserve in, service "
                        "action=0x%x", service_action);
        break;
    case SG_PERSISTENT_RESERVE_OUT:
        vnp = get_value_name(sg_lib_pr_out_arr, service_action, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Persistent reserve out, service "
                        "action=0x%x", service_action);
        break;
    case SG_EXTENDED_COPY:
        vnp = get_value_name(sg_lib_xcopy_sa_arr, service_action, peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Extended copy, service action=0x%x",
                        service_action);
        break;
    case SG_RECEIVE_COPY:
        vnp = get_value_name(sg_lib_rec_copy_sa_arr, service_action,
                             peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "%s", vnp->name);
        else
            my_snprintf(buff, buff_len, "Receive copy, service action=0x%x",
                        service_action);
        break;
    case SG_READ_BUFFER:
        /* spc4r34 requested treating mode as service action */
        vnp = get_value_name(sg_lib_read_buff_arr, service_action,
                             peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "Read buffer (%s)\n", vnp->name);
        else
            my_snprintf(buff, buff_len, "Read buffer, mode=0x%x",
                        service_action);
        break;
    case SG_WRITE_BUFFER:
        /* spc4r34 requested treating mode as service action */
        vnp = get_value_name(sg_lib_write_buff_arr, service_action,
                             peri_type);
        if (vnp)
            my_snprintf(buff, buff_len, "Write buffer (%s)\n", vnp->name);
        else
            my_snprintf(buff, buff_len, "Write buffer, mode=0x%x",
                        service_action);
        break;
    default:
        sg_get_opcode_name(cmd_byte0, peri_type, buff_len, buff);
        break;
    }
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


/* safe_strerror() contributed by Clayton Weaver <cgweav at email dot com>
   Allows for situation in which strerror() is given a wild value (or the
   C library is incomplete) and returns NULL. Still not thread safe.
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


/* Note the ASCII-hex output goes to stdout. [Most other output from functions
   in this file go to sg_warnings_strm (default stderr).]
   'no_ascii' allows for 3 output types:
       > 0     each line has address then up to 16 ASCII-hex bytes
       = 0     in addition, the bytes are listed in ASCII to the right
       < 0     only the ASCII-hex bytes are listed (i.e. without address) */
void
dStrHex(const char* str, int len, int no_ascii)
{
    const char * p = str;
    const char * formatstr;
    unsigned char c;
    char buff[82];
    int a = 0;
    const int bpstart = 5;
    const int cpstart = 60;
    int cpos = cpstart;
    int bpos = bpstart;
    int i, k, blen;

    if (len <= 0)
        return;
    blen = (int)sizeof(buff);
    formatstr = (0 == no_ascii) ? "%.76s\n" : "%.56s\n";
    memset(buff, ' ', 80);
    buff[80] = '\0';
    if (no_ascii < 0) {
        for (k = 0; k < len; k++) {
            c = *p++;
            bpos += 3;
            if (bpos == (bpstart + (9 * 3)))
                bpos++;
            my_snprintf(&buff[bpos], blen - bpos, "%.2x",
                        (int)(unsigned char)c);
            buff[bpos + 2] = ' ';
            if ((k > 0) && (0 == ((k + 1) % 16))) {
                printf(formatstr, buff);
                bpos = bpstart;
                memset(buff, ' ', 80);
            }
        }
        if (bpos > bpstart) {
            buff[bpos + 2] = '\0';
            printf("%s\n", buff);
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
            printf(formatstr, buff);
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
        printf("%s\n", buff);
    }
}

/* Output to ASCII-Hex bytes to 'b' not to exceed 'b_len' characters.
 * 16 bytes per line with an extra space between the 8th and 9th bytes */
static void
dStrHexErr(const char* str, int len, int b_len, char * b)
{
    const char * p = str;
    unsigned char c;
    char buff[82];
    const int bpstart = 5;
    int bpos = bpstart;
    int k, n;

    if (len <= 0)
        return;
    n = 0;
    memset(buff, ' ', 80);
    buff[80] = '\0';
    for (k = 0; k < len; k++) {
        c = *p++;
        bpos += 3;
        if (bpos == (bpstart + (9 * 3)))
            bpos++;
        my_snprintf(&buff[bpos], (int)sizeof(buff) - bpos, "%.2x",
                    (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
        if ((k > 0) && (0 == ((k + 1) % 16))) {
            n += my_snprintf(b + n, b_len - n, "%.60s\n", buff);
            if (n >= (b_len - 1))
                return;
            bpos = bpstart;
            memset(buff, ' ', 80);
        }
    }
    if (bpos > bpstart)
        n += my_snprintf(b + n, b_len - n, "%.60s\n", buff);
    return;
}

/* Returns 1 when executed on big endian machine; else returns 0.
   Useful for displaying ATA identify words (which need swapping on a
   big endian machine). */
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
   in this file go to sg_warnings_strm (default stderr).]
   'no_ascii' allows for 3 output types:
       > 0     each line has address then up to 8 ASCII-hex 16 bit words
       = 0     in addition, the ASCI bytes pairs are listed to the right
       = -1    only the ASCII-hex words are listed (i.e. without address)
       = -2    only the ASCII-hex words, formatted for "hdparm --Istdin"
       < -2    same as -1
   If 'swapb' non-zero then bytes in each word swapped. Needs to be set
   for ATA IDENTIFY DEVICE response on big-endian machines. */
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
   then -1 is returned. Accepts a hex prefix (0x or 0X) or a decimal
   multiplier suffix (as per GNU's dd (since 2002: SI and IEC 60027-2)).
   Main (SI) multipliers supported: K, M, G. */
int
sg_get_num(const char * buf)
{
    int res, num, n, len;
    unsigned int unum;
    char * cp;
    char c = 'c';
    char c2, c3;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    len = strlen(buf);
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1]))) {
        res = sscanf(buf + 2, "%x", &unum);
        num = unum;
    } else if ('H' == toupper((int)buf[len - 1])) {
        res = sscanf(buf, "%x", &unum);
        num = unum;
    } else
        res = sscanf(buf, "%d%c%c%c", &num, &c, &c2, &c3);
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
            cp = strchr(buf, 'x');
            if (NULL == cp)
                cp = strchr(buf, 'X');
            if (cp) {
                n = sg_get_num(cp + 1);
                if (-1 != n)
                    return num * n;
            }
            return -1;
        default:
            if (NULL == sg_warnings_strm)
                sg_warnings_strm = stderr;
            fprintf(sg_warnings_strm, "unrecognized multiplier\n");
            return -1;
        }
    }
}

/* If the number in 'buf' can not be decoded then -1 is returned. Accepts a
   hex prefix (0x or 0X) or a 'h' (or 'H') suffix; otherwise decimal is
   assumed. Does not accept multipliers. Accept a comma (","), a whitespace
   or newline as terminator.  */
int
sg_get_num_nomult(const char * buf)
{
    int res, len, num;
    unsigned int unum;
    const char * commap;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    len = strlen(buf);
    commap = strchr(buf + 1, ',');
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
   then -1LL is returned. Accepts a hex prefix (0x or 0X) or a decimal
   multiplier suffix (as per GNU's dd (since 2002: SI and IEC 60027-2)).
   Main (SI) multipliers supported: K, M, G, T, P. */
int64_t
sg_get_llnum(const char * buf)
{
    int res, len;
    int64_t num, ll;
    uint64_t unum;
    char * cp;
    char c = 'c';
    char c2, c3;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1LL;
    len = strlen(buf);
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1]))) {
        res = sscanf(buf + 2, "%" SCNx64 "", &unum);
        num = unum;
    } else if ('H' == toupper((int)buf[len - 1])) {
        res = sscanf(buf, "%" SCNx64 "", &unum);
        num = unum;
    } else
        res = sscanf(buf, "%" SCNd64 "%c%c%c", &num, &c, &c2, &c3);
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
            cp = strchr(buf, 'x');
            if (NULL == cp)
                cp = strchr(buf, 'X');
            if (cp) {
                ll = sg_get_llnum(cp + 1);
                if (-1LL != ll)
                    return num * ll;
            }
            return -1LL;
        default:
            if (NULL == sg_warnings_strm)
                sg_warnings_strm = stderr;
            fprintf(sg_warnings_strm, "unrecognized multiplier\n");
            return -1LL;
        }
    }
}

/* Extract character sequence from ATA words as in the model string
   in a IDENTIFY DEVICE response. Returns number of characters
   written to 'ochars' before 0 character is found or 'num' words
   are processed. */
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

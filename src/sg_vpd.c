/*
 * Copyright (c) 2006-2015 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"
#include "sg_unaligned.h"

/* This utility program was originally written for the Linux OS SCSI subsystem.

   This program fetches Vital Product Data (VPD) pages from the given
   device and outputs it as directed. VPD pages are obtained via a
   SCSI INQUIRY command. Most of the data in this program is obtained
   from the SCSI SPC-4 document at http://www.t10.org .

*/

static const char * version_str = "1.03 20150212";  /* spc5r02 + sbc4r05 */


/* These structures are duplicates of those of the same name in
 * sg_vpd_vendor.c . Take care that both are the same. */
struct opts_t {
    int do_all;
    int do_enum;
    int do_hex;
    int num_vpd;
    int do_ident;
    int do_long;
    int maxlen;
    int do_quiet;
    int do_raw;
    int vend_prod_num;
    int verbose;
    const char * device_name;
    const char * page_str;
    const char * inhex_fn;
    const char * vend_prod;
};

struct svpd_values_name_t {
    int value;       /* VPD page number */
    int subvalue;    /* to differentiate if value+pdt are not unique */
    int pdt;         /* peripheral device type id, -1 is the default */
                     /* (all or not applicable) value */
    const char * acron;
    const char * name;
};


void svpd_enumerate_vendor(int vend_prod_num);
int svpd_count_vendor_vpds(int num_vpd, int vend_prod_num);
int svpd_decode_vendor(int sg_fd, struct opts_t * op, int off);
const struct svpd_values_name_t * svpd_find_vendor_by_acron(const char * ap);
int svpd_find_vp_num_by_acron(const char * vp_ap);
const struct svpd_values_name_t * svpd_find_vendor_by_num(int page_num,
                                                          int vend_prod_num);
int vpd_fetch_page_from_dev(int sg_fd, unsigned char * rp, int page,
                            int mxlen, int vb, int * rlenp);


/* standard VPD pages, in ascending page number order */
#define VPD_SUPPORTED_VPDS 0x0
#define VPD_UNIT_SERIAL_NUM 0x80
#define VPD_IMP_OP_DEF 0x81     /* obsolete in SPC-2 */
#define VPD_ASCII_OP_DEF 0x82   /* obsolete in SPC-2 */
#define VPD_DEVICE_ID 0x83
#define VPD_SOFTW_INF_ID 0x84
#define VPD_MAN_NET_ADDR 0x85
#define VPD_EXT_INQ 0x86
#define VPD_MODE_PG_POLICY 0x87
#define VPD_SCSI_PORTS 0x88
#define VPD_ATA_INFO 0x89
#define VPD_POWER_CONDITION 0x8a
#define VPD_DEVICE_CONSTITUENTS 0x8b
#define VPD_CFA_PROFILE_INFO 0x8c
#define VPD_POWER_CONSUMPTION  0x8d
#define VPD_3PARTY_COPY 0x8f    /* 3PC, XCOPY, SPC-4, SBC-3 */
#define VPD_PROTO_LU 0x90
#define VPD_PROTO_PORT 0x91
#define VPD_BLOCK_LIMITS 0xb0   /* SBC-3 */
#define VPD_SA_DEV_CAP 0xb0     /* SSC-3 */
#define VPD_OSD_INFO 0xb0       /* OSD */
#define VPD_BLOCK_DEV_CHARS 0xb1 /* SBC-3 */
#define VPD_MAN_ASS_SN 0xb1     /* SSC-3, ADC-2 */
#define VPD_SECURITY_TOKEN 0xb1 /* OSD */
#define VPD_TA_SUPPORTED 0xb2   /* SSC-3 */
#define VPD_LB_PROVISIONING 0xb2   /* SBC-3 */
#define VPD_REFERRALS 0xb3   /* SBC-3 */
#define VPD_AUTOMATION_DEV_SN 0xb3   /* SSC-3 */
#define VPD_SUP_BLOCK_LENS 0xb4 /* SBC-4 */
#define VPD_DTDE_ADDRESS 0xb4   /* SSC-4 */
#define VPD_BLOCK_DEV_C_EXTENS 0xb5 /* SBC-4 */
#define VPD_ZBC_DEV_CHARS 0xb6  /* ZBC */
#define VPD_NO_RATHER_STD_INQ -2      /* request for standard inquiry */

/* Device identification VPD page associations */
#define VPD_ASSOC_LU 0
#define VPD_ASSOC_TPORT 1
#define VPD_ASSOC_TDEVICE 2

/* values for selection one or more associations (2**vpd_assoc),
   except _AS_IS */
#define VPD_DI_SEL_LU 1
#define VPD_DI_SEL_TPORT 2
#define VPD_DI_SEL_TARGET 4
#define VPD_DI_SEL_AS_IS 32

#define DEF_ALLOC_LEN 252
#define MX_ALLOC_LEN (0xc000 + 0x80)
#define VPD_ATA_INFO_LEN  572

#define SENSE_BUFF_LEN  64       /* Arbitrary, could be larger */
#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define DEF_PT_TIMEOUT  60       /* 60 seconds */


unsigned char rsp_buff[MX_ALLOC_LEN + 2];

static int decode_dev_ids(const char * print_if_found, unsigned char * buff,
                          int len, int m_assoc, int m_desig_type,
                          int m_code_set, int long_out, int quiet);
static void decode_transport_id(const char * leadin, unsigned char * ucp,
                                int len);

static struct option long_options[] = {
        {"all", no_argument, 0, 'a'},
        {"enumerate", no_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"ident", no_argument, 0, 'i'},
        {"inhex", required_argument, 0, 'I'},
        {"long", no_argument, 0, 'l'},
        {"maxlen", required_argument, 0, 'm'},
        {"page", required_argument, 0, 'p'},
        {"quiet", no_argument, 0, 'q'},
        {"raw", no_argument, 0, 'r'},
        {"vendor", required_argument, 0, 'M'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};


/* arranged in alphabetical order by acronym */
static struct svpd_values_name_t standard_vpd_pg[] = {
    {VPD_ATA_INFO, 0, -1, "ai", "ATA information (SAT)"},
    {VPD_ASCII_OP_DEF, 0, -1, "aod",
     "ASCII implemented operating definition (obsolete)"},
    {VPD_AUTOMATION_DEV_SN, 0, 1, "adsn", "Automation device serial "
     "number (SSC)"},
    {VPD_BLOCK_LIMITS, 0, 0, "bl", "Block limits (SBC)"},
    {VPD_BLOCK_DEV_CHARS, 0, 0, "bdc", "Block device characteristics "
     "(SBC)"},
    {VPD_BLOCK_DEV_C_EXTENS, 0, 0, "bdce", "Block device characteristics "
     "extension (SBC)"},
    {VPD_CFA_PROFILE_INFO, 0, 0, "cfa", "CFA profile information"},
    {VPD_DEVICE_CONSTITUENTS, 0, -1, "dc", "Device constituents"},
    {VPD_DEVICE_ID, 0, -1, "di", "Device identification"},
    {VPD_DEVICE_ID, VPD_DI_SEL_AS_IS, -1, "di_asis", "Like 'di' "
     "but designators ordered as found"},
    {VPD_DEVICE_ID, VPD_DI_SEL_LU, -1, "di_lu", "Device identification, "
     "lu only"},
    {VPD_DEVICE_ID, VPD_DI_SEL_TPORT, -1, "di_port", "Device "
     "identification, target port only"},
    {VPD_DEVICE_ID, VPD_DI_SEL_TARGET, -1, "di_target", "Device "
     "identification, target device only"},
    {VPD_DTDE_ADDRESS, 0, 1, "dtde",
     "Data transfer device element address (SSC)"},
    {VPD_EXT_INQ, 0, -1, "ei", "Extended inquiry data"},
    {VPD_IMP_OP_DEF, 0, -1, "iod",
     "Implemented operating definition (obsolete)"},
    {VPD_LB_PROVISIONING, 0, 0, "lbpv",
     "Logical block provisioning (SBC)"},
    {VPD_MAN_ASS_SN, 0, 1, "mas",
     "Manufacturer assigned serial number (SSC)"},
    {VPD_MAN_ASS_SN, 0, 0x12, "masa",
     "Manufacturer assigned serial number (ADC)"},
    {VPD_MAN_NET_ADDR, 0, -1, "mna", "Management network addresses"},
    {VPD_MODE_PG_POLICY, 0, -1, "mpp", "Mode page policy"},
    {VPD_OSD_INFO, 0, 0x11, "oi", "OSD information"},
    {VPD_POWER_CONDITION, 0, -1, "pc", "Power condition"},
    {VPD_POWER_CONSUMPTION, 0, -1, "psm", "Power consumption"},
    {VPD_PROTO_LU, 0, -1, "pslu", "Protocol-specific logical unit "
     "information"},
    {VPD_PROTO_PORT, 0, -1, "pspo", "Protocol-specific port information"},
    {VPD_REFERRALS, 0, 0, "ref", "Referrals (SBC)"},
    {VPD_SA_DEV_CAP, 0, 1, "sad",
     "Sequential access device capabilities (SSC)"},
    {VPD_SOFTW_INF_ID, 0, -1, "sii", "Software interface identification"},
    {VPD_NO_RATHER_STD_INQ, 0, -1, "sinq", "Standard inquiry response"},
    {VPD_UNIT_SERIAL_NUM, 0, -1, "sn", "Unit serial number"},
    {VPD_SCSI_PORTS, 0, -1, "sp", "SCSI ports"},
    {VPD_SECURITY_TOKEN, 0, 0x11, "st", "Security token (OSD)"},
    {VPD_SUP_BLOCK_LENS, 0, 0, "sbl", "Supported block lengths and "
     "protection types (SBC)"},
    {VPD_SUPPORTED_VPDS, 0, -1, "sv", "Supported VPD pages"},
    {VPD_TA_SUPPORTED, 0, 1, "tas", "TapeAlert supported flags (SSC)"},
    {VPD_3PARTY_COPY, 0, -1, "tpc", "Third party copy"},
    {VPD_ZBC_DEV_CHARS, 0, -1, "zbdc", "Zoned block device characteristics"},
        /* Use pdt of -1 since this page both for pdt=0 and pdt=0x14 */
    {0, 0, 0, NULL, NULL},
};


#ifdef __GNUC__
static int pr2serr(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
static int pr2serr(const char * fmt, ...);
#endif


static int
pr2serr(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

static void
usage()
{
    pr2serr("Usage: sg_vpd  [--all] [--enumerate] [--help] [--hex] "
            "[--ident]\n"
            "               [--inhex=FN] [--long] [--maxlen=LEN] "
            "[--page=PG] [--quiet]\n"
            "               [--raw] [--vendor=VP] [--verbose] [--version] "
            "DEVICE\n");
    pr2serr("  where:\n"
            "    --all|-a        output all pages listed in the supported "
            "pages VPD\n"
            "                    page\n"
            "    --enumerate|-e    enumerate known VPD pages names (ignore "
            "DEVICE),\n"
            "                      can be used with --page=num to search\n"
            "    --help|-h       output this usage message then exit\n"
            "    --hex|-H        output page in ASCII hexadecimal\n"
            "    --ident|-i      output device identification VPD page, "
            "twice for\n"
            "                    short logical unit designator (equiv: "
            "'-qp di_lu')\n"
            "    --inhex=FN|-I FN    read ASCII hex from file FN instead of "
            "DEVICE;\n"
            "                        if used with --raw then read binary "
            "from FN\n"
            "    --long|-l       perform extra decoding\n"
            "    --maxlen=LEN|-m LEN    max response length (allocation "
            "length in cdb)\n"
            "                           (def: 0 -> 252 bytes)\n"
            "    --page=PG|-p PG    fetch VPD page where PG is an "
            "acronym, or a decimal\n"
            "                       number unless hex indicator "
            "is given (e.g. '0x83')\n"
            "    --quiet|-q      suppress some output when decoding\n"
            "    --raw|-r        output page in binary\n"
            "    --vendor=VP | -M VP    vendor/product abbreviation [or "
            "number]\n"
            "    --verbose|-v    increase verbosity\n"
            "    --version|-V    print version string and exit\n\n"
            "Fetch Vital Product Data (VPD) page using SCSI INQUIRY or "
            "decodes VPD\npage response held in file FN. To list available "
            "pages use '-e'. Also\n'-p -1' yields the standard INQUIRY "
            "response.\n");
}

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
    int fn_len, in_len, k, j, m, split_line, fd, has_stdin;
    unsigned int h;
    const char * lcp;
    FILE * fp;
    char line[512];
    char carry_over[4];
    int off = 0;
    struct stat a_stat;

    if ((NULL == fname) || (NULL == mp_arr) || (NULL == mp_arr_len))
        return 1;
    fn_len = strlen(fname);
    if (0 == fn_len)
        return 1;
    has_stdin = ((1 == fn_len) && ('-' == fname[0]));   /* read from stdin */
    if (as_binary) {
        if (has_stdin)
            fd = STDIN_FILENO;
        else {
            fd = open(fname, O_RDONLY);
            if (fd < 0) {
                pr2serr("unable to open binary file %s: %s\n", fname,
                         safe_strerror(errno));
                return 1;
            }
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
        if ((0 == fstat(fd, &a_stat)) && S_ISFIFO(a_stat.st_mode)) {
            /* pipe; keep reading till error or 0 read */
            while (k < max_arr_len) {
                m = read(fd, mp_arr + k, max_arr_len - k);
                if (0 == m)
                   break;
                if (m < 0) {
                    pr2serr("read from binary pipe %s: %s\n", fname,
                            safe_strerror(errno));
                    if (! has_stdin)
                        close(fd);
                    return 1;
                }
                k += m;
            }
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
                        pr2serr("%s: hex number larger than 0xff in line "
                                "%d, pos %d\n", __func__, j + 1,
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
    inqCmdBlk[3] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    inqCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
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

/* mxlen is command line --maxlen=LEN option (def: 0) or -1 for a VPD page
 * with a short length (1 byte). Returns 0 for success. */
int     /* global: use by sg_vpd_vendor.c */
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
        n = (rlen < 32) ? rlen : 32;
        if (vb) {
            pr2serr("First %d bytes of bad response\n", n);
            dStrHexErr((const char *)rp, n, 0);
        }
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

static const struct svpd_values_name_t *
sdp_get_vpd_detail(int page_num, int subvalue, int pdt)
{
    const struct svpd_values_name_t * vnp;
    int sv, ty;

    sv = (subvalue < 0) ? 1 : 0;
    ty = (pdt < 0) ? 1 : 0;
    for (vnp = standard_vpd_pg; vnp->acron; ++vnp) {
        if ((page_num == vnp->value) &&
            (sv || (subvalue == vnp->subvalue)) &&
            (ty || (pdt == vnp->pdt)))
            return vnp;
    }
    if (! ty)
        return sdp_get_vpd_detail(page_num, subvalue, -1);
    if (! sv)
        return sdp_get_vpd_detail(page_num, -1, -1);
    return NULL;
}

static const struct svpd_values_name_t *
sdp_find_vpd_by_acron(const char * ap)
{
    const struct svpd_values_name_t * vnp;

    for (vnp = standard_vpd_pg; vnp->acron; ++vnp) {
        if (0 == strcmp(vnp->acron, ap))
            return vnp;
    }
    return NULL;
}

static void
enumerate_vpds(int standard, int vendor)
{
    const struct svpd_values_name_t * vnp;

    if (standard) {
        for (vnp = standard_vpd_pg; vnp->acron; ++vnp) {
            if (vnp->name) {
                if (vnp->value < 0)
                    printf("  %-10s -1        %s\n", vnp->acron, vnp->name);
                else
                    printf("  %-10s 0x%02x      %s\n", vnp->acron, vnp->value,
                       vnp->name);
            }
        }
    }
    if (vendor)
        svpd_enumerate_vendor(-2);
}

static int
count_standard_vpds(int num_vpd)
{
    const struct svpd_values_name_t * vnp;
    int matches;

    for (vnp = standard_vpd_pg, matches = 0; vnp->acron; ++vnp) {
        if ((num_vpd == vnp->value) && vnp->name) {
            if (0 == matches)
                printf("Matching standard VPD pages:\n");
            ++matches;
            if (vnp->value < 0)
                printf("  %-10s -1        %s\n", vnp->acron, vnp->name);
            else
                printf("  %-10s 0x%02x      %s\n", vnp->acron, vnp->value,
                   vnp->name);
        }
    }
    return matches;
}

static void
dStrRaw(const char * str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

/* Assume index is less than 16 */
const char * sg_ansi_version_arr[] =
{
    "no conformance claimed",
    "SCSI-1",           /* obsolete, ANSI X3.131-1986 */
    "SCSI-2",           /* obsolete, ANSI X3.131-1994 */
    "SPC",              /* withdrawn */
    "SPC-2",
    "SPC-3",
    "SPC-4",
    "SPC-5",
    "ecma=1, [8h]",
    "ecma=1, [9h]",
    "ecma=1, [Ah]",
    "ecma=1, [Bh]",
    "reserved [Ch]",
    "reserved [Dh]",
    "reserved [Eh]",
    "reserved [Fh]",
};

static void
decode_std_inq(unsigned char * b, int len, int verbose)
{
    int pqual, n;

    if (len < 4)
        return;
    pqual = (b[0] & 0xe0) >> 5;
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
    printf("  PQual=%d  Device_type=%d  RMB=%d  LU_CONG=%d  version=0x%02x ",
           pqual, b[0] & 0x1f, !!(b[1] & 0x80), !!(b[1] & 0x40),
           (unsigned int)b[2]);
    printf(" [%s]\n", sg_ansi_version_arr[b[2] & 0xf]);
    printf("  [AERC=%d]  [TrmTsk=%d]  NormACA=%d  HiSUP=%d "
           " Resp_data_format=%d\n",
           !!(b[3] & 0x80), !!(b[3] & 0x40), !!(b[3] & 0x20),
           !!(b[3] & 0x10), b[3] & 0x0f);
    if (len < 5)
        return;
    n = b[4] + 5;
    if (verbose)
        pr2serr(">> requested %d bytes, %d bytes available\n", len, n);
    printf("  SCCS=%d  ACC=%d  TPGS=%d  3PC=%d  Protect=%d ",
           !!(b[5] & 0x80), !!(b[5] & 0x40), ((b[5] & 0x30) >> 4),
           !!(b[5] & 0x08), !!(b[5] & 0x01));
    printf(" [BQue=%d]\n  EncServ=%d  ", !!(b[6] & 0x80), !!(b[6] & 0x40));
    if (b[6] & 0x10)
        printf("MultiP=1 (VS=%d)  ", !!(b[6] & 0x20));
    else
        printf("MultiP=0  ");
    printf("[MChngr=%d]  [ACKREQQ=%d]  Addr16=%d\n  [RelAdr=%d]  ",
           !!(b[6] & 0x08), !!(b[6] & 0x04), !!(b[6] & 0x01),
           !!(b[7] & 0x80));
    printf("WBus16=%d  Sync=%d  [Linked=%d]  [TranDis=%d]  ",
           !!(b[7] & 0x20), !!(b[7] & 0x10), !!(b[7] & 0x08),
           !!(b[7] & 0x04));
    printf("CmdQue=%d\n", !!(b[7] & 0x02));
    if (len < 36)
        return;
    printf("  Vendor_identification: %.8s\n", b + 8);
    printf("  Product_identification: %.16s\n", b + 16);
    printf("  Product_revision_level: %.4s\n", b + 32);
}

static const char * assoc_arr[] =
{
    "Addressed logical unit",
    "Target port",      /* that received request; unless SCSI ports VPD */
    "Target device that contains addressed lu",
    "Reserved [0x3]",
};

static void
decode_id_vpd(unsigned char * buff, int len, int subvalue, int do_long,
              int do_quiet)
{
    int m_a, m_d, m_cs;

    if (len < 4) {
        pr2serr("Device identification VPD page length too short=%d\n", len);
        return;
    }
    m_a = -1;
    m_d = -1;
    m_cs = -1;
    if (0 == subvalue) {
        decode_dev_ids(assoc_arr[VPD_ASSOC_LU], buff + 4, len - 4,
                       VPD_ASSOC_LU, m_d, m_cs, do_long, do_quiet);
        decode_dev_ids(assoc_arr[VPD_ASSOC_TPORT], buff + 4, len - 4,
                       VPD_ASSOC_TPORT, m_d, m_cs, do_long, do_quiet);
        decode_dev_ids(assoc_arr[VPD_ASSOC_TDEVICE], buff + 4, len - 4,
                       VPD_ASSOC_TDEVICE, m_d, m_cs, do_long, do_quiet);
    } else if (VPD_DI_SEL_AS_IS == subvalue)
        decode_dev_ids(NULL, buff + 4, len - 4, m_a, m_d, m_cs, do_long,
                       do_quiet);
    else {
        if (VPD_DI_SEL_LU & subvalue)
            decode_dev_ids(assoc_arr[VPD_ASSOC_LU], buff + 4, len - 4,
                           VPD_ASSOC_LU, m_d, m_cs, do_long, do_quiet);
        if (VPD_DI_SEL_TPORT & subvalue)
            decode_dev_ids(assoc_arr[VPD_ASSOC_TPORT], buff + 4, len - 4,
                           VPD_ASSOC_TPORT, m_d, m_cs, do_long, do_quiet);
        if (VPD_DI_SEL_TARGET & subvalue)
            decode_dev_ids(assoc_arr[VPD_ASSOC_TDEVICE], buff + 4, len - 4,
                           VPD_ASSOC_TDEVICE, m_d, m_cs, do_long, do_quiet);
    }
}

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
    "reserved[0x8]", "reserved[0x9]",
    "reserved[0xa]", "reserved[0xb]", "reserved[0xc]", "reserved[0xd]",
    "reserved[0xe]", "reserved[0xf]", "reserved[0x10]", "reserved[0x11]",
    "reserved[0x12]", "reserved[0x13]", "reserved[0x14]", "reserved[0x15]",
    "reserved[0x16]", "reserved[0x17]", "reserved[0x18]", "reserved[0x19]",
    "reserved[0x1a]", "reserved[0x1b]", "reserved[0x1c]", "reserved[0x1d]",
    "reserved[0x1e]", "reserved[0x1f]",
};

/* VPD_MAN_NET_ADDR */
static void
decode_net_man_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump, na_len;
    unsigned char * ucp;

    if ((1 == do_hex) || (do_hex > 2)) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Management network addresses VPD page length too short=%d\n",
                len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        printf("  %s, Service type: %s\n",
               assoc_arr[(ucp[0] >> 5) & 0x3],
               network_service_type_arr[ucp[0] & 0x1f]);
        na_len = sg_get_unaligned_be16(ucp + 2);
        bump = 4 + na_len;
        if ((k + bump) > len) {
            pr2serr("Management network addresses VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (na_len > 0) {
            if (do_hex > 1) {
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

    if ((1 == do_hex) || (do_hex > 2)) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Mode page policy VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            pr2serr("Mode page policy VPD page, short "
                    "descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (do_hex > 1)
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
decode_scsi_ports_vpd(unsigned char * buff, int len, int do_hex, int do_long,
                      int do_quiet)
{
    int k, bump, rel_port, ip_tid_len, tpd_len;
    unsigned char * ucp;

    if ((1 == do_hex) || (do_hex > 2)) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("SCSI Ports VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        rel_port = sg_get_unaligned_be16(ucp + 2);
        printf("  Relative port=%d\n", rel_port);
        ip_tid_len = sg_get_unaligned_be16(ucp + 6);
        bump = 8 + ip_tid_len;
        if ((k + bump) > len) {
            pr2serr("SCSI Ports VPD page, short descriptor "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (ip_tid_len > 0) {
            if (do_hex > 1) {
                printf("    Initiator port transport id:\n");
                dStrHex((const char *)(ucp + 8), ip_tid_len, 1);
            } else
                decode_transport_id("    ", ucp + 8, ip_tid_len);
        }
        tpd_len = sg_get_unaligned_be16(ucp + bump + 2);
        if ((k + bump + tpd_len + 4) > len) {
            pr2serr("SCSI Ports VPD page, short descriptor(tgt) "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (tpd_len > 0) {
            if (do_hex > 1) {
                printf("    Target port descriptor(s):\n");
                dStrHex((const char *)(ucp + bump + 4), tpd_len, 1);
            } else {
                if ((0 == do_quiet) || (ip_tid_len > 0))
                    printf("    Target port descriptor(s):\n");
                decode_dev_ids("SCSI Ports", ucp + bump + 4, tpd_len,
                               VPD_ASSOC_TPORT, -1, -1, do_long, do_quiet);
            }
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
    "Reserved [0x4]", "Reserved [0x5]", "Reserved [0x6]", "Reserved [0x7]",
    "Reserved [0x8]", "Reserved [0x9]", "Reserved [0xa]", "Reserved [0xb]",
    "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};

static const char * desig_type_arr[] =
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
    "Protocol specific port identifier",  /* spc4r36 */
    "Reserved [0xa]", "Reserved [0xb]",
    "Reserved [0xc]", "Reserved [0xd]", "Reserved [0xe]", "Reserved [0xf]",
};


/* Prints outs an abridged set of device identification designators
   selected by association, designator type and/or code set. */
static int
decode_dev_ids_quiet(unsigned char * buff, int len, int m_assoc,
                     int m_desig_type, int m_code_set)
{
    int m, p_id, c_set, piv, desig_type, i_len, naa, off, u;
    int assoc, is_sas, rtp;
    const unsigned char * ucp;
    const unsigned char * ip;
    unsigned char sas_tport_addr[8];

    rtp = 0;
    memset(sas_tport_addr, 0, sizeof(sas_tport_addr));
    off = -1;
    if (buff[2] != 0) {
        if (m_assoc != VPD_ASSOC_LU)
            return 0;
        ip = buff;
        p_id = 0;
        c_set = 1;
        assoc = VPD_ASSOC_LU;
        piv = 0;
        is_sas = 0;
        desig_type = 3;
        i_len = 16;
        off = 16;
        goto decode;
    }
    while ((u = sg_vpd_dev_id_iter(buff, len, &off, m_assoc, m_desig_type,
                                   m_code_set)) == 0) {
        ucp = buff + off;
        i_len = ucp[3];
        if ((off + i_len + 4) > len) {
            pr2serr("    VPD page error: designator length longer than\n"
                    "     remaining response length=%d\n", (len - off));
            return SG_LIB_CAT_MALFORMED;
        }
        ip = ucp + 4;
        p_id = ((ucp[0] >> 4) & 0xf);
        c_set = (ucp[0] & 0xf);
        piv = ((ucp[1] & 0x80) ? 1 : 0);
        is_sas = (piv && (6 == p_id)) ? 1 : 0;
        assoc = ((ucp[1] >> 4) & 0x3);
        desig_type = (ucp[1] & 0xf);
 decode:
        switch (desig_type) {
        case 0: /* vendor specific */
            break;
        case 1: /* T10 vendor identification */
            break;
        case 2: /* EUI-64 based */
            if ((8 != i_len) && (12 != i_len) && (16 != i_len))
                pr2serr("      << expect 8, 12 and 16 byte "
                        "EUI, got %d>>\n", i_len);
            printf("  0x");
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        case 3: /* NAA */
            naa = (ip[0] >> 4) & 0xff;
            if (1 != c_set) {
                pr2serr("      << expected binary code_set (1), got %d for "
                        "NAA=%d>>\n", c_set, naa);
                dStrHexErr((const char *)ip, i_len, 0);
                break;
            }
            switch (naa) {
            case 2:             /* NAA IEEE extended */
                if (8 != i_len) {
                    pr2serr("      << unexpected NAA 2 identifier "
                            "length: 0x%x>>\n", i_len);
                    dStrHexErr((const char *)ip, i_len, 0);
                    break;
                }
                printf("  0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
                break;
            case 3:             /* Locally assigned */
            case 5:             /* IEEE Registered */
                if (8 != i_len) {
                    pr2serr("      << unexpected NAA 3 or 5 "
                            "identifier length: 0x%x>>\n", i_len);
                    dStrHexErr((const char *)ip, i_len, 0);
                    break;
                }
                if ((0 == is_sas) || (1 != assoc)) {
                    printf("  0x");
                    for (m = 0; m < 8; ++m)
                        printf("%02x", (unsigned int)ip[m]);
                    printf("\n");
                } else if (rtp) {
                    printf("  0x");
                    for (m = 0; m < 8; ++m)
                        printf("%02x", (unsigned int)ip[m]);
                    printf(",0x%x\n", rtp);
                    rtp = 0;
                } else {
                    if (sas_tport_addr[0]) {
                        printf("  0x");
                        for (m = 0; m < 8; ++m)
                            printf("%02x", (unsigned int)sas_tport_addr[m]);
                        printf("\n");
                    }
                    memcpy(sas_tport_addr, ip, sizeof(sas_tport_addr));
                }
                break;
            case 6:             /* NAA IEEE registered extended */
                if (16 != i_len) {
                    pr2serr("      << unexpected NAA 6 identifier length: "
                            "0x%x>>\n", i_len);
                    dStrHexErr((const char *)ip, i_len, 0);
                    break;
                }
                printf("  0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
                break;
            default:
                pr2serr("      << bad NAA nibble, expected 2, 3, 5 or 6, got "
                        "%d>>\n", naa);
                dStrHexErr((const char *)ip, i_len, 0);
                break;
            }
            break;
        case 4: /* Relative target port */
            if ((0 == is_sas) || (1 != c_set) || (1 != assoc) || (4 != i_len))
                break;
            rtp = sg_get_unaligned_be16(ip + 2);
            if (sas_tport_addr[0]) {
                printf("  0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)sas_tport_addr[m]);
                printf(",0x%x\n", rtp);
                memset(sas_tport_addr, 0, sizeof(sas_tport_addr));
                rtp = 0;
            }
            break;
        case 5: /* (primary) Target port group */
            break;
        case 6: /* Logical unit group */
            break;
        case 7: /* MD5 logical unit identifier */
            break;
        case 8: /* SCSI name string */
            if (3 != c_set) {
                pr2serr("      << expected UTF-8 code_set>>\n");
                dStrHexErr((const char *)ip, i_len, 0);
                break;
            }
            if (! (strncmp((const char *)ip, "eui.", 4) ||
                   strncmp((const char *)ip, "EUI.", 4) ||
                   strncmp((const char *)ip, "naa.", 4) ||
                   strncmp((const char *)ip, "NAA.", 4) ||
                   strncmp((const char *)ip, "iqn.", 4))) {
                pr2serr("      << expected name string prefix>>\n");
                dStrHexErr((const char *)ip, i_len, -1);
                break;
            }
            /* does %s print out UTF-8 ok??
             * Seems to depend on the locale. Looks ok here with my
             * locale setting: en_AU.UTF-8
             */
            printf("  %s\n", (const char *)ip);
            break;
        case 9: /* PCIe routing ID */
            break;
        default: /* reserved */
            break;
        }
    }
    if (sas_tport_addr[0]) {
        printf("  0x");
        for (m = 0; m < 8; ++m)
            printf("%02x", (unsigned int)sas_tport_addr[m]);
        printf("\n");
    }
    if (-2 == u) {
        pr2serr("VPD page error: short designator around offset %d\n", off);
        return SG_LIB_CAT_MALFORMED;
    }
    return 0;
}

static void
decode_designation_descriptor(const unsigned char * ip, int i_len,
                              int p_id, int c_set, int piv, int assoc,
                              int desig_type, int long_out, int print_assoc)
{
    int m, ci_off, c_id, d_id, naa;
    int vsi, k;
    uint64_t vsei;
    uint64_t id_ext;
    char b[64];

    if (print_assoc)
        printf("  %s:\n", assoc_arr[assoc]);
    printf("    designator type: %s,  code set: %s\n",
           desig_type_arr[desig_type], code_set_arr[c_set]);
    if (piv && ((1 == assoc) || (2 == assoc)))
        printf("     transport: %s\n",
               sg_get_trans_proto_str(p_id, sizeof(b), b));
    /* printf("    associated with the %s\n", assoc_arr[assoc]); */
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
            pr2serr("      vendor specific:\n");
            dStrHexErr((const char *)ip, i_len, 0);
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
        if (! long_out) {
            if ((8 != i_len) && (12 != i_len) && (16 != i_len)) {
                pr2serr("      << expect 8, 12 and 16 byte EUI, got %d>>\n",
                        i_len);
                dStrHexErr((const char *)ip, i_len, 0);
                break;
            }
            printf("      0x");
            for (m = 0; m < i_len; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        }
        printf("      EUI-64 based %d byte identifier\n", i_len);
        if (1 != c_set) {
            pr2serr("      << expected binary code_set (1)>>\n");
            dStrHexErr((const char *)ip, i_len, 0);
            break;
        }
        ci_off = 0;
        if (16 == i_len) {
            ci_off = 8;
            id_ext = sg_get_unaligned_be64(ip);
            printf("      Identifier extension: 0x%" PRIx64 "\n", id_ext);
        } else if ((8 != i_len) && (12 != i_len)) {
            pr2serr("      << can only decode 8, 12 and 16 byte ids>>\n");
            dStrHexErr((const char *)ip, i_len, 0);
            break;
        }
        c_id = sg_get_unaligned_be24(ip + ci_off);
        printf("      IEEE Company_id: 0x%x\n", c_id);
        vsei = ((uint64_t)sg_get_unaligned_be32(ip + ci_off + 3) << 8) +
               ip[ci_off + 3 + 4];      /* 5 byte integer */
        printf("      Vendor Specific Extension Identifier: 0x%" PRIx64
               "\n", vsei);
        if (12 == i_len) {
            d_id = sg_get_unaligned_be32(ip + 8);
            printf("      Directory ID: 0x%x\n", d_id);
        }
        break;
    case 3: /* NAA <n> */
        if (1 != c_set) {
            pr2serr("      << unexpected code set %d for NAA>>\n", c_set);
            dStrHexErr((const char *)ip, i_len, 0);
            break;
        }
        naa = (ip[0] >> 4) & 0xff;
        switch (naa) {
        case 2:         /* NAA 2: IEEE Extended */
            if (8 != i_len) {
                pr2serr("      << unexpected NAA 2 identifier length: "
                        "0x%x>>\n", i_len);
                dStrHexErr((const char *)ip, i_len, 0);
                break;
            }
            d_id = sg_get_unaligned_be16(ip) & 0xfff;
            c_id = sg_get_unaligned_be24(ip + 2);
            vsi = sg_get_unaligned_be24(ip + 5);
            if (long_out) {
                printf("      NAA 2, vendor specific identifier A: "
                       "0x%x\n", d_id);
                printf("      IEEE Company_id: 0x%x\n", c_id);
                printf("      vendor specific identifier B: 0x%x\n", vsi);
                printf("      [0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            }
            printf("      0x");
            for (m = 0; m < 8; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        case 3:         /* NAA 3: Locally assigned */
            if (8 != i_len) {
                pr2serr("      << unexpected NAA 3 identifier length: "
                        "0x%x>>\n", i_len);
                dStrHexErr((const char *)ip, i_len, 0);
                break;
            }
            if (long_out)
                printf("      NAA 3, Locally assigned value:\n");
            printf("      0x");
            for (m = 0; m < 8; ++m)
                printf("%02x", (unsigned int)ip[m]);
            printf("\n");
            break;
        case 5:         /* NAA 5: IEEE Registered */
            if (8 != i_len) {
                pr2serr("      << unexpected NAA 5 identifier length: "
                        "0x%x>>\n", i_len);
                dStrHexErr((const char *)ip, i_len, 0);
                break;
            }
            if (long_out) {
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
            } else {
                printf("      0x");
                for (m = 0; m < 8; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            }
            break;
        case 6:         /* NAA 6: IEEE Registered extended */
            if (16 != i_len) {
                pr2serr("      << unexpected NAA 6 identifier length: "
                        "0x%x>>\n", i_len);
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
            if (long_out) {
                printf("      NAA 6, IEEE Company_id: 0x%x\n", c_id);
                printf("      Vendor Specific Identifier: 0x%" PRIx64
                       "\n", vsei);
                vsei = sg_get_unaligned_be64(ip + 8);
                printf("      Vendor Specific Identifier Extension: "
                       "0x%" PRIx64 "\n", vsei);
                printf("      [0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("]\n");
            } else {
                printf("      0x");
                for (m = 0; m < 16; ++m)
                    printf("%02x", (unsigned int)ip[m]);
                printf("\n");
            }
            break;
        default:
            pr2serr("      << unexpected NAA [0x%x]>>\n", naa);
            dStrHexErr((const char *)ip, i_len, 0);
            break;
        }
        break;
    case 4: /* Relative target port */
        if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
            pr2serr("      << expected binary code_set, target port "
                    "association, length 4>>\n");
            dStrHexErr((const char *)ip, i_len, 0);
            break;
        }
        d_id = sg_get_unaligned_be16(ip + 2);
        printf("      Relative target port: 0x%x\n", d_id);
        break;
    case 5: /* (primary) Target port group */
        if ((1 != c_set) || (1 != assoc) || (4 != i_len)) {
            pr2serr("      << expected binary code_set, target port "
                    "association, length 4>>\n");
            dStrHexErr((const char *)ip, i_len, 0);
            break;
        }
        d_id = sg_get_unaligned_be16(ip + 2);
        printf("      Target port group: 0x%x\n", d_id);
        break;
    case 6: /* Logical unit group */
        if ((1 != c_set) || (0 != assoc) || (4 != i_len)) {
            pr2serr("      << expected binary code_set, logical unit "
                    "association, length 4>>\n");
            dStrHexErr((const char *)ip, i_len, 0);
            break;
        }
        d_id = sg_get_unaligned_be16(ip + 2);
        printf("      Logical unit group: 0x%x\n", d_id);
        break;
    case 7: /* MD5 logical unit identifier */
        if ((1 != c_set) || (0 != assoc)) {
            pr2serr("      << expected binary code_set, logical unit "
                    "association>>\n");
            dStrHexErr((const char *)ip, i_len, 0);
            break;
        }
        printf("      MD5 logical unit identifier:\n");
        dStrHex((const char *)ip, i_len, 0);
        break;
    case 8: /* SCSI name string */
        if (3 != c_set) {
            pr2serr("      << expected UTF-8 code_set>>\n");
            dStrHexErr((const char *)ip, i_len, 0);
            break;
        }
        if (! (strncmp((const char *)ip, "eui.", 4) ||
               strncmp((const char *)ip, "EUI.", 4) ||
               strncmp((const char *)ip, "naa.", 4) ||
               strncmp((const char *)ip, "NAA.", 4) ||
               strncmp((const char *)ip, "iqn.", 4))) {
            pr2serr("      << expected name string prefix>>\n");
            dStrHexErr((const char *)ip, i_len, -1);
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
            pr2serr("      >>>> unexpected protocol indentifier: %s\n"
                    "           with Protocol specific port "
                    "identifier\n",
                    sg_get_trans_proto_str(p_id, sizeof(b), b));
        break;
    default: /* reserved */
        pr2serr("      reserved designator=0x%x\n", desig_type);
        dStrHexErr((const char *)ip, i_len, 0);
        break;
    }
}

/* Prints outs device identification designators selected by association,
   designator type and/or code set. */
static int
decode_dev_ids(const char * print_if_found, unsigned char * buff, int len,
               int m_assoc, int m_desig_type, int m_code_set, int long_out,
               int quiet)
{
    int assoc, i_len, c_set, piv, p_id, desig_type;
    int printed, off, u;
    const unsigned char * ucp;

    if (quiet)
        return decode_dev_ids_quiet(buff, len, m_assoc, m_desig_type,
                                    m_code_set);
    if ( buff[2] != 0 ) {
        if (m_assoc == VPD_ASSOC_LU)
            decode_designation_descriptor( buff, 16, 0, 1, 0, m_assoc, 3,
                                           long_out, 0);
        return 0;
    }
    off = -1;
    printed = 0;
    while ((u = sg_vpd_dev_id_iter(buff, len, &off, m_assoc, m_desig_type,
                                   m_code_set)) == 0) {
        ucp = buff + off;
        i_len = ucp[3];
        if ((off + i_len + 4) > len) {
            pr2serr("    VPD page error: designator length longer than\n"
                    "     remaining response length=%d\n", (len - off));
            return SG_LIB_CAT_MALFORMED;
        }
        assoc = ((ucp[1] >> 4) & 0x3);
        if (print_if_found && (0 == printed)) {
            printed = 1;
            printf("  %s:\n", print_if_found);
        }
        if (NULL == print_if_found)
            printf("  %s:\n", assoc_arr[assoc]);
        p_id = ((ucp[0] >> 4) & 0xf);
        c_set = (ucp[0] & 0xf);
        piv = ((ucp[1] & 0x80) ? 1 : 0);
        desig_type = (ucp[1] & 0xf);
        decode_designation_descriptor(ucp + 4, i_len, p_id, c_set, piv, assoc,
                                      desig_type, long_out, 0);
    }
    if (-2 == u) {
        pr2serr("VPD page error: short designator around offset %d\n", off);
        return SG_LIB_CAT_MALFORMED;
    }
    return 0;
}

/* Transport IDs are initiator port identifiers, typically other than the
   initiator port issuing a SCSI command. */
static void
decode_transport_id(const char * leadin, unsigned char * ucp, int len)
{
    int format_code, proto_id, num, k;
    uint64_t ull;
    int bump;

    for (k = 0, bump= 24; k < len; k += bump, ucp += bump) {
        if ((len < 24) || (0 != (len % 4)))
            printf("%sTransport Id short or not multiple of 4 "
                   "[length=%d]:\n", leadin, len);
        else
            printf("%sTransport Id of initiator:\n", leadin);
        format_code = ((ucp[0] >> 6) & 0x3);
        proto_id = (ucp[0] & 0xf);
        switch (proto_id) {
        case TPROTO_FCP: /* Fibre channel */
            printf("%s  FCP-2 World Wide Name:\n", leadin);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            dStrHex((const char *)&ucp[8], 8, -1);
            bump = 24;
            break;
        case TPROTO_SPI:        /* Scsi Parallel Interface */
            printf("%s  Parallel SCSI initiator SCSI address: 0x%x\n",
                   leadin, sg_get_unaligned_be16(ucp + 2));
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            printf("%s  relative port number (of corresponding target): "
                   "0x%x\n", leadin, sg_get_unaligned_be16(ucp + 6));
            bump = 24;
            break;
        case TPROTO_SSA:
            printf("%s  SSA (transport id not defined):\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case TPROTO_1394: /* IEEE 1394 */
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
            num = sg_get_unaligned_be16(ucp + 2);
            if (0 == format_code)
                printf("name: %.*s\n", num, &ucp[4]);
            else if (1 == format_code)
                printf("world wide unique port id: %.*s\n", num, &ucp[4]);
            else {
                pr2serr("  [Unexpected format code: %d]\n", format_code);
                dStrHexErr((const char *)ucp, num + 4, 0);
            }
            bump = (((num + 4) < 24) ? 24 : num + 4);
            break;
        case TPROTO_SAS:
            ull = sg_get_unaligned_be64(ucp + 4);
            printf("%s  SAS address: 0x%" PRIx64 "\n", leadin, ull);
            if (0 != format_code)
                printf("%s  [Unexpected format code: %d]\n", leadin,
                       format_code);
            bump = 24;
            break;
        case TPROTO_ADT:
            printf("%s  ADT:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case TPROTO_ATA: /* ATA/ATAPI */
            printf("%s  ATAPI:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case TPROTO_UAS:
            printf("%s  UAS:\n", leadin);
            printf("%s  format code: %d\n", leadin, format_code);
            dStrHex((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        case TPROTO_SOP:
            printf("%s  SOP ", leadin);
            num = sg_get_unaligned_be16(ucp + 2);
            if (0 == format_code)
                printf("Routing ID: 0x%x\n", num);
            else {
                pr2serr("  [Unexpected format code: %d]\n", format_code);
                dStrHexErr((const char *)ucp, 24, 0);
            }
            bump = 24;
            break;
        case TPROTO_NONE:
            pr2serr("%s  No specified protocol\n", leadin);
            /* dStrHexErr((const char *)ucp, ((len > 24) ? 24 : len), 0); */
            bump = 24;
            break;
        default:
            pr2serr("%s  unknown protocol id=0x%x  format_code=%d\n", leadin,
                    proto_id, format_code);
            dStrHexErr((const char *)ucp, ((len > 24) ? 24 : len), 0);
            bump = 24;
            break;
        }
    }
}

/* VPD_EXT_INQ    Extended Inquiry VPD */
static void
decode_x_inq_vpd(unsigned char * b, int len, int do_hex, int do_long,
                 int protect)
{
    int n;

    if (len < 7) {
        pr2serr("Extended INQUIRY data VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex) {
        dStrHex((const char *)b, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    if (do_long) {
        n = (b[4] >> 6) & 0x3;
        printf("  ACTIVATE_MICROCODE=%d", n);
        if (1 == n)
            printf(" [before final WRITE BUFFER]\n");
        else if (2 == n)
            printf(" [after power on or hard reset]\n");
        else
            printf("\n");
        n = (b[4] >> 3) & 0x7;
        printf("  SPT=%d", n);
        if (protect) {
            switch (n)
            {
            case 0:
                printf(" [protection type 1 supported]\n");
                break;
            case 1:
                printf(" [protection types 1 and 2 supported]\n");
                break;
            case 2:
                printf(" [protection type 2 supported]\n");
                break;
            case 3:
                printf(" [protection types 1 and 3 supported]\n");
                break;
            case 4:
                printf(" [protection type 3 supported]\n");
                break;
            case 5:
                printf(" [protection types 2 and 3 supported]\n");
                break;
            case 6:
                printf(" [see Supported block lengths and protection types "
                       "VPD page]\n");
                break;
            case 7:
                printf(" [protection types 1, 2 and 3 supported]\n");
                break;
            default:
                printf("\n");
                break;
            }
        } else
            printf("\n");
        printf("  GRD_CHK=%d\n", !!(b[4] & 0x4));
        printf("  APP_CHK=%d\n", !!(b[4] & 0x2));
        printf("  REF_CHK=%d\n", !!(b[4] & 0x1));
        printf("  UASK_SUP=%d\n", !!(b[5] & 0x20));
        printf("  GROUP_SUP=%d\n", !!(b[5] & 0x10));
        printf("  PRIOR_SUP=%d\n", !!(b[5] & 0x8));
        printf("  HEADSUP=%d\n", !!(b[5] & 0x4));
        printf("  ORDSUP=%d\n", !!(b[5] & 0x2));
        printf("  SIMPSUP=%d\n", !!(b[5] & 0x1));
        printf("  WU_SUP=%d\n", !!(b[6] & 0x8));
        printf("  CRD_SUP=%d\n", !!(b[6] & 0x4));
        printf("  NV_SUP=%d\n", !!(b[6] & 0x2));
        printf("  V_SUP=%d\n", !!(b[6] & 0x1));
        printf("  NO_PI_CHK=%d\n", !!(b[7] & 0x10));    /* spc5r02 */
        printf("  P_I_I_SUP=%d\n", !!(b[7] & 0x10));
        printf("  LUICLR=%d\n", !!(b[7] & 0x1));
        printf("  R_SUP=%d\n", !!(b[8] & 0x10));
        printf("  HSSRELEF=%d\n", !!(b[8] & 0x2));      /* spc5r02 */
        printf("  CBCS=%d\n", !!(b[8] & 0x1));  /* obsolete in spc5r01 */
        printf("  Multi I_T nexus microcode download=%d\n", b[9] & 0xf);
        printf("  Extended self-test completion minutes=%d\n",
               sg_get_unaligned_be16(b + 10));
        printf("  POA_SUP=%d\n", !!(b[12] & 0x80));     /* spc4r32 */
        printf("  HRA_SUP=%d\n", !!(b[12] & 0x40));     /* spc4r32 */
        printf("  VSA_SUP=%d\n", !!(b[12] & 0x20));     /* spc4r32 */
        printf("  Maximum supported sense data length=%d\n",
               b[13]); /* spc4r34 */
        return;
    }
    printf("  ACTIVATE_MICROCODE=%d SPT=%d GRD_CHK=%d APP_CHK=%d "
           "REF_CHK=%d\n", ((b[4] >> 6) & 0x3), ((b[4] >> 3) & 0x7),
           !!(b[4] & 0x4), !!(b[4] & 0x2), !!(b[4] & 0x1));
    printf("  UASK_SUP=%d GROUP_SUP=%d PRIOR_SUP=%d HEADSUP=%d ORDSUP=%d "
           "SIMPSUP=%d\n", !!(b[5] & 0x20), !!(b[5] & 0x10), !!(b[5] & 0x8),
           !!(b[5] & 0x4), !!(b[5] & 0x2), !!(b[5] & 0x1));
    printf("  WU_SUP=%d CRD_SUP=%d NV_SUP=%d V_SUP=%d\n",
           !!(b[6] & 0x8), !!(b[6] & 0x4), !!(b[6] & 0x2), !!(b[6] & 0x1));
    /* CBCS, capability-based command security, obsolete in spc5r01 */
    printf("  P_I_I_SUP=%d LUICLR=%d R_SUP=%d CBCS=%d\n",
           !!(b[7] & 0x10), !!(b[7] & 0x1), !!(b[8] & 0x10), !!(b[8] & 0x1));
    printf("  Multi I_T nexus microcode download=%d\n", b[9] & 0xf);
    printf("  Extended self-test completion minutes=%d\n",
           sg_get_unaligned_be16(b + 10));    /* spc4r27 */
    printf("  POA_SUP=%d HRA_SUP=%d VSA_SUP=%d\n",      /* spc4r32 */
           !!(b[12] & 0x80), !!(b[12] & 0x40), !!(b[12] & 0x20));
    printf("  Maximum supported sense data length=%d\n", b[13]); /* spc4r34 */
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
    for ( ; len > 5; len -= 6, buff += 6) {
        printf("    IEEE Company_id: 0x%06x, vendor specific extension "
               "id: 0x%06x\n", sg_get_unaligned_be24(buff),
               sg_get_unaligned_be24(buff + 3));
    }
}

/* VPD_ATA_INFO */
static void
decode_ata_info_vpd(unsigned char * buff, int len, int do_long, int do_hex)
{
    char b[80];
    int num, is_be;
    const char * cp;
    const char * ata_transp;

    if (len < 36) {
        pr2serr("ATA information VPD page length too short=%d\n", len);
        return;
    }
    if (do_hex && (2 != do_hex)) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
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
    ata_transp = (0x34 == buff[36]) ? "SATA" : "PATA";
    if (do_long) {
        printf("  Device signature [%s] (in hex):\n", ata_transp);
        dStrHex((const char *)buff + 36, 20, 0);
    } else
        printf("  Device signature indicates %s transport\n", ata_transp);
    if (len < 60)
        return;
    is_be = sg_is_big_endian();
    if ((0xec == buff[56]) || (0xa1 == buff[56])) {
        cp = (0xa1 == buff[56]) ? "PACKET " : "";
        printf("  ATA command IDENTIFY %sDEVICE response summary:\n", cp);
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
        if (do_long)
            printf("  ATA command IDENTIFY %sDEVICE response in hex:\n", cp);
    } else if (do_long)
        printf("  ATA command 0x%x got following response:\n",
               (unsigned int)buff[56]);
    if (len < 572)
        return;
    if (2 == do_hex)
        dStrHex((const char *)(buff + 60), 512, 0);
    else if (do_long)
        dWordHex((const unsigned short *)(buff + 60), 256, 0, is_be);
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

static const char * power_unit_arr[] =
{
    "Gigawatts",
    "Megawatts",
    "Kilowatts",
    "Watts",
    "Milliwatts",
    "Microwatts",
    "Unit reserved",
    "Unit reserved",
};

/* VPD_POWER_CONSUMPTION */
static void
decode_power_consumption_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump;
    unsigned char * ucp;
    unsigned int value;

    if ((1 == do_hex) || (do_hex > 2)) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 1 : -1);
        return;
    }
    if (len < 4) {
        pr2serr("Power consumption VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        bump = 4;
        if ((k + bump) > len) {
            pr2serr("Power consumption VPD page, short descriptor "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (do_hex > 1)
            dStrHex((const char *)ucp, 4, 1);
        else {
            value = sg_get_unaligned_be16(ucp + 2);
            printf("  Power consumption identifier: 0x%x", ucp[0]);
            if (value >= 1000 && (ucp[1] & 0x7) > 0)
                printf("    Maximum power consumption: %d.%03d %s\n",
                       value / 1000, value % 1000,
                       power_unit_arr[(ucp[1] & 0x7) - 1]);
            else
                printf("    Maximum power consumption: %d %s\n",
                       value, power_unit_arr[ucp[1] & 0x7]);
        }
    }
}

/* This is xcopy(LID4) related: "ROD" == Representation Of Data
 * Used by VPD_3PARTY_COPY */
static void
decode_rod_descriptor(const unsigned char * buff, int len)
{
    const unsigned char * ucp = buff;
    int k, bump;

    for (k = 0; k < len; k += bump, ucp += bump) {
        bump = sg_get_unaligned_be16(ucp + 2) + 4;
        switch (ucp[0]) {
            case 0:
                /* Block ROD device type specific descriptor */
                printf("  Optimal block ROD length granularity: %d\n",
                       sg_get_unaligned_be16(ucp + 6));
                printf("  Maximum Bytes in block ROD: %" PRIu64 "\n",
                       sg_get_unaligned_be64(ucp + 8));
                printf("  Optimal Bytes in block ROD transfer: %" PRIu64 "\n",
                       sg_get_unaligned_be64(ucp + 16));
                printf("  Optimal Bytes to token per segment: %" PRIu64 "\n",
                       sg_get_unaligned_be64(ucp + 24));
                printf("  Optimal Bytes from token per segment:"
                       " %" PRIu64 "\n", sg_get_unaligned_be64(ucp + 32));
                break;
            case 1:
                /* Stream ROD device type specific descriptor */
                printf("  Maximum Bytes in stream ROD: %" PRIu64 "\n",
                       sg_get_unaligned_be64(ucp + 8));
                printf("  Optimal Bytes in stream ROD transfer:"
                       " %" PRIu64 "\n", sg_get_unaligned_be64(ucp + 16));
                break;
            case 3:
                /* Copy manager ROD device type specific descriptor */
                printf("  Maximum Bytes in processor ROD: %" PRIu64 "\n",
                       sg_get_unaligned_be64(ucp + 8));
                printf("  Optimal Bytes in processor ROD transfer:"
                       " %" PRIu64 "\n", sg_get_unaligned_be64(ucp + 16));
                break;
            default:
                printf("  Unhandled descriptor (format %d, device type %d)\n",
                       ucp[0] >> 5, ucp[0] & 0x1F);
                break;
        }
    }
}

struct tpc_desc_type {
    unsigned char code;
    const char * name;
};

static struct tpc_desc_type tpc_desc_arr[] = {
    {0x0, "block -> stream"},
    {0x1, "stream -> block"},
    {0x2, "block -> block"},
    {0x3, "stream -> stream"},
    {0x4, "inline -> stream"},
    {0x5, "embedded -> stream"},
    {0x6, "stream -> discard"},
    {0x7, "verify CSCD"},
    {0x8, "block<o> -> stream"},
    {0x9, "stream -> block<o>"},
    {0xa, "block<o> -> block<o>"},
    {0xb, "block -> stream & application_client"},
    {0xc, "stream -> block & application_client"},
    {0xd, "block -> block & application_client"},
    {0xe, "stream -> stream&application_client"},
    {0xf, "stream -> discard&application_client"},
    {0x10, "filemark -> tape"},
    {0x11, "space -> tape"},            /* obsolete: spc5r02 */
    {0x12, "locate -> tape"},           /* obsolete: spc5r02 */
    {0x13, "<i>tape -> <i>tape"},
    {0x14, "register persistent reservation key"},
    {0x15, "third party persistent reservation source I_T nexus"},
    {0x16, "<i>block -> <i>block"},
    {0x17, "positioning -> tape"},      /* this and next added spc5r02 */
    {0x18, "<loi>tape -> <loi>tape"},   /* loi: logical object identifier */
    {0xbe, "ROD <- block range(n)"},
    {0xbf, "ROD <- block range(1)"},
    {0xe0, "CSCD: FC N_Port_Name"},
    {0xe1, "CSCD: FC N_Port_ID"},
    {0xe2, "CSCD: FC N_Port_ID with N_Port_Name, checking"},
    {0xe3, "CSCD: Parallel interface: I_T"},
    {0xe4, "CSCD: Identification Descriptor"},
    {0xe5, "CSCD: IPv4"},
    {0xe6, "CSCD: Alias"},
    {0xe7, "CSCD: RDMA"},
    {0xe8, "CSCD: IEEE 1394 EUI-64"},
    {0xe9, "CSCD: SAS SSP"},
    {0xea, "CSCD: IPv6"},
    {0xeb, "CSCD: IP copy service"},
    {0xfe, "CSCD: ROD"},
    {0xff, "CSCD: extension"},
    {0x0, NULL},
};

static const char *
get_tpc_desc_name(unsigned char code)
{
    const struct tpc_desc_type * dtp;

    for (dtp = tpc_desc_arr; dtp->name; ++dtp) {
        if (code == dtp->code)
            return dtp->name;
    }
    return "";
}

struct tpc_rod_type {
    uint32_t type;
    const char * name;
};

static struct tpc_rod_type tpc_rod_arr[] = {
    {0x0, "copy manager internal"},
    {0x10000, "access upon reference"},
    {0x800000, "point in time copy - default"},
    {0x800001, "point in time copy - change vulnerable"},
    {0x800002, "point in time copy - persistent"},
    {0x80ffff, "point in time copy - any"},
    {0xffff0001, "block device zero"},
    {0x0, NULL},
};

static const char *
get_tpc_rod_name(uint32_t rod_type)
{
    const struct tpc_rod_type * rtp;

    for (rtp = tpc_rod_arr; rtp->name; ++rtp) {
        if (rod_type == rtp->type)
            return rtp->name;
    }
    return "";
}

struct cscd_desc_id_t {
    uint16_t id;
    const char * name;
};

static struct cscd_desc_id_t cscd_desc_id_arr[] = {
    /* only values higher than 0x7ff are listed */
    {0xc000, "copy src or dst null LU, pdt=0"},
    {0xc001, "copy src or dst null LU, pdt=1"},
    {0xf800, "copy src or dst in ROD token"},
    {0xffff, "copy src or dst is copy manager LU"},
    {0x0, NULL},
};

static const char *
get_cscd_desc_id_name(uint16_t cscd_desc_id)
{
    const struct cscd_desc_id_t * cdip;

    for (cdip = cscd_desc_id_arr; cdip->name; ++cdip) {
        if (cscd_desc_id == cdip->id)
            return cdip->name;
    }
    return "";
}

/* VPD_3PARTY_COPY [3PC, third party copy] */
static void
decode_3party_copy_vpd(unsigned char * buff, int len, int do_hex, int verbose)
{
    int j, k, m, bump, desc_type, desc_len, sa_len;
    unsigned int u;
    const unsigned char * ucp;
    const char * cp;
    uint64_t ull;
    char b[80];

    if (len < 4) {
        pr2serr("Third-party Copy VPD page length too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        desc_type = sg_get_unaligned_be16(ucp);
        desc_len = sg_get_unaligned_be16(ucp + 2);
        if (verbose)
            printf("Descriptor type=%d [0x%x] , len %d\n", desc_type,
                   desc_type, desc_len);
        bump = 4 + desc_len;
        if ((k + bump) > len) {
            pr2serr("Third-party Copy VPD page, short descriptor length=%d, "
                    "left=%d\n", bump, (len - k));
            return;
        }
        if (0 == desc_len)
            continue;
        if (2 == do_hex)
            dStrHex((const char *)ucp + 4, desc_len, 1);
        else if (do_hex > 2)
            dStrHex((const char *)ucp, bump, 1);
        else {
            switch (desc_type) {
            case 0x0000:    /* Required if POPULATE TOKEN (or friend) used */
                printf(" Block Device ROD Token Limits:\n");
                printf("  Maximum Range Descriptors: %d\n",
                       sg_get_unaligned_be16(ucp + 10));
                u = sg_get_unaligned_be32(ucp + 12);
                printf("  Maximum Inactivity Timeout: %u seconds\n", u);
                u = sg_get_unaligned_be32(ucp + 16);
                printf("  Default Inactivity Timeout: %u seconds\n", u);
                ull = sg_get_unaligned_be64(ucp + 20);
                printf("  Maximum Token Transfer Size: %" PRIu64 "\n", ull);
                ull = sg_get_unaligned_be64(ucp + 28);
                printf("  Optimal Transfer Count: %" PRIu64 "\n", ull);
                break;
            case 0x0001:    /* Mandatory (SPC-4) */
                printf(" Supported Commands:\n");
                j = 0;
                while (j < ucp[4]) {
                    sa_len = ucp[6 + j];
                    for (m = 0; m < sa_len; ++m) {
                        sg_get_opcode_sa_name(ucp[5 + j], ucp[7 + j + m],
                                              0, sizeof(b), b);
                        printf("  %s\n", b);
                    }
                    j += sa_len + 2;
                }
                break;
            case 0x0004:
                printf(" Parameter Data:\n");
                printf("  Maximum CSCD Descriptor Count: %d\n",
                       sg_get_unaligned_be16(ucp + 8));
                printf("  Maximum Segment Descriptor Count: %d\n",
                       sg_get_unaligned_be16(ucp + 10));
                u = sg_get_unaligned_be32(ucp + 12);
                printf("  Maximum Descriptor List Length: %u\n", u);
                u = sg_get_unaligned_be32(ucp + 16);
                printf("  Maximum Inline Data Length: %u\n", u);
                break;
            case 0x0008:
                printf(" Supported Descriptors:\n");
                for (j = 0; j < ucp[4]; j++) {
                    cp = get_tpc_desc_name(ucp[5 + j]);
                    if (strlen(cp) > 0)
                        printf("  %s [0x%x]\n", cp, ucp[5 + j]);
                    else
                        printf("  0x%x\n", ucp[5 + j]);
                }
                break;
            case 0x000C:
                printf(" Supported CSCD IDs (above 0x7ff):\n");
                for (j = 0; j < sg_get_unaligned_be16(ucp + 4); j += 2) {
                    u = sg_get_unaligned_be16(ucp + 6 + j);
                    cp = get_cscd_desc_id_name(u);
                    if (strlen(cp) > 0)
                        printf("  %s [0x%04x]\n", cp, u);
                    else
                        printf("  0x%04x\n", u);
                }
                break;
            case 0x0106:
                printf(" ROD Token Features:\n");
                printf("  Remote Tokens: %d\n", ucp[4] & 0x0f);
                u = sg_get_unaligned_be32(ucp + 16);
                printf("  Minimum Token Lifetime: %u seconds\n", u);
                u = sg_get_unaligned_be32(ucp + 20);
                printf("  Maximum Token Lifetime: %u seconds\n", u);
                u = sg_get_unaligned_be32(ucp + 24);
                printf("  Maximum Token inactivity timeout: %d\n", u);
                decode_rod_descriptor(ucp + 48,
                                      sg_get_unaligned_be16(ucp + 46));
                break;
            case 0x0108:
                printf(" Supported ROD Token and ROD Types:\n");
                for (j = 0; j < sg_get_unaligned_be16(ucp + 6); j+= 64) {
                    u = sg_get_unaligned_be32(ucp + 8 + j);
                    cp = get_tpc_rod_name(u);
                    if (strlen(cp) > 0)
                        printf("  ROD Type: %s [0x%x]\n", cp, u);
                    else
                        printf("  ROD Type: 0x%x\n", u);
                    printf("    Internal: %s\n",
                           (ucp[8 + j + 4] & 0x80) ? "yes" : "no");
                    printf("    Token In: %s\n",
                           (ucp[8 + j + 4] & 0x02) ? "yes" : "no");
                    printf("    Token Out: %s\n",
                           (ucp[8 + j + 4] & 0x01) ? "yes" : "no");
                    printf("    Preference: %d\n",
                           sg_get_unaligned_be16(ucp + 8 + j + 6));
                }
                break;
            case 0x8001:    /* Mandatory (SPC-4) */
                printf(" General Copy Operations:\n");
                u = sg_get_unaligned_be32(ucp + 4);
                printf("  Total Concurrent Copies: %u\n", u);
                u = sg_get_unaligned_be32(ucp + 8);
                printf("  Maximum Identified Concurrent Copies: %u\n", u);
                u = sg_get_unaligned_be32(ucp + 12);
                printf("  Maximum Segment Length: %u\n", u);
                ull = (1 << ucp[16]); /* field is power of 2 */
                printf("  Data Segment Granularity: %" PRIu64 "\n", ull);
                ull = (1 << ucp[17]);
                printf("  Inline Data Granularity: %" PRIu64 "\n", ull);
                break;
            case 0x9101:
                printf(" Stream Copy Operations:\n");
                u = sg_get_unaligned_be32(ucp + 4);
                printf("  Maximum Stream Device Transfer Size: %u\n", u);
                break;
            case 0xC001:
                printf(" Held Data:\n");
                u = sg_get_unaligned_be32(ucp + 4);
                printf("  Held Data Limit: %u\n", u);
                ull = (1 << ucp[8]);
                printf("  Held Data Granularity: %" PRIu64 "\n", ull);
                break;
            default:
                pr2serr("Unexpected type=%d\n", desc_type);
                dStrHexErr((const char *)ucp, bump, 1);
                break;
            }
        }
    }
}

/* VPD_PROTO_LU */
static void
decode_proto_lu_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, bump, rel_port, desc_len, proto;
    unsigned char * ucp;

    if (1 == do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    if (len < 4) {
        pr2serr("Protocol-specific logical unit information VPD page length "
                "too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        rel_port = sg_get_unaligned_be16(ucp);
        printf("  Relative port=%d\n", rel_port);
        proto = ucp[2] & 0xf;
        desc_len = sg_get_unaligned_be16(ucp + 6);
        bump = 8 + desc_len;
        if ((k + bump) > len) {
            pr2serr("Protocol-specific logical unit information VPD page, "
                    "short descriptor length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (0 == desc_len)
            continue;
        if (2 == do_hex)
            dStrHex((const char *)ucp + 8, desc_len, 1);
        else if (do_hex > 2)
            dStrHex((const char *)ucp, bump, 1);
        else {
            switch (proto) {
            case TPROTO_SAS:
                printf("    Protocol identifier: SAS\n");
                printf("    TLR control supported: %d\n", !!(ucp[8] & 0x1));
                break;
            default:
                pr2serr("Unexpected proto=%d\n", proto);
                dStrHexErr((const char *)ucp, bump, 1);
                break;
            }
        }
    }
}

/* VPD_PROTO_PORT */
static void
decode_proto_port_vpd(unsigned char * buff, int len, int do_hex)
{
    int k, j, bump, rel_port, desc_len, proto;
    unsigned char * ucp;
    unsigned char * pidp;

    if (1 == do_hex) {
        dStrHex((const char *)buff, len, 0);
        return;
    }
    if (len < 4) {
        pr2serr("Protocol-specific port information VPD page length too "
                "short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += bump, ucp += bump) {
        rel_port = sg_get_unaligned_be16(ucp);
        printf("  Relative port=%d\n", rel_port);
        proto = ucp[2] & 0xf;
        desc_len = sg_get_unaligned_be16(ucp + 6);
        bump = 8 + desc_len;
        if ((k + bump) > len) {
            pr2serr("Protocol-specific port VPD page, short descriptor "
                    "length=%d, left=%d\n", bump, (len - k));
            return;
        }
        if (0 == desc_len)
            continue;
        if (2 == do_hex)
            dStrHex((const char *)ucp + 8, desc_len, 1);
        else if (do_hex > 2)
            dStrHex((const char *)ucp, bump, 1);
        else {
            switch (proto) {
            case TPROTO_SAS:    /* page added in spl3r02 */
                printf("    power disable supported (pwr_d_s)=%d\n",
                       !!(ucp[3] & 0x1));       /* added spl3r03 */
                pidp = ucp + 8;
                for (j = 0; j < desc_len; j += 4, pidp += 4)
                    printf("      phy id=%d, ssp persistent capable=%d\n",
                           pidp[1], (0x1 & pidp[2]));
                break;
            default:
                pr2serr("Unexpected proto=%d\n", proto);
                dStrHexErr((const char *)ucp, bump, 1);
                break;
            }
        }
    }
}

/* VPD_BLOCK_LIMITS sbc */
/* VPD_SA_DEV_CAP ssc */
/* VPD_OSD_INFO osd */
static void
decode_b0_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    unsigned int u;
    unsigned char b[4];

    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        if (len < 16) {
            pr2serr("Block limits VPD page length too short=%d\n", len);
            return;
        }
        printf("  Write same non-zero (WSNZ): %d\n", !!(buff[4] & 0x1));
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
            printf("  Maximum prefetch length: %u blocks\n", u);
            /* was 'Maximum prefetch transfer length' prior to sbc3r33 */
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
            memcpy(b, buff + 32, 4);
            b[0] &= 0x7f;       /* mask off top bit */
            u = sg_get_unaligned_be32(b);
            printf("  Unmap granularity alignment: %u\n", u);
            /* added in sbc3r26 */
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
        if (len > 56) {     /* added in sbc4r04 */
            u = sg_get_unaligned_be32(buff + 56);
            printf("  Maximum atomic transfer length with atomic boundary: "
                   "%u\n", u);
            u = sg_get_unaligned_be32(buff + 60);
            printf("  Maximum atomic boundary size: %u\n", u);
        }
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        printf("  WORM=%d\n", !!(buff[4] & 0x1));
        break;
    case PDT_OSD:
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHexErr((const char *)buff, len, 0);
        break;
    }
}

static const char * product_type_arr[] =
{
    "Not specified",
    "CFast",
    "CompactFlash",
    "MemoryStick",
    "MultiMediaCard",
    "Secure Digital Card (SD)",
    "XQD",
    "Universal Flash Storage Card (UFS)",
};

/* VPD_BLOCK_DEV_CHARS sbc */
/* VPD_MAN_ASS_SN ssc */
/* VPD_SECURITY_TOKEN osd */
static void
decode_b1_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    unsigned int u, k;

    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
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
        u = buff[6];
        k = sizeof(product_type_arr) / sizeof(product_type_arr[0]);
        if (u < k)
            printf("  Product type: %s\n", product_type_arr[u]);
        else if (u < 0xf0)
            printf("  Product type: Reserved [0x%x]\n", u);
        else
            printf("  Product type: Vendor specific [0x%x]\n", u);
        printf("  WABEREQ=%d\n", (buff[7] >> 6) & 0x3);
        printf("  WACEREQ=%d\n", (buff[7] >> 4) & 0x3);
        u = buff[7] & 0xf;
        printf("  Nominal form factor");
        switch (u) {
        case 0:
            printf(" not reported\n");
            break;
        case 1:
            printf(": 5.25 inch\n");
            break;
        case 2:
            printf(": 3.5 inch\n");
            break;
        case 3:
            printf(": 2.5 inch\n");
            break;
        case 4:
            printf(": 1.8 inch\n");
            break;
        case 5:
            printf(": less then 1.8 inch\n");
            break;
        default:
            printf(": reserved\n");
            break;
        }
        printf("  ZONED=%d\n", (buff[8] >> 4) & 0x3);       /* sbc4r04 */
        printf("  FUAB=%d\n", !!(buff[8] & 0x2));
        printf("  VBULS=%d\n", !!(buff[8] & 0x1));
        break;
    case PDT_TAPE: case PDT_MCHANGER: case PDT_ADC:
        printf("  Manufacturer-assigned serial number: %.*s\n",
               len - 4, buff + 4);
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHexErr((const char *)buff, len, 0);
        break;
    }
}

/* VPD_LB_PROVISIONING */
static int
decode_block_lb_prov_vpd(unsigned char * b, int len)
{
    int dp;

    if (len < 4) {
        pr2serr("Logical block provisioning page too short=%d\n", len);
        return SG_LIB_CAT_MALFORMED;
    }
    printf("  Unmap command supported (LBPU): %d\n", !!(0x80 & b[5]));
    printf("  Write same (16) with unmap bit supported (LBWS): %d\n",
           !!(0x40 & b[5]));
    printf("  Write same (10) with unmap bit supported (LBWS10): %d\n",
           !!(0x20 & b[5]));
    printf("  Logical block provisioning read zeros (LBPRZ): %d\n",
           !!(0x4 & b[5]));
    printf("  Anchored LBAs supported (ANC_SUP): %d\n", !!(0x2 & b[5]));
    dp = !!(b[5] & 0x1);
    printf("  Threshold exponent: %d\n", b[4]);
    printf("  Descriptor present (DP): %d\n", dp);
    printf("  Provisioning type: %d\n", b[6] & 0x7);
    if (dp) {
        const unsigned char * ucp;
        int i_len, p_id, c_set, piv, assoc, desig_type;

        ucp = b + 8;
        i_len = ucp[3];
        if (0 == i_len) {
            pr2serr("Logical block provisioning page provisioning group "
                    "descriptor too short=%d\n", i_len);
            return 0;
        }
        printf("  Provisioning group descriptor\n");
        p_id = ((ucp[0] >> 4) & 0xf);
        c_set = (ucp[0] & 0xf);
        piv = ((ucp[1] & 0x80) ? 1 : 0);
        assoc = ((ucp[1] >> 4) & 0x3);
        desig_type = (ucp[1] & 0xf);
        decode_designation_descriptor(ucp, i_len, p_id, c_set, piv, assoc,
                                      desig_type, 0, 1);
    }
    return 0;
}

/* VPD_SUP_BLOCK_LENS  0xb4 */
static void
decode_sup_block_lens_vpd(unsigned char * buff, int len)
{
    int k;
    unsigned int u;
    unsigned char * ucp;

    if (len < 4) {
        pr2serr("Supported block lengths and protection types VPD page "
                "length too short=%d\n", len);
        return;
    }
    len -= 4;
    ucp = buff + 4;
    for (k = 0; k < len; k += 8, ucp += 8) {
        u = sg_get_unaligned_be32(ucp);
        printf("  Logical block length: %u\n", u);
        printf("    P_I_I_SUP: %d\n", !!(ucp[4] & 0x40));
        printf("    NO_PI_CHK: %d\n", !!(ucp[4] & 0x8));  /* sbc4r05 */
        printf("    GRD_CHK: %d\n", !!(ucp[4] & 0x4));
        printf("    APP_CHK: %d\n", !!(ucp[4] & 0x2));
        printf("    REF_CHK: %d\n", !!(ucp[4] & 0x1));
        printf("    T3PS_SUP: %d\n", !!(ucp[5] & 0x8));
        printf("    T2PS_SUP: %d\n", !!(ucp[5] & 0x4));
        printf("    T1PS_SUP: %d\n", !!(ucp[5] & 0x2));
        printf("    T0PS_SUP: %d\n", !!(ucp[5] & 0x1));
    }
}

/* VPD_BLOCK_DEV_C_EXTENS  0xb5 */
static void
decode_block_dev_char_ext_vpd(unsigned char * b, int len)
{
    if (len < 16) {
        pr2serr("Block device characteristics extension VPD page "
                "length too short=%d\n", len);
        return;
    }
    printf("  Utilization type: ");
    switch (b[5]) {
    case 1:
        printf("Combined writes and reads");
        break;
    case 2:
        printf("Writes only");
        break;
    case 3:
        printf("Separate writes and reads");
        break;
    default:
        printf("Reserved");
        break;
    }
    printf(" [0x%x]\n", b[5]);
    printf("  Utilization units: ");
    switch (b[6]) {
    case 2:
        printf("megabytes");
        break;
    case 3:
        printf("gigabytes");
        break;
    case 4:
        printf("terabytes");
        break;
    case 5:
        printf("petabytes");
        break;
    case 6:
        printf("exabytes");
        break;
    default:
        printf("Reserved");
        break;
    }
    printf(" [0x%x]\n", b[6]);
    printf("  Utilization interval: ");
    switch (b[7]) {
    case 0xa:
        printf("per day");
        break;
    case 0xe:
        printf("per year");
        break;
    default:
        printf("Reserved");
        break;
    }
    printf(" [0x%x]\n", b[7]);
    printf("  Utilization B: %u\n", sg_get_unaligned_be32(b + 8));
    printf("  Utilization A: %u\n", sg_get_unaligned_be32(b + 12));
}

/* VPD_TA_SUPPORTED */
static int
decode_tapealert_supported_vpd(unsigned char * b, int len)
{
    if (len < 12) {
        pr2serr("TapeAlert supported flags length too short=%d\n", len);
        return SG_LIB_CAT_MALFORMED;
    }
    printf("  Flag01h: %d  02h: %d  03h: %d  04h: %d  05h: %d  06h: %d  "
           "07h: %d  08h: %d\n", !!(b[4] & 0x80), !!(b[4] & 0x40),
           !!(b[4] & 0x20), !!(b[4] & 0x10), !!(b[4] & 0x8), !!(b[4] & 0x4),
           !!(b[4] & 0x2), !!(b[4] & 0x1));
    printf("  Flag09h: %d  0ah: %d  0bh: %d  0ch: %d  0dh: %d  0eh: %d  "
           "0fh: %d  10h: %d\n", !!(b[5] & 0x80), !!(b[5] & 0x40),
           !!(b[5] & 0x20), !!(b[5] & 0x10), !!(b[5] & 0x8), !!(b[5] & 0x4),
           !!(b[5] & 0x2), !!(b[5] & 0x1));
    printf("  Flag11h: %d  12h: %d  13h: %d  14h: %d  15h: %d  16h: %d  "
           "17h: %d  18h: %d\n", !!(b[6] & 0x80), !!(b[6] & 0x40),
           !!(b[6] & 0x20), !!(b[6] & 0x10), !!(b[6] & 0x8), !!(b[6] & 0x4),
           !!(b[6] & 0x2), !!(b[6] & 0x1));
    printf("  Flag19h: %d  1ah: %d  1bh: %d  1ch: %d  1dh: %d  1eh: %d  "
           "1fh: %d  20h: %d\n", !!(b[7] & 0x80), !!(b[7] & 0x40),
           !!(b[7] & 0x20), !!(b[7] & 0x10), !!(b[7] & 0x8), !!(b[7] & 0x4),
           !!(b[7] & 0x2), !!(b[7] & 0x1));
    printf("  Flag21h: %d  22h: %d  23h: %d  24h: %d  25h: %d  26h: %d  "
           "27h: %d  28h: %d\n", !!(b[8] & 0x80), !!(b[8] & 0x40),
           !!(b[8] & 0x20), !!(b[8] & 0x10), !!(b[8] & 0x8), !!(b[8] & 0x4),
           !!(b[8] & 0x2), !!(b[8] & 0x1));
    printf("  Flag29h: %d  2ah: %d  2bh: %d  2ch: %d  2dh: %d  2eh: %d  "
           "2fh: %d  30h: %d\n", !!(b[9] & 0x80), !!(b[9] & 0x40),
           !!(b[9] & 0x20), !!(b[9] & 0x10), !!(b[9] & 0x8), !!(b[9] & 0x4),
           !!(b[9] & 0x2), !!(b[9] & 0x1));
    printf("  Flag31h: %d  32h: %d  33h: %d  34h: %d  35h: %d  36h: %d  "
           "37h: %d  38h: %d\n", !!(b[10] & 0x80), !!(b[10] & 0x40),
           !!(b[10] & 0x20), !!(b[10] & 0x10), !!(b[10] & 0x8),
           !!(b[10] & 0x4), !!(b[10] & 0x2), !!(b[10] & 0x1));
    printf("  Flag39h: %d  3ah: %d  3bh: %d  3ch: %d  3dh: %d  3eh: %d  "
           "3fh: %d  40h: %d\n", !!(b[11] & 0x80), !!(b[11] & 0x40),
           !!(b[11] & 0x20), !!(b[11] & 0x10), !!(b[11] & 0x8),
           !!(b[11] & 0x4), !!(b[11] & 0x2), !!(b[11] & 0x1));
    return 0;
}

/* VPD_LB_PROVISIONING sbc */
/* VPD_TA_SUPPORTED ssc */
static void
decode_b2_vpd(unsigned char * buff, int len, int do_hex, int pdt)
{
    if (do_hex) {
        dStrHex((const char *)buff, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        decode_block_lb_prov_vpd(buff, len);
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        decode_tapealert_supported_vpd(buff, len);
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHexErr((const char *)buff, len, 0);
        break;
    }
}

/* VPD_REFERRALS sbc */
/* VPD_AUTOMATION_DEV_SN ssc */
static void
decode_b3_vpd(unsigned char * b, int len, int do_hex, int pdt)
{
    char obuff[DEF_ALLOC_LEN];
    unsigned int u;

    if (do_hex) {
        dStrHex((const char *)b, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        if (len < 16) {
            pr2serr("Referrals VPD page length too short=%d\n", len);
            break;
        }
        u = sg_get_unaligned_be32(b + 8);
        printf("  User data segment size: %u\n", u);
        u = sg_get_unaligned_be32(b + 12);
        printf("  User data segment multiplier: %u\n", u);
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        memset(obuff, 0, sizeof(obuff));
        len -= 4;
        if (len >= (int)sizeof(obuff))
            len = sizeof(obuff) - 1;
        memcpy(obuff, b + 4, len);
        printf("  Automation device serial number: %s\n", obuff);
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHexErr((const char *)b, len, 0);
        break;
    }
}

/* VPD_SUP_BLOCK_LENS sbc */
/* VPD_DTDE_ADDRESS ssc */
static void
decode_b4_vpd(unsigned char * b, int len, int do_hex, int pdt)
{
    int k;

    if (do_hex) {
        dStrHex((const char *)b, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        decode_sup_block_lens_vpd(b, len);
        break;
    case PDT_TAPE: case PDT_MCHANGER:
        printf("  Data transfer device element address: 0x");
        for (k = 4; k < len; ++k)
            printf("%02x", (unsigned int)b[k]);
        printf("\n");
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHexErr((const char *)b, len, 0);
        break;
    }
}

/* VPD_BLOCK_DEV_C_EXTENS sbc */
static void
decode_b5_vpd(unsigned char * b, int len, int do_hex, int pdt)
{
    if (do_hex) {
        dStrHex((const char *)b, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    switch (pdt) {
    case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
        decode_block_dev_char_ext_vpd(b, len);
        break;
    default:
        pr2serr("  Unable to decode pdt=0x%x, in hex:\n", pdt);
        dStrHexErr((const char *)b, len, 0);
        break;
    }
}

/* VPD_ZBC_DEV_CHARS  sbc or zbc */
static void
decode_zbdc_vpd(unsigned char * b, int len, int do_hex)
{
    uint32_t u;

    if (do_hex) {
        dStrHex((const char *)b, len, (1 == do_hex) ? 0 : -1);
        return;
    }
    if (len < 64) {
        pr2serr("Zoned block device characteristics VPD page length too "
                "short=%d\n", len);
        return;
    }
    printf("  URSWRZ type: %d\n", !!(b[4] & 0x1));
    u = sg_get_unaligned_be32(b + 8);
    printf("  Optimal number of open sequential write preferred zones: ");
    if (0xffffffff == u)
        printf("not reported\n");
    else
        printf("%" PRIu32 "\n", u);
    u = sg_get_unaligned_be32(b + 12);
    printf("  Optimal number of non-sequentially written sequential write "
           "preferred zones: ");
    if (0xffffffff == u)
        printf("not reported\n");
    else
        printf("%" PRIu32 "\n", u);
    u = sg_get_unaligned_be32(b + 16);
    printf("  Maximum number of open sequential write required zones: ");
    if (0xffffffff == u)
        printf("no limit\n");
    else
        printf("%" PRIu32 "\n", u);
}

/* Returns 0 if successful */
static int
svpd_unable_to_decode(int sg_fd, struct opts_t * op, int subvalue, int off)
{
    int len, res;
    int alloc_len = op->maxlen;
    unsigned char * rp;

    rp = rsp_buff + off;
    if ((! op->do_hex) && (! op->do_raw))
        printf("Only hex output supported\n");
    if ((!op->do_raw) && (op->do_hex < 2)) {
        if (subvalue)
            printf("VPD page code=0x%.2x, subvalue=0x%.2x:\n", op->num_vpd,
                   subvalue);
        else if (op->num_vpd >= 0)
            printf("VPD page code=0x%.2x:\n", op->num_vpd);
        else
            printf("VPD page code=%d:\n", op->num_vpd);
    }
    if (sg_fd >= 0) {
        if (0 == alloc_len)
            alloc_len = DEF_ALLOC_LEN;
    }

    res = vpd_fetch_page_from_dev(sg_fd, rp, op->num_vpd, alloc_len,
                                  op->verbose, &len);
    if (0 == res) {
        if (op->do_raw)
            dStrRaw((const char *)rp, len);
        else {
            if (op->do_hex > 1)
                dStrHex((const char *)rp, len, -1);
            else if (VPD_ASCII_OP_DEF == op->num_vpd)
                dStrHex((const char *)rp, len, 0);
            else
                dStrHex((const char *)rp, len, (op->do_long ? 0 : 1));
        }
        return 0;
    } else {
        if (op->num_vpd >= 0)
            pr2serr("fetching VPD page code=0x%.2x: failed\n", op->num_vpd);
        else
            pr2serr("fetching VPD page code=%d: failed\n", op->num_vpd);
        return res;
    }
}

/* Returns 0 if successful, else see sg_ll_inquiry() */
static int
svpd_decode_t10(int sg_fd, struct opts_t * op, int subvalue, int off)
{
    int len, pdt, num, k, resid, alloc_len, pn, vb, allow_name, long_notquiet;
    int res = 0;
    char b[48];
    const struct svpd_values_name_t * vnp;
    char obuff[DEF_ALLOC_LEN];
    unsigned char * rp;

    pn = op->num_vpd;
    vb = op->verbose;
    long_notquiet = op->do_long && (! op->do_quiet);
    if (op->do_raw || (op->do_quiet && (! op->do_long) && (! op->do_all)) ||
        (op->do_hex >= 3))
        allow_name = 0;
    else
        allow_name = 1;
    rp = rsp_buff + off;
    switch(pn) {
    case VPD_NO_RATHER_STD_INQ:    /* -2 (want standard inquiry response) */
        if (sg_fd >= 0) {
            if (op->maxlen > 0)
                alloc_len = op->maxlen;
            else if (op->do_long)
                alloc_len = DEF_ALLOC_LEN;
            else
                alloc_len = 36;
            res = pt_inquiry(sg_fd, 0, 0, rp, alloc_len, &resid, 1, vb);
        } else {
            alloc_len = op->maxlen;
            resid = 0;
            res = 0;
        }
        if (0 == res) {
            alloc_len -= resid;
            if (op->do_raw)
                dStrRaw((const char *)rp, alloc_len);
            else if (op->do_hex) {
                if (! op->do_quiet && (op->do_hex < 3))
                    printf("Standard Inquiry reponse:\n");
                dStrHex((const char *)rp, alloc_len,
                        (1 == op->do_hex) ? 0 : -1);
            } else
                decode_std_inq(rp, alloc_len, vb);
            return 0;
        }
        break;
    case VPD_SUPPORTED_VPDS:    /* 0x0 */
        if (allow_name)
            printf("Supported VPD pages VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else if (op->do_hex)
                dStrHex((const char *)rp, len, (1 == op->do_hex) ? 0 : -1);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                num = rp[3];
                if (num > (len - 4))
                    num = (len - 4);
                for (k = 0; k < num; ++k) {
                    pn = rp[4 + k];
                    vnp = sdp_get_vpd_detail(pn, -1, pdt);
                    if (vnp) {
                        if (op->do_long)
                            printf("  0x%02x  %s [%s]\n", pn, vnp->name,
                                   vnp->acron);
                        else
                            printf("  %s [%s]\n", vnp->name, vnp->acron);
                    } else if (op->vend_prod_num >= 0) {
                        vnp = svpd_find_vendor_by_num(pn, op->vend_prod_num);
                        if (vnp) {
                            if (op->do_long)
                                printf("  0x%02x  %s [%s]\n", pn, vnp->name,
                                       vnp->acron);
                            else
                                printf("  %s [%s]\n", vnp->name, vnp->acron);
                        } else
                            printf("  0x%x\n", pn);
                    } else
                        printf("  0x%x\n", pn);
                }
            }
            return 0;
        }
        break;
    case VPD_UNIT_SERIAL_NUM:   /* 0x80 */
        if (allow_name)
            printf("Unit serial number VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else if (op->do_hex)
                dStrHex((const char *)rp, len, (1 == op->do_hex) ? 0 : -1);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                memset(obuff, 0, sizeof(obuff));
                len -= 4;
                if (len >= (int)sizeof(obuff))
                    len = sizeof(obuff) - 1;
                memcpy(obuff, rp + 4, len);
                printf("  Unit serial number: %s\n", obuff);
            }
            return 0;
        }
        break;
    case VPD_DEVICE_ID:         /* 0x83 */
        if (allow_name)
            printf("Device Identification VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else if (op->do_hex)
                dStrHex((const char *)rp, len, (1 == op->do_hex) ? 0 : -1);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_id_vpd(rp, len, subvalue, op->do_long, op->do_quiet);
            }
            return 0;
        }
        break;
    case VPD_SOFTW_INF_ID:      /* 0x84 */
        if (allow_name)
            printf("Software interface identification VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_softw_inf_id(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_MAN_NET_ADDR:      /* 0x85 */
        if (allow_name)
            printf("Management network addresses VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else
                decode_net_man_vpd(rp, len, op->do_hex);
            return 0;
        }
        break;
    case VPD_EXT_INQ:           /* 0x86 */
        if (allow_name)
            printf("extended INQUIRY data VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                int protect = 0;
                struct sg_simple_inquiry_resp sir;

                if ((sg_fd >= 0) && long_notquiet) {
                    res = sg_simple_inquiry(sg_fd, &sir, 0, vb);
                    if (res) {
                        if (op->verbose)
                            pr2serr("%s: sg_simple_inquiry() failed, "
                                    "res=%d\n", __func__, res);
                    } else
                        protect = sir.byte_5 & 0x1;  /* SPC-3 and later */
                }
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_x_inq_vpd(rp, len, op->do_hex, long_notquiet, protect);
            }
            return 0;
        }
        break;
    case VPD_MODE_PG_POLICY:    /* 0x87 */
        if (allow_name)
            printf("Mode page policy VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_mode_policy_vpd(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_SCSI_PORTS:        /* 0x88 */
        if (allow_name)
            printf("SCSI Ports VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_scsi_ports_vpd(rp, len, op->do_hex, op->do_long,
                                      op->do_quiet);
            }
            return 0;
        }
        break;
    case VPD_ATA_INFO:          /* 0x89 */
        if (allow_name)
            printf("ATA information VPD page:\n");
        alloc_len = op->maxlen ? op->maxlen : VPD_ATA_INFO_LEN;
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, alloc_len, vb, &len);
        if (0 == res) {
            if ((2 == op->do_raw) || (3 == op->do_hex)) {  /* for hdparm */
                if (len < (60 + 512))
                    pr2serr("ATA_INFO VPD page len (%d) less than expected "
                            "572\n", len);
                else
                    dWordHex((const unsigned short *)(rp + 60), 256, -2,
                             sg_is_big_endian());
            }
            else if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_ata_info_vpd(rp, len, long_notquiet, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_POWER_CONDITION:          /* 0x8a */
        if (allow_name)
            printf("Power condition VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_power_condition(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_POWER_CONSUMPTION:    /* 0x8d */
        if (allow_name)
            printf("Power consumption VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_power_consumption_vpd(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_3PARTY_COPY:   /* 0x8f */
        if (allow_name)
            printf("Third party copy VPD page:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else if (1 == op->do_hex)
                dStrHex((const char *)rp, len, 0);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_3party_copy_vpd(rp, len, op->do_hex, vb);
            }
            return 0;
        }
        break;
    case VPD_PROTO_LU:          /* 0x90 */
        if (allow_name)
            printf("Protocol-specific logical unit information:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                pdt = rsp_buff[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_proto_lu_vpd(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case VPD_PROTO_PORT:        /* 0x91 */
        if (allow_name)
            printf("Protocol-specific port information:\n");
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_proto_port_vpd(rp, len, op->do_hex);
            }
            return 0;
        }
        break;
    case 0xb0:  /* depends on pdt */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (allow_name) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                    printf("Block limits VPD page (SBC):\n");
                    break;
                case PDT_TAPE: case PDT_MCHANGER:
                    printf("Sequential access device capabilities VPD page "
                           "(SSC):\n");
                    break;
                case PDT_OSD:
                    printf("OSD information VPD page (OSD):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                pdt = rp[0] & 0x1f;
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b0_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3))
            printf("VPD page=0xb0\n");
        break;
    case 0xb1:  /* depends on pdt */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (allow_name) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                    printf("Block device characteristics VPD page (SBC):\n");
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
                    printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b1_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3))
            printf("VPD page=0xb1\n");
        break;
    case 0xb2:          /* VPD page depends on pdt */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (allow_name) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                    printf("Logical block provisioning VPD page (SBC):\n");
                    break;
                case PDT_TAPE: case PDT_MCHANGER:
                    printf("TapeAlert supported flags VPD page (SSC):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b2_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3))
            printf("VPD page=0xb2\n");
        break;
    case 0xb3:          /* VPD page depends on pdt */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (allow_name) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                    printf("Referrals VPD page (SBC):\n");
                    break;
                case PDT_TAPE: case PDT_MCHANGER:
                    printf("Automation device serial number VPD page "
                           "(SSC):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b3_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3))
            printf("VPD page=0xb3\n");
        break;
    case 0xb4:          /* VPD page depends on pdt */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (allow_name) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                    printf("Supported block lengths and protection types "
                           "VPD page (SBC):\n");
                    break;
                case PDT_TAPE: case PDT_MCHANGER:
                    printf("Data transfer device element address (SSC):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b4_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3))
            printf("VPD page=0xb4\n");
        break;
    case 0xb5:          /* VPD page depends on pdt */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (allow_name) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                    printf("Block device characteristics extension VPD page "
                           "(SBC):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_b5_vpd(rp, len, op->do_hex, pdt);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3))
            printf("VPD page=0xb5\n");
        break;
    case VPD_ZBC_DEV_CHARS:       /* 0xb6 for both pdt=0 and pdt=0x14 */
        res = vpd_fetch_page_from_dev(sg_fd, rp, pn, op->maxlen, vb, &len);
        if (0 == res) {
            pdt = rp[0] & 0x1f;
            if (allow_name) {
                switch (pdt) {
                case PDT_DISK: case PDT_WO: case PDT_OPTICAL: case PDT_ZBC:
                    printf("Zoned block device characteristics VPD page "
                           "(SBC, ZBC):\n");
                    break;
                default:
                    printf("VPD page=0x%x, pdt=0x%x:\n", pn, pdt);
                    break;
                }
            }
            if (op->do_raw)
                dStrRaw((const char *)rp, len);
            else {
                if (vb || long_notquiet)
                    printf("   [PQual=%d  Peripheral device type: %s]\n",
                           (rp[0] & 0xe0) >> 5,
                           sg_get_pdt_str(pdt, sizeof(b), b));
                decode_zbdc_vpd(rp, len, op->do_hex);
            }
            return 0;
        } else if ((! op->do_raw) && (! op->do_quiet) && (op->do_hex < 3))
            printf("VPD page=0xb5\n");
        break;
    default:
        return SG_LIB_SYNTAX_ERROR;
    }
    return res;
}

static int
svpd_decode_all(int sg_fd, struct opts_t * op)
{
    int k, res, rlen, n, pn;
    int max_pn = 255;
    int any_err = 0;
    unsigned char vpd0_buff[512];
    unsigned char * rp = vpd0_buff;

    if (op->num_vpd > 0)
        max_pn = op->num_vpd;
    if (sg_fd >= 0) {
        res = vpd_fetch_page_from_dev(sg_fd, rp, VPD_SUPPORTED_VPDS,
                                      op->maxlen, op->verbose, &rlen);
        if (res) {
            if (SG_LIB_CAT_ABORTED_COMMAND == res)
                pr2serr("%s: VPD page 0, aborted command\n", __func__);
            else if (res) {
                char b[80];

                sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
                pr2serr("%s: fetching VPD page 0 failed: %s\n", __func__, b);
            }
            return res;
        }
        n = (rp[2] >> 8) + rp[3];
        if (n > (rlen - 4)) {
            if (op->verbose)
                pr2serr("%s: rlen=%d > page0 size=%d\n", __func__, rlen,
                        n + 4);
            n = (rlen - 4);
        }
        for (k = 0; k < n; ++k) {
            pn = rp[4 + k];
            if (pn > max_pn)
                continue;
            op->num_vpd = pn;
            if (op->do_long)
                printf("[0x%x] ", pn);

            res = svpd_decode_t10(sg_fd, op, 0, 0);
            if (SG_LIB_SYNTAX_ERROR == res) {
                res = svpd_decode_vendor(sg_fd, op, 0);
                if (SG_LIB_SYNTAX_ERROR == res)
                    res = svpd_unable_to_decode(sg_fd, op, 0, 0);
            }
            if (SG_LIB_CAT_ABORTED_COMMAND == res)
                pr2serr("fetching VPD page failed, aborted command\n");
            else if (res) {
                char b[80];

                sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
                pr2serr("fetching VPD page failed: %s\n", b);
            }
            if (res)
                any_err = res;
        }
        res = any_err;
    } else {    /* input is coming from --inhex=FN */
        int bump, off;
        int in_len = op->maxlen;
        int prev_pn = -1;

        rp = rsp_buff;
        for (k = 0, off = 0; off < in_len; ++k, off += bump) {
            rp = rsp_buff + off;
            pn = rp[1];
            bump = sg_get_unaligned_be16(rp + 2) + 4;
            if ((off + bump) > in_len) {
                pr2serr("%s: page 0x%x size (%d) exceeds buffer\n", __func__,
                        pn, bump);
                bump = in_len - off;
            }
            if (pn <= prev_pn) {
                pr2serr("%s: prev_pn=0x%x, this pn=0x%x, not ascending so "
                        "exit\n", __func__, prev_pn, pn);
                break;
            }
            prev_pn = pn;
            op->num_vpd = pn;
            if (pn > max_pn) {
                if (op->verbose > 2)
                    pr2serr("%s: skipping as this pn=0x%x exceeds "
                            "max_pn=0x%x\n", __func__, pn, max_pn);
                continue;
            }
            if (op->do_long)
                printf("[0x%x] ", pn);

            res = svpd_decode_t10(-1, op, 0, off);
            if (SG_LIB_SYNTAX_ERROR == res) {
                res = svpd_decode_vendor(-1, op, off);
                if (SG_LIB_SYNTAX_ERROR == res)
                    res = svpd_unable_to_decode(-1, op, 0, off);
            }
        }
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    int sg_fd, c, res, matches;
    const struct svpd_values_name_t * vnp;
    const char * cp;
    int inhex_len = 0;
    int ret = 0;
    int subvalue = 0;
    int page_pdt = -1;
    struct opts_t opts;
    struct opts_t * op;

    op = &opts;
    memset(&opts, 0, sizeof(opts));
    op->vend_prod_num = -1;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aehHiI:lm:M:p:qrvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            ++op->do_all;
            break;
        case 'e':
            ++op->do_enum;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            ++op->do_ident;
            break;
        case 'I':
            if (op->inhex_fn) {
                pr2serr("only one '--inhex=' option permitted\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            } else
                op->inhex_fn = optarg;
            break;
        case 'l':
            ++op->do_long;
            break;
        case 'm':
            op->maxlen = sg_get_num(optarg);
            if ((op->maxlen < 0) || (op->maxlen > MX_ALLOC_LEN)) {
                pr2serr("argument to '--maxlen' should be %d or less\n",
                        MX_ALLOC_LEN);
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'M':
            if (op->vend_prod) {
                pr2serr("only one '--vendor=' option permitted\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            } else
                op->vend_prod = optarg;
            break;
        case 'p':
            if (op->page_str) {
                pr2serr("only one '--page=' option permitted\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            } else
                op->page_str = optarg;
            break;
        case 'q':
            ++op->do_quiet;
            break;
        case 'r':
            ++op->do_raw;
            break;
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            pr2serr("version: %s\n", version_str);
            return 0;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
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
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (op->do_enum) {
        if (op->device_name)
            pr2serr("Device name %s ignored when --enumerate given\n",
                    op->device_name);
        if (op->vend_prod) {
            if (isdigit(op->vend_prod[0])) {
                op->vend_prod_num = sg_get_num_nomult(op->vend_prod);
                if ((op->vend_prod_num < 0) || (op->vend_prod_num > 10)) {
                    pr2serr("Bad vendor/product number after '--vendor=' "
                            "option\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                op->vend_prod_num = svpd_find_vp_num_by_acron(op->vend_prod);
                if (op->vend_prod_num < 0) {
                    pr2serr("Bad vendor/product acronym after '--vendor=' "
                            "option\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            svpd_enumerate_vendor(op->vend_prod_num);
            return 0;
        }
        if (op->page_str) {
            if ((0 == strcmp("-1", op->page_str)) ||
                (0 == strcmp("-2", op->page_str)))
                op->num_vpd = VPD_NO_RATHER_STD_INQ;
            else if (isdigit(op->page_str[0])) {
                op->num_vpd = sg_get_num_nomult(op->page_str);
                if ((op->num_vpd < 0) || (op->num_vpd > 255)) {
                    pr2serr("Bad page code value after '-p' option\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                pr2serr("with --enumerate only search using VPD page "
                        "numbers\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            matches = count_standard_vpds(op->num_vpd);
            if (0 == matches)
                matches = svpd_count_vendor_vpds(op->num_vpd,
                                                 op->vend_prod_num);
            if (0 == matches)
                printf("No matches found for VPD page number 0x%x\n",
                       op->num_vpd);
        } else {        /* enumerate standard then vendor VPD pages */
            printf("Standard VPD pages:\n");
            enumerate_vpds(1, 1);
        }
        return 0;
    }
    if (op->page_str) {
        if ((0 == strcmp("-1", op->page_str)) ||
            (0 == strcmp("-2", op->page_str)))
            op->num_vpd = VPD_NO_RATHER_STD_INQ;
        else if (isalpha(op->page_str[0])) {
            vnp = sdp_find_vpd_by_acron(op->page_str);
            if (NULL == vnp) {
                vnp = svpd_find_vendor_by_acron(op->page_str);
                if (NULL == vnp) {
                    pr2serr("abbreviation doesn't match a VPD page\n");
                    printf("Available standard VPD pages:\n");
                    enumerate_vpds(1, 1);
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            op->num_vpd = vnp->value;
            subvalue = vnp->subvalue;
            op->vend_prod_num = subvalue;
            page_pdt = vnp->pdt;
        } else {
            cp = strchr(op->page_str, ',');
            if (cp && op->vend_prod) {
                pr2serr("the --page=pg,vp and the --vendor=vp forms overlap, "
                        "choose one or the other\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->num_vpd = sg_get_num_nomult(op->page_str);
            if ((op->num_vpd < 0) || (op->num_vpd > 255)) {
                pr2serr("Bad page code value after '-p' option\n");
                printf("Available standard VPD pages:\n");
                enumerate_vpds(1, 1);
                return SG_LIB_SYNTAX_ERROR;
            }
            if (cp) {
                if (isdigit(*(cp + 1)))
                    op->vend_prod_num = sg_get_num_nomult(cp + 1);
                else
                    op->vend_prod_num = svpd_find_vp_num_by_acron(cp + 1);
                if ((op->vend_prod_num < 0) || (op->vend_prod_num > 255)) {
                    pr2serr("Bad vendor/product acronym after comma in '-p' "
                            "option\n");
                    if (op->vend_prod_num < 0)
                        svpd_enumerate_vendor(-1);
                    return SG_LIB_SYNTAX_ERROR;
                }
                subvalue = op->vend_prod_num;
            } else if (op->vend_prod) {
                if (isdigit(op->vend_prod[0]))
                    op->vend_prod_num = sg_get_num_nomult(op->vend_prod);
                else
                    op->vend_prod_num =
                        svpd_find_vp_num_by_acron(op->vend_prod);
                if ((op->vend_prod_num < 0) || (op->vend_prod_num > 255)) {
                    pr2serr("Bad vendor/product acronym after '--vendor=' "
                            "option\n");
                    svpd_enumerate_vendor(-1);
                    return SG_LIB_SYNTAX_ERROR;
                }
                subvalue = op->vend_prod_num;
            }
        }
    } else if (op->vend_prod) {
        if (isdigit(op->vend_prod[0]))
            op->vend_prod_num = sg_get_num_nomult(op->vend_prod);
        else
            op->vend_prod_num = svpd_find_vp_num_by_acron(op->vend_prod);
        if ((op->vend_prod_num < 0) || (op->vend_prod_num > 255)) {
            pr2serr("Bad vendor/product acronym after '--vendor=' "
                    "option\n");
            svpd_enumerate_vendor(-1);
            return SG_LIB_SYNTAX_ERROR;
        }
        subvalue = op->vend_prod_num;
    }
    if (op->inhex_fn) {
        if (op->device_name) {
            pr2serr("Cannot have both a DEVICE and --inhex= option\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        if (f2hex_arr(op->inhex_fn, op->do_raw, 0, rsp_buff, &inhex_len,
                      sizeof(rsp_buff)))
            return SG_LIB_FILE_ERROR;
        op->do_raw = 0;         /* don't want raw on output with --inhex= */
        if ((NULL == op->page_str) && (0 == op->do_all)) {
            /* may be able to deduce VPD page */
            if ((0x2 == (0xf & rsp_buff[3])) && (rsp_buff[2] > 2)) {
                if (op->verbose)
                    pr2serr("Guessing from --inhex= this is a standard "
                            "INQUIRY\n");
                if (page_pdt < 0)
                    page_pdt = 0x1f & rsp_buff[0];
            } else if (rsp_buff[2] <= 2) {
                if (op->verbose)
                    pr2serr("Guessing from --inhex this is VPD page 0x%x\n",
                            rsp_buff[1]);
                op->num_vpd = rsp_buff[1];
                if (page_pdt < 0)
                    page_pdt = 0x1f & rsp_buff[0];
            } else {
                if (op->num_vpd > 0x80) {
                    op->num_vpd = rsp_buff[1];
                    if (page_pdt < 0)
                        page_pdt = 0x1f & rsp_buff[0];
                    if (op->verbose)
                        pr2serr("Guessing from --inhex this is VPD page "
                                "0x%x\n", rsp_buff[1]);
                } else {
                    op->num_vpd = VPD_NO_RATHER_STD_INQ;
                    if (op->verbose)
                        pr2serr("page number unclear from --inhex, hope "
                                "it's a standard INQUIRY response\n");
                }
            }
        }
    } else if (NULL == op->device_name) {
        pr2serr("No DEVICE argument given\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (op->do_raw && op->do_hex) {
        pr2serr("Can't do hex and raw at the same time\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->do_ident) {
        op->num_vpd = VPD_DEVICE_ID;
        if (op->do_ident > 1) {
            if (0 == op->do_long)
                ++op->do_quiet;
            subvalue = VPD_DI_SEL_LU;
        }
    }
    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if (op->inhex_fn) {
        if ((0 == op->maxlen) || (inhex_len < op->maxlen))
            op->maxlen = inhex_len;
        if (op->do_all)
            res = svpd_decode_all(-1, op);
        else {
            res = svpd_decode_t10(-1, op, subvalue, 0);
            if (SG_LIB_SYNTAX_ERROR == res) {
                res = svpd_decode_vendor(-1, op, 0);
                if (SG_LIB_SYNTAX_ERROR == res)
                    res = svpd_unable_to_decode(-1, op, subvalue, 0);
            }
        }
        return res;
    }

    if ((sg_fd = sg_cmds_open_device(op->device_name, 1 /* ro */,
                                     op->verbose)) < 0) {
        pr2serr("error opening file: %s: %s\n", op->device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (op->do_all)
        ret = svpd_decode_all(sg_fd, op);
    else {
        memset(rsp_buff, 0, sizeof(rsp_buff));

        res = svpd_decode_t10(sg_fd, op, subvalue, 0);
        if (SG_LIB_SYNTAX_ERROR == res) {
            res = svpd_decode_vendor(sg_fd, op, 0);
                if (SG_LIB_SYNTAX_ERROR == res)
            res = svpd_unable_to_decode(sg_fd, op, subvalue, 0);
        }
        if (SG_LIB_CAT_ABORTED_COMMAND == res)
            pr2serr("fetching VPD page failed, aborted command\n");
        else if (res) {
            char b[80];

            sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
            pr2serr("fetching VPD page failed: %s\n", b);
        }
        ret = res;
    }
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

/*
 * Copyright (c) 2006-2022 Luben Tuikov and Douglas Gilbert.
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
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_pt.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/*
 * This utility issues the SCSI READ BUFFER(10 or 16) command to the given
 * device.
 */

static const char * version_str = "1.35 20220217";      /* spc6r06 */

#ifndef SG_READ_BUFFER_10_CMD
#define SG_READ_BUFFER_10_CMD 0x3c
#define SG_READ_BUFFER_10_CMDLEN 10
#endif
#ifndef SG_READ_BUFFER_16_CMD
#define SG_READ_BUFFER_16_CMD 0x9b
#define SG_READ_BUFFER_16_CMDLEN 16
#endif

#define MODE_HEADER_DATA        0
#define MODE_VENDOR             1
#define MODE_DATA               2
#define MODE_DESCRIPTOR         3
#define MODE_ECHO_BUFFER        0x0A
#define MODE_ECHO_BDESC         0x0B
#define MODE_READ_MICROCODE_ST  0x0F
#define MODE_EN_EX_ECHO         0x1A
#define MODE_ERR_HISTORY        0x1C

#define MAX_DEF_INHEX_LEN 8192
#define SENSE_BUFF_LEN  64      /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60      /* 60 seconds */
#define DEF_RESPONSE_LEN 4      /* increased to 64 for MODE_ERR_HISTORY */


static struct option long_options[] = {
        {"16", no_argument, 0, 'L'},
        {"eh_code", required_argument, 0, 'e'},
        {"eh-code", required_argument, 0, 'e'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"id", required_argument, 0, 'i'},
        {"inhex", required_argument, 0, 'I'},
        {"length", required_argument, 0, 'l'},
        {"long", no_argument, 0, 'L'},
        {"mode", required_argument, 0, 'm'},
        {"no_output", no_argument, 0, 'N'},
        {"no-output", no_argument, 0, 'N'},
        {"offset", required_argument, 0, 'o'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"specific", required_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},   /* sentinel */
};

struct opts_t {
    bool do_long;
    bool o_readonly;
    bool do_raw;
    bool eh_code_given;
    bool no_output;
    bool rb_id_given;
    bool rb_len_given;
    bool rb_mode_given;
    bool verbose_given;
    bool version_given;
    int sg_fd;
    int do_help;
    int do_hex;
    int eh_code;
    int rb_id;
    int rb_len;
    int rb_mode;
    int rb_mode_sp;
    int verbose;
    uint64_t rb_offset;
    const char * device_name;
    const char * inhex_name;
};


static void
usage()
{
    pr2serr("Usage: sg_read_buffer [--16] [--eh_code=EHC] [--help] [--hex] "
            "[--id=ID]\n"
            "                      [--inhex=FN] [--length=LEN] [--long] "
            "[--mode=MO]\n"
            "                      [--no_output] [--offset=OFF] [--raw] "
            "[--readonly]\n"
            "                      [--specific=MS] [--verbose] [--version] "
            "DEVICE\n"
            "  where:\n"
            "    --16|-L             issue READ BUFFER(16) (def: 10)\n"
            "    --eh_code=EHC|-e EHC    same as '-m eh -i EHC' where "
            "EHC is the\n"
            "                            error history code\n"
            "    --help|-h           print out usage message\n"
            "    --hex|-H            print output in hex\n"
            "    --id=ID|-i ID       buffer identifier (0 (default) to 255)\n"
            "    --inhex=FN|-I FN    filename FN contains hex data to "
            "decode\n"
            "                        rather than DEVICE. If --raw given "
            "then binary\n"
            "    --length=LEN|-l LEN    length in bytes to read (def: 4, "
            "64 for eh)\n"
            "    --long|-L           issue READ BUFFER(16) (def: 10)\n"
            "    --mode=MO|-m MO     read buffer mode, MO is number or "
            "acronym (def: 0)\n"
            "    --no_output|-N      perform the command then exit\n"
            "    --offset=OFF|-o OFF    buffer offset (unit: bytes, def: 0)\n"
            "    --raw|-r            output response in binary to stdout\n"
            "    --readonly|-R       open DEVICE read-only (def: read-write)\n"
            "    --specific=MS|-S MS    mode specific value; 3 bit field (0 "
            "to 7)\n"
            "    --verbose|-v        increase verbosity\n"
            "    --version|-V        print version string and exit\n\n"
            "Performs a SCSI READ BUFFER (10 or 16) command. Use '-m xxx' to "
            "list\navailable modes. Some responses are decoded, others are "
            "output in hex.\n"
           );
}


static struct mode_s {
        const char *mode_string;
        int   mode;
        const char *comment;
} modes[] = {
        { "hd",         MODE_HEADER_DATA, "combined header and data"},
        { "vendor",     MODE_VENDOR,    "vendor specific"},
        { "data",       MODE_DATA,      "data"},
        { "desc",       MODE_DESCRIPTOR, "descriptor"},
        { "echo",       MODE_ECHO_BUFFER, "read data from echo buffer "
          "(spc-2)"},
        { "echo_desc",  MODE_ECHO_BDESC, "echo buffer descriptor (spc-2)"},
        { "rd_microc_st",  MODE_READ_MICROCODE_ST, "read microcode status "
          "(spc-5)"},
        { "en_ex",      MODE_EN_EX_ECHO,
          "enable expander communications protocol and echo buffer (spc-3)"},
        { "err_hist|eh",   MODE_ERR_HISTORY, "error history (spc-4)"},
        { NULL,   999, NULL},   /* end sentinel */
};


static void
print_modes(void)
{
    const struct mode_s *mp;

    pr2serr("The modes parameter argument can be numeric (hex or decimal)\n"
            "or symbolic:\n");
    for (mp = modes; mp->mode_string; ++mp) {
        pr2serr(" %2d (0x%02x)  %-16s%s\n", mp->mode, mp->mode,
                mp->mode_string, mp->comment);
    }
}

/* Invokes a SCSI READ BUFFER(10) command (spc5r02).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_read_buffer_10(void * resp, int * residp, bool noisy,
                    const struct opts_t * op)
{
    int ret, res, sense_cat;
    uint8_t rb10_cb[SG_READ_BUFFER_10_CMDLEN] =
          {SG_READ_BUFFER_10_CMD, 0, 0, 0,  0, 0, 0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;
    struct sg_pt_base * ptvp;

    rb10_cb[1] = (uint8_t)(op->rb_mode & 0x1f);
    if (op->rb_mode_sp)
        rb10_cb[1] |= (uint8_t)((op->rb_mode_sp & 0x7) << 5);
    rb10_cb[2] = (uint8_t)op->rb_id;
    sg_put_unaligned_be24(op->rb_offset, rb10_cb + 3);
    sg_put_unaligned_be24(op->rb_len, rb10_cb + 6);
    if (op->verbose) {
        char b[128];

        pr2serr("    Read buffer(10) cdb: %s\n",
                sg_get_command_str(rb10_cb, SG_READ_BUFFER_10_CMDLEN, false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("Read buffer(10): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rb10_cb, sizeof(rb10_cb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, op->rb_len);
    res = do_scsi_pt(ptvp, op->sg_fd, DEF_PT_TIMEOUT, op->verbose);
    ret = sg_cmds_process_resp(ptvp, "Read buffer(10)", res, noisy,
                               op->verbose, &sense_cat);
    if (-1 == ret) {
        if (get_scsi_pt_transport_err(ptvp))
            ret = SG_LIB_TRANSPORT_ERROR;
        else
            ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    } else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((op->verbose > 2) && (ret > 0)) {
            pr2serr("    Read buffer(10): response%s\n",
                    (ret > 256 ? ", first 256 bytes" : ""));
            hex2stderr((const uint8_t *)resp, (ret > 256 ? 256 : ret), -1);
        }
        ret = 0;
    }
    if (residp)
        *residp = get_scsi_pt_resid(ptvp);
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI READ BUFFER(16) command (spc5r02).  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
static int
sg_ll_read_buffer_16(void * resp, int * residp, bool noisy,
                    const struct opts_t * op)
{
    int ret, res, sense_cat;
    uint8_t rb16_cb[SG_READ_BUFFER_16_CMDLEN] =
          {SG_READ_BUFFER_16_CMD, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
           0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;
    struct sg_pt_base * ptvp;

    rb16_cb[1] = (uint8_t)(op->rb_mode & 0x1f);
    if (op->rb_mode_sp)
        rb16_cb[1] |= (uint8_t)((op->rb_mode_sp & 0x7) << 5);
    sg_put_unaligned_be64(op->rb_offset, rb16_cb + 2);
    sg_put_unaligned_be32(op->rb_len, rb16_cb + 10);
    rb16_cb[14] = (uint8_t)op->rb_id;
    if (op->verbose) {
        char b[128];

        pr2serr("    Read buffer(16) cdb: %s\n",
                sg_get_command_str(rb16_cb, SG_READ_BUFFER_16_CMDLEN, false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rb16_cb, sizeof(rb16_cb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, op->rb_len);
    res = do_scsi_pt(ptvp, op->sg_fd, DEF_PT_TIMEOUT, op->verbose);
    ret = sg_cmds_process_resp(ptvp, "Read buffer(16)", res, noisy,
                               op->verbose, &sense_cat);
    if (-1 == ret) {
        if (get_scsi_pt_transport_err(ptvp))
            ret = SG_LIB_TRANSPORT_ERROR;
        else
            ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    } else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((op->verbose > 2) && (ret > 0)) {
            pr2serr("    Read buffer(16): response%s\n",
                    (ret > 256 ? ", first 256 bytes" : ""));
            hex2stderr((const uint8_t *)resp, (ret > 256 ? 256 : ret), -1);
        }
        ret = 0;
    }
    if (residp)
        *residp = get_scsi_pt_resid(ptvp);
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Microcode status: active, redundant and download */
static const char * act_micro_st_arr[] = {
    "Microcode status not reported",
    "Activated microcode is valid",
    "Activated microcode is not valid",
    "Activated microcode is not a full microcode image",
};

static const char * red_micro_st_arr[] = {
    "Redundant microcode status is not reported",
    "At least one redundant microcode copy is valid",
    "No redundant microcode copy is valid",
    "Redundant microcode is not a full microcode image",
};

/* Major overlap between this SPC-4 table and SES-4r2 table 63 */
struct sg_lib_simple_value_name_t down_micro_st_arr[] = {
    {0x0, "No download microcode operation in progress"},
    {0x1, "Download in progress, awaiting more"},               /* SES */
    {0x2, "Download complete, updating storage"},               /* SES */
    {0x3, "Updating storage with deferred microcode"},          /* SES */
    {0x10, "Complete, no error, starting now"},                 /* SES */
    {0x11, "Complete, no error, start after hard reset or power "
           "cycle"},                                            /* SES */
    {0x12, "Complete, no error, start after power cycle"},      /* SES */
    {0x13, "Complete, no error, start after activate_mc, hard reset or "
           "power cycle"},                                      /* SES */
    {0x21, "Download in progress, awaiting more"},              /* SPC-6 */
    {0x22, "Download complete, updating storage"},              /* SPC-6 */
    {0x23, "Updating storage with deferred microcode"},         /* SPC-6 */
    {0x30, "Deferred microcode download complete, no reports"}, /* SPC-6 */
    {0x31, "Deferred download ok, await hard reset or power cycle"},
    {0x32, "Deferred download ok, await power cycle"},          /* SPC-6 */
    {0x33, "Deferred download ok, await any event"},            /* SPC-6 */
    {0x34, "Deferred download ok, await Write buffer command"}, /* SPC-6 */
    {0x35, "Deferred download ok, await any event, WB only this LU"},
    {0x80, "Error, discarded, see additional status"},          /* SES */
    {0x81, "Error, discarded, image error"},                    /* SES */
    {0x82, "Timeout, discarded"},                               /* SES */
    {0x83, "Internal error, need new microcode before reset"},  /* SES */
    {0x84, "Internal error, need new microcode, reset safe"},   /* SES */
    {0x85, "Unexpected activate_mc received"},                  /* SES */
    {0x90, "Error, discarded, see additional status"},          /* SPC-6 */
    {0x91, "Error, discarded, image error"},                    /* SPC-6 */
    {0x92, "Timeout, discarded"},                               /* SPC-6 */
    {0x93, "Internal error, need new microcode before reset"},  /* SPC-6 */
    {0x94, "Internal error, need new microcode, reset safe"},   /* SPC-6 */
    {0x95, "Unexpected activate_mc received, mcrocode discard"}, /* SPC-6 */
    {0x1000, NULL},             /* End sentinel */
};

static void
decode_microcode_status(const uint8_t * resp, const struct opts_t * op)
{
    int n;
    uint32_t u;
    const char * cp;
    const struct sg_lib_simple_value_name_t * vnp;
    char b[32];

    if ((NULL == resp) || (op->rb_len < 1))
        return;
    n = resp[0];
    if (n < (int)SG_ARRAY_SIZE(act_micro_st_arr))
        cp = act_micro_st_arr[n];
    else {
        snprintf(b, sizeof(b), "unknown [0x%x]", n);
        cp = b;
    }
    printf("Activated microcode status: %s\n", cp);

    if (op->rb_len < 2)
        return;
    n = resp[1];
    if (n < (int)SG_ARRAY_SIZE(red_micro_st_arr))
        cp = red_micro_st_arr[n];
    else {
        snprintf(b, sizeof(b), "unknown [0x%x]", n);
        cp = b;
    }
    printf("Redundant microcode status: %s\n", cp);

    if (op->rb_len < 3)
        return;
    n = resp[2];
    for (vnp = down_micro_st_arr, cp = NULL; vnp->name; ++vnp) {
        if (vnp->value == n) {
            cp = vnp->name;
            break;
        }
    }
    if (NULL == cp) {
        snprintf(b, sizeof(b), "unknown [0x%x]", n);
        cp = b;
    }
    printf("Download microcode status: %s\n", cp);

    if (op->rb_len > 7) {
        u = sg_get_unaligned_be32(resp + 4);
        printf("Download microcode maximum size (bytes): %u [0x%x]\n", u, u);
    }
    if (op->rb_len > 15) {
        u = sg_get_unaligned_be32(resp + 12);
        printf("Download microcode expected buffer offset (bytes): %u "
               "[0x%x]\n", u, u);
    }
}

static void
decode_error_history(const uint8_t * resp, const struct opts_t * op)
{
    static const char * eh_s = "Error history";
    int k, num;
    uint32_t dir_len;
    const uint8_t * up;

    if (op->rb_id < 0x4) {     /* eh directory variants */
        if (op->rb_len < 8) {
            pr2serr("%s response buffer too short [%d] to show directory "
                    "header\n", eh_s, op->rb_len);
            return;
        }
        printf("%s directory header:\n", eh_s);
        printf("  T10 Vendor: %.8s\n", resp + 0);
        printf("  Version: %u\n", resp[8]);
        printf("  EHS_retrieved: %u\n", 0x3 & (resp[9] >> 3));
        printf("  EHS_source: %u\n", 0x3 & (resp[9] >> 1));
        printf("  CLR_SUP: %u\n", 0x1 & resp[9]);
        if (op->rb_len < 32) {
            pr2serr("%s response buffer too short [%d] to show directory "
                    "length\n", eh_s, op->rb_len);
            return;
        }
        dir_len = sg_get_unaligned_be16(resp + 30);
        printf("  Directory length: %u\n", dir_len);
        if ((unsigned)op->rb_len < (32 + dir_len)) {
            pr2serr("%s directory entries truncated, try adding '-l %u' "
                    "option\n", eh_s, 32 + dir_len);
        }
        num = (op->rb_len - 32) / 8;
        for (k = 0, up = resp + 32; k < num; ++k, up += 8) {
            if (k > 0)
                printf("\n");
            printf("   Supported buffer ID: 0x%x\n", up[0]);
            printf("    Buffer format: 0x%x\n", up[1]);
            printf("    Buffer source: 0x%x\n", 0xf & up[2]);
            printf("    Maximum available length: 0x%x\n",
                   sg_get_unaligned_be32(up + 4));
        }
    } else if ((op->rb_id >= 0x10) && (op->rb_id <= 0xef))
        hex2stdout(resp, op->rb_len, (op->verbose > 1 ? 0 : 1));
    else if (0xfe == op->rb_id)
        pr2serr("clear %s I_T nexus [0x%x]\n", eh_s, op->rb_id);
    else if (0xff == op->rb_id)
        pr2serr("clear %s I_T nexus and release any snapshots [0x%x]\n",
                eh_s, op->rb_id);
    else
        pr2serr("Reserved Buffer ID value [0x%x] for %s\n", op->rb_id, eh_s);

}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

int
main(int argc, char * argv[])
{
    int res, c, len, k;
    int inhex_len = 0;
    int resid = 0;
    int ret = 0;
    int64_t ll;
    const char * cp = NULL;
    uint8_t * resp = NULL;
    uint8_t * free_resp = NULL;
    const struct mode_s * mp;
    struct opts_t opts SG_C_CPP_ZERO_INIT;
    struct opts_t * op = &opts;

    op->sg_fd = -1;
    op->rb_len = DEF_RESPONSE_LEN;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "e:hHi:I:l:Lm:No:rRS:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'e':
            if (op->rb_mode_given && (MODE_ERR_HISTORY != op->rb_mode)) {
                pr2serr("mode incompatible with --eh_code= option\n");
                return SG_LIB_CONTRADICT;
            }
            op->eh_code = sg_get_num(optarg);
            if ((op->eh_code < 0) || (op->eh_code > 255)) {
                pr2serr("argument to '--eh_code=' should be in the range 0 "
                        "to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->rb_mode = MODE_ERR_HISTORY;
            op->eh_code_given = true;
            break;
        case 'h':
        case '?':
            ++op->do_help;
            break;
        case 'H':
            ++op->do_hex;
            break;
        case 'i':
            op->rb_id = sg_get_num(optarg);
            if ((op->rb_id < 0) || (op->rb_id > 255)) {
                pr2serr("argument to '--id=' should be in the range 0 to "
                        "255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->rb_id_given = true;
            break;
        case 'I':
            if (op->inhex_name) {
                pr2serr("--inhex= option given more than once. Once only "
                        "please\n");
                return SG_LIB_SYNTAX_ERROR;
            } else
                op->inhex_name = optarg;
            break;
        case 'l':
            op->rb_len = sg_get_num(optarg);
            if (op->rb_len < 0) {
                pr2serr("bad argument to '--length'\n");
                return SG_LIB_SYNTAX_ERROR;
             }
             if (op->rb_len > 0xffffff) {
                pr2serr("argument to '--length' must be <= 0xffffff\n");
                return SG_LIB_SYNTAX_ERROR;
             }
             op->rb_len_given = true;
             break;
        case 'L':
            op->do_long = true;
            break;
        case 'm':
            if (NULL == optarg) {
                pr2serr("bad argument to '--mode'\n");
                return SG_LIB_SYNTAX_ERROR;
            } else if (isdigit((uint8_t)*optarg)) {
                op->rb_mode = sg_get_num(optarg);
                if ((op->rb_mode < 0) || (op->rb_mode > 31)) {
                    pr2serr("argument to '--mode' should be in the range 0 "
                            "to 31\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                len = strlen(optarg);
                for (mp = modes; mp->mode_string; ++mp) {
                    cp = strchr(mp->mode_string, '|');
                    if (NULL == cp) {
                        if (0 == strncmp(mp->mode_string, optarg, len)) {
                            op->rb_mode = mp->mode;
                            break;
                        }
                    } else {
                        int f_len = cp - mp->mode_string;

                        if ((f_len == len) &&
                            (0 == memcmp(mp->mode_string, optarg, len))) {
                            op->rb_mode = mp->mode;
                            break;
                        }
                        if (0 == strncmp(cp + 1, optarg, len)) {
                            op->rb_mode = mp->mode;
                            break;
                        }
                    }
                }
                if (NULL == mp->mode_string) {
                    print_modes();
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            if (op->eh_code_given && (MODE_ERR_HISTORY != op->rb_mode)) {
                pr2serr("mode incompatible with --eh_code= option\n");
                return SG_LIB_CONTRADICT;
            }
            op->rb_mode_given = true;
            break;
        case 'N':
            op->no_output = true;
            break;
        case 'o':
           ll = sg_get_llnum(optarg);
           if (ll < 0) {
                pr2serr("bad argument to '--offset'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->rb_offset = ll;
            break;
        case 'r':
            op->do_raw = true;
            break;
        case 'R':
            op->o_readonly = true;
            break;
        case 'S':
           op->rb_mode_sp = sg_get_num(optarg);
           if ((op->rb_mode_sp < 0) || (op->rb_mode_sp > 7)) {
                pr2serr("expected argument to '--specific' to be 0 to 7\n");
                return SG_LIB_SYNTAX_ERROR;
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
    if (op->do_help) {
        if (op->do_help > 1) {
            usage();
            pr2serr("\n");
            print_modes();
        } else
            usage();
        return 0;
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
    if ((MODE_ERR_HISTORY == op->rb_mode) && (NULL == op->inhex_name)) {
        if (! op->rb_len_given)
            op->rb_len = 64;
    }
    if (op->eh_code_given) {
        if (op->rb_id_given && (op->eh_code != op->rb_id)) {
            pr2serr("Buffer ID incompatible with --eh_code= option\n");
            return SG_LIB_CONTRADICT;
        }
        op->rb_id = op->eh_code;
    }

    if (op->device_name && op->inhex_name) {
        pr2serr("Confused: both DEVICE (%s) and --inhex= option given. One "
                "only please\n", op->device_name);
                return SG_LIB_SYNTAX_ERROR;
    } else if (op->inhex_name) {
        op->rb_len = (op->rb_len > MAX_DEF_INHEX_LEN) ? op->rb_len :
                                                        MAX_DEF_INHEX_LEN;
        resp = (uint8_t *)sg_memalign(op->rb_len, 0, &free_resp, false);
        ret = sg_f2hex_arr(op->inhex_name, op->do_raw, false, resp,
                           &inhex_len, op->rb_len);
        if (ret)
            goto fini;
        if (op->do_raw)
            op->do_raw = false;     /* only used for input in this case */
        op->rb_len = inhex_len;
        resid = 0;
        goto decode_result;
    } else if (NULL == op->device_name) {
        pr2serr("Missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    len = op->rb_len ? op->rb_len : 8;
    resp = (uint8_t *)sg_memalign(len, 0, &free_resp, false);
    if (NULL == resp) {
        pr2serr("unable to allocate %d bytes on the heap\n", len);
        return SG_LIB_CAT_OTHER;
    }

    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto fini;
        }
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (op->verbose > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif

    op->sg_fd = sg_cmds_open_device(op->device_name, op->o_readonly,
                                    op->verbose);
    if (op->sg_fd < 0) {
        if (op->verbose)
            pr2serr("open error: %s: %s\n", op->device_name,
                    safe_strerror(-op->sg_fd));
        ret = sg_convert_errno(-op->sg_fd);
        goto fini;
    }

    if (op->do_long)
        res = sg_ll_read_buffer_16(resp, &resid, true, op);
    else if (op->rb_offset > 0xffffff) {
        pr2serr("--offset value is too large for READ BUFFER(10), try "
                "--16\n");
        ret = SG_LIB_SYNTAX_ERROR;
        goto fini;
    } else
        res = sg_ll_read_buffer_10(resp, &resid, true, op);
    if (0 != res) {
        char b[80];

        ret = res;
        if (res > 0) {
            sg_get_category_sense_str(res, sizeof(b), b, op->verbose);
            pr2serr("Read buffer(%d) failed: %s\n",
                    (op->do_long ? 16 : 10), b);
        }
        goto fini;
    }
    if (resid > 0)
        op->rb_len -= resid;        /* got back less than requested */
    if (op->no_output)
        goto fini;
decode_result:
    if (op->rb_len > 0) {
        if (op->do_raw)
            dStrRaw(resp, op->rb_len);
        else if (op->do_hex || (op->rb_len < 4)) {
            k = (op->do_hex > 2) ? -1 : (2 - op->do_hex);
            hex2stdout(resp, op->rb_len, k);
        } else {
            switch (op->rb_mode) {
            case MODE_DESCRIPTOR:
                k = sg_get_unaligned_be24(resp + 1);
                printf("OFFSET BOUNDARY: %d, Buffer offset alignment: "
                       "%d-byte\n", resp[0], (1 << resp[0]));
                printf("BUFFER CAPACITY: %d (0x%x)\n", k, k);
                break;
            case MODE_ECHO_BDESC:
                k = sg_get_unaligned_be16(resp + 2) & 0x1fff;
                printf("EBOS:%d\n", resp[0] & 1 ? 1 : 0);
                printf("Echo buffer capacity: %d (0x%x)\n", k, k);
                break;
            case MODE_READ_MICROCODE_ST:
                decode_microcode_status(resp, op);
                break;
            case MODE_ERR_HISTORY:
                decode_error_history(resp, op);
                break;
            default:
                hex2stdout(resp, op->rb_len, (op->verbose > 1 ? 0 : 1));
                break;
            }
        }
    }

fini:
    if (free_resp)
        free(free_resp);
    if (op->sg_fd >= 0) {
        res = sg_cmds_close_device(op->sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == op->verbose) {
        if (! sg_if_can2stderr("sg_read_buffer failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

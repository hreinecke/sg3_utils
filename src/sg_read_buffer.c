/*
 * Copyright (c) 2006-2019 Luben Tuikov and Douglas Gilbert.
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

static const char * version_str = "1.30 20191220";      /* spc5r22 */


#ifndef SG_READ_BUFFER_10_CMD
#define SG_READ_BUFFER_10_CMD 0x3c
#define SG_READ_BUFFER_10_CMDLEN 10
#endif
#ifndef SG_READ_BUFFER_16_CMD
#define SG_READ_BUFFER_16_CMD 0x9b
#define SG_READ_BUFFER_16_CMDLEN 16
#endif

#define MAX_DEF_INHEX_LEN 8192
#define SENSE_BUFF_LEN  64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT  60       /* 60 seconds */


static struct option long_options[] = {
        {"16", no_argument, 0, 'L'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"id", required_argument, 0, 'i'},
        {"inhex", required_argument, 0, 'I'},
        {"length", required_argument, 0, 'l'},
        {"long", no_argument, 0, 'L'},
        {"mode", required_argument, 0, 'm'},
        {"offset", required_argument, 0, 'o'},
        {"raw", no_argument, 0, 'r'},
        {"readonly", no_argument, 0, 'R'},
        {"specific", required_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},   /* sentinel */
};


static void
usage()
{
    pr2serr("Usage: sg_read_buffer [--16] [--help] [--hex] [--id=ID] "
            "[--inhex=FN]\n"
            "                      [--length=LEN] [--long] [--mode=MO] "
            "[--offset=OFF]\n"
            "                      [--raw] [--readonly] [--specific=MS] "
            "[--verbose]\n"
            "                      [--version] DEVICE\n"
            "  where:\n"
            "    --16|-L             issue READ BUFFER(16) (def: 10)\n"
            "    --help|-h           print out usage message\n"
            "    --hex|-H            print output in hex\n"
            "    --id=ID|-i ID       buffer identifier (0 (default) to 255)\n"
            "    --inhex=FN|-I FN    filename FN contains hex data to "
            "decode\n"
            "                        rather than DEVICE. If --raw given "
            "then binary\n"
            "    --length=LEN|-l LEN    length in bytes to read (def: 4)\n"
            "    --long|-L           issue READ BUFFER(16) (def: 10)\n"
            "    --mode=MO|-m MO     read buffer mode, MO is number or "
            "acronym (def: 0)\n"
            "    --offset=OFF|-o OFF    buffer offset (unit: bytes, def: 0)\n"
            "    --raw|-r            output response in binary to stdout\n"
            "    --readonly|-R       open DEVICE read-only (def: read-write)\n"
            "    --specific=MS|-S MS    mode specific value; 3 bit field (0 "
            "to 7)\n"
            "    --verbose|-v        increase verbosity\n"
            "    --version|-V        print version string and exit\n\n"
            "Performs a SCSI READ BUFFER (10 or 16) command. Use '-m xxx' to "
            "list\navailable modes. Numbers given in options are decimal "
            "unless they have\na hex indicator (e.g. a leading '0x').\n"
           );
}


#define MODE_HEADER_DATA        0
#define MODE_VENDOR             1
#define MODE_DATA               2
#define MODE_DESCRIPTOR         3
#define MODE_ECHO_BUFFER        0x0A
#define MODE_ECHO_BDESC         0x0B
#define MODE_READ_MICROCODE_ST  0x0F
#define MODE_EN_EX_ECHO         0x1A
#define MODE_ERR_HISTORY        0x1C

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
        { "err_hist",   MODE_ERR_HISTORY, "error history (spc-4)"},
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
sg_ll_read_buffer_10(int sg_fd, int rb_mode, int rb_mode_sp, int rb_id,
                     uint32_t rb_offset, void * resp, int mx_resp_len,
                     int * residp, bool noisy, int verbose)
{
    int ret, res, sense_cat;
    uint8_t rb10_cb[SG_READ_BUFFER_10_CMDLEN] =
          {SG_READ_BUFFER_10_CMD, 0, 0, 0,  0, 0, 0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    rb10_cb[1] = (uint8_t)(rb_mode & 0x1f);
    if (rb_mode_sp)
        rb10_cb[1] |= (uint8_t)((rb_mode_sp & 0x7) << 5);
    rb10_cb[2] = (uint8_t)rb_id;
    sg_put_unaligned_be24(rb_offset, rb10_cb + 3);
    sg_put_unaligned_be24(mx_resp_len, rb10_cb + 6);
    if (verbose) {
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
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "Read buffer(10)", res, noisy, verbose,
                               &sense_cat);
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
    } else {
        if ((verbose > 2) && (ret > 0)) {
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
sg_ll_read_buffer_16(int sg_fd, int rb_mode, int rb_mode_sp, int rb_id,
                     uint64_t rb_offset, void * resp, int mx_resp_len,
                     int * residp, bool noisy, int verbose)
{
    int ret, res, sense_cat;
    uint8_t rb16_cb[SG_READ_BUFFER_16_CMDLEN] =
          {SG_READ_BUFFER_16_CMD, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,
           0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    rb16_cb[1] = (uint8_t)(rb_mode & 0x1f);
    if (rb_mode_sp)
        rb16_cb[1] |= (uint8_t)((rb_mode_sp & 0x7) << 5);
    sg_put_unaligned_be64(rb_offset, rb16_cb + 2);
    sg_put_unaligned_be24(mx_resp_len, rb16_cb + 11);
    rb16_cb[14] = (uint8_t)rb_id;
    if (verbose) {
        char b[128];

        pr2serr("    Read buffer(16) cdb: %s\n",
                sg_get_command_str(rb16_cb, SG_READ_BUFFER_16_CMDLEN, false,
                                   sizeof(b), b));
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("Read buffer(16): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rb16_cb, sizeof(rb16_cb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "Read buffer(16)", res, noisy, verbose,
                               &sense_cat);
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
    } else {
        if ((verbose > 2) && (ret > 0)) {
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
decode_microcode_status(uint8_t * resp, int rb_len)
{
    int n;
    uint32_t u;
    const char * cp;
    const struct sg_lib_simple_value_name_t * vnp;
    char b[32];

    if ((NULL == resp) || (rb_len < 1))
        return;
    n = resp[0];
    if (n < (int)SG_ARRAY_SIZE(act_micro_st_arr))
        cp = act_micro_st_arr[n];
    else {
        snprintf(b, sizeof(b), "unknown [0x%x]", n);
        cp = b;
    }
    printf("Activated microcode status: %s\n", cp);

    if (rb_len < 2)
        return;
    n = resp[1];
    if (n < (int)SG_ARRAY_SIZE(red_micro_st_arr))
        cp = red_micro_st_arr[n];
    else {
        snprintf(b, sizeof(b), "unknown [0x%x]", n);
        cp = b;
    }
    printf("Redundant microcode status: %s\n", cp);

    if (rb_len < 3)
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

    if (rb_len > 7) {
        u = sg_get_unaligned_be32(resp + 4);
        printf("Download microcode maximum size (bytes): %u [0x%x]\n", u, u);
    }
    if (rb_len > 15) {
        u = sg_get_unaligned_be32(resp + 12);
        printf("Download microcode expected buffer offset (bytes): %u "
               "[0x%x]\n", u, u);
    }
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
    bool do_long = false;
    bool o_readonly = false;
    bool do_raw = false;
    bool verbose_given = false;
    bool version_given = false;
    int res, c, len, k, inhex_len;
    int sg_fd = -1;
    int do_help = 0;
    int do_hex = 0;
    int rb_id = 0;
    int rb_len = 4;
    int rb_mode = 0;
    int rb_mode_sp = 0;
    int resid = 0;
    int verbose = 0;
    int ret = 0;
    int64_t ll;
    uint64_t rb_offset = 0;
    const char * device_name = NULL;
    const char * fname = NULL;
    uint8_t * resp = NULL;
    uint8_t * free_resp = NULL;
    const struct mode_s * mp;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHi:I:l:Lm:o:rRS:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            ++do_help;
            break;
        case 'H':
            ++do_hex;
            break;
        case 'i':
            rb_id = sg_get_num(optarg);
            if ((rb_id < 0) || (rb_id > 255)) {
                pr2serr("argument to '--id' should be in the range 0 to "
                        "255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'I':
            if (fname) {
                pr2serr("--inhex= option given more than once. Once only "
                        "please\n");
                return SG_LIB_SYNTAX_ERROR;
            } else
                fname = optarg;
            break;
        case 'l':
            rb_len = sg_get_num(optarg);
            if (rb_len < 0) {
                pr2serr("bad argument to '--length'\n");
                return SG_LIB_SYNTAX_ERROR;
             }
             if (rb_len > 0xffffff) {
                pr2serr("argument to '--length' must be <= 0xffffff\n");
                return SG_LIB_SYNTAX_ERROR;
             }
             break;
        case 'L':
            do_long = true;
            break;
        case 'm':
            if (isdigit(*optarg)) {
                rb_mode = sg_get_num(optarg);
                if ((rb_mode < 0) || (rb_mode > 31)) {
                    pr2serr("argument to '--mode' should be in the range 0 "
                            "to 31\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                len = strlen(optarg);
                for (mp = modes; mp->mode_string; ++mp) {
                    if (0 == strncmp(mp->mode_string, optarg, len)) {
                        rb_mode = mp->mode;
                        break;
                    }
                }
                if (NULL == mp->mode_string) {
                    print_modes();
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            break;
        case 'o':
           ll = sg_get_llnum(optarg);
           if (ll < 0) {
                pr2serr("bad argument to '--offset'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            rb_offset = ll;
            break;
        case 'r':
            do_raw = true;
            break;
        case 'R':
            o_readonly = true;
            break;
        case 'S':
           rb_mode_sp = sg_get_num(optarg);
           if ((rb_mode_sp < 0) || (rb_mode_sp > 7)) {
                pr2serr("expected argument to '--specific' to be 0 to 7\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (do_help) {
        if (do_help > 1) {
            usage();
            pr2serr("\n");
            print_modes();
        } else
            usage();
        return 0;
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
    if (verbose_given && version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        verbose_given = false;
        version_given = false;
        verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", verbose);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    rb_len = 0;
    inhex_len = 0;
    if (device_name && fname) {
        pr2serr("Confused: both DEVICE (%s) and --inhex= option given. One "
                "only please\n", device_name);
                return SG_LIB_SYNTAX_ERROR;
    } else if (fname) {
        rb_len = (rb_len > MAX_DEF_INHEX_LEN) ? rb_len : MAX_DEF_INHEX_LEN;
        resp = (uint8_t *)sg_memalign(rb_len, 0, &free_resp, false);
        ret = sg_f2hex_arr(fname, do_raw, false, resp, &inhex_len, rb_len);
        if (ret)
            goto fini;
        if (do_raw)
            do_raw = false;     /* only used for input in this case */
        rb_len = inhex_len;
        resid = 0;
        goto decode_result;
    } else if (NULL == device_name) {
        pr2serr("Missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    len = rb_len ? rb_len : 8;
    resp = (uint8_t *)sg_memalign(len, 0, &free_resp, false);
    if (NULL == resp) {
        pr2serr("unable to allocate %d bytes on the heap\n", len);
        return SG_LIB_CAT_OTHER;
    }

    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            ret = SG_LIB_FILE_ERROR;
            goto fini;
        }
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (verbose > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif

    sg_fd = sg_cmds_open_device(device_name, o_readonly, verbose);
    if (sg_fd < 0) {
        if (verbose)
            pr2serr("open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }

    if (do_long)
        res = sg_ll_read_buffer_16(sg_fd, rb_mode, rb_mode_sp, rb_id,
                                   rb_offset, resp, rb_len, &resid, true,
                                   verbose);
    else if (rb_offset > 0xffffff) {
        pr2serr("--offset value is too large for READ BUFFER(10), try "
                "--16\n");
        ret = SG_LIB_SYNTAX_ERROR;
        goto fini;
    } else
        res = sg_ll_read_buffer_10(sg_fd, rb_mode, rb_mode_sp, rb_id,
                                   (uint32_t)rb_offset, resp, rb_len, &resid,
                                   true, verbose);
    if (0 != res) {
        char b[80];

        ret = res;
        if (res > 0) {
            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("Read buffer(%d) failed: %s\n", (do_long ? 16 : 10), b);
        }
        goto fini;
    }
    if (resid > 0)
        rb_len -= resid;        /* got back less than requested */
decode_result:
    if (rb_len > 0) {
        if (do_raw)
            dStrRaw(resp, rb_len);
        else if (do_hex || (rb_len < 4))
            hex2stdout((const uint8_t *)resp, rb_len, ((do_hex > 1) ? 0 : 1));
        else {
            switch (rb_mode) {
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
                decode_microcode_status(resp, rb_len);
                break;
            default:
                hex2stdout((const uint8_t *)resp, rb_len,
                           (verbose > 1 ? 0 : 1));
                break;
            }
        }
    }

fini:
    if (free_resp)
        free(free_resp);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_read_buffer failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

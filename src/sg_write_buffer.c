/*
 * Copyright (c) 2006-2014 Luben Tuikov and Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_pt.h"      /* needed for scsi_pt_win32_direct() */

/*
 * This utility issues the SCSI WRITE BUFFER command to the given device.
 */

static const char * version_str = "1.15 20140518";    /* spc4r37 */

#define ME "sg_write_buffer: "
#define DEF_XFER_LEN (8 * 1024 * 1024)
#define EBUFF_SZ 256

#define WRITE_BUFFER_CMD 0x3b
#define WRITE_BUFFER_CMDLEN 10
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT 120       /* 120 seconds, 2 minutes */

static struct option long_options[] = {
        {"bpw", required_argument, 0, 'b'},
        {"help", no_argument, 0, 'h'},
        {"id", required_argument, 0, 'i'},
        {"in", required_argument, 0, 'I'},
        {"length", required_argument, 0, 'l'},
        {"mode", required_argument, 0, 'm'},
        {"offset", required_argument, 0, 'o'},
        {"raw", no_argument, 0, 'r'},
        {"skip", required_argument, 0, 's'},
        {"specific", required_argument, 0, 'S'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
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
    pr2serr("Usage: "
            "sg_write_buffer [--bpw=CS] [--help] [--id=ID] [--in=FILE]\n"
            "                       [--length=LEN] [--mode=MO] "
            "[--offset=OFF] [--raw]\n"
            "                       [--skip=SKIP] [--specific=MS] "
            "[--verbose] [--version]\n"
            "                       DEVICE\n"
            "  where:\n"
            "    --bpw=CS|-b CS         CS is chunk size: bytes per write "
            "buffer\n"
            "                           command (def: 0 -> as many as "
            "possible)\n"
            "    --help|-h              print out usage message then exit\n"
            "    --id=ID|-i ID          buffer identifier (0 (default) to "
            "255)\n"
            "    --in=FILE|-I FILE      read from FILE ('-I -' read "
            "from stdin)\n"
            "    --length=LEN|-l LEN    length in bytes to write; may be "
            "deduced from\n"
            "                           FILE\n"
            "    --mode=MO|-m MO        write buffer mode, MO is number or "
            "acronym\n"
            "                           (def: 0 -> 'combined header and "
            "data' (obs))\n"
            "    --off=OFF|-o OFF       buffer offset (unit: bytes, def: 0)\n"
            "    --raw|-r               read from stdin (same as '-I -')\n"
            "    --skip=SKIP|-s SKIP    bytes in file FILE to skip before "
            "reading\n"
            "    --specific=MS|-S MS    mode specific value; 3 bit field "
            "(0 to 7)\n"
            "    --verbose|-v           increase verbosity\n"
            "    --version|-V           print version string and exit\n\n"
            "Performs one or more SCSI WRITE BUFFER commands. Use '-m xxx' "
            "to list\navailable modes. Numbers given in options are decimal "
            "unless they have\na hex indicator.\n"
          );

}

#define MODE_HEADER_DATA        0
#define MODE_VENDOR             1
#define MODE_DATA               2
#define MODE_DNLD_MC            4
#define MODE_DNLD_MC_SAVE       5
#define MODE_DNLD_MC_OFFS       6
#define MODE_DNLD_MC_OFFS_SAVE  7
#define MODE_ECHO_BUFFER        0x0A
#define MODE_DNLD_MC_EV_OFFS_DEFER 0x0D
#define MODE_DNLD_MC_OFFS_DEFER 0x0E
#define MODE_ACTIVATE_MC        0x0F
#define MODE_EN_EX_ECHO         0x1A
#define MODE_DIS_EX             0x1B
#define MODE_DNLD_ERR_HISTORY   0x1C


static struct mode_s {
        const char *mode_string;
        int   mode;
        const char *comment;
} modes[] = {
        { "hd",         MODE_HEADER_DATA, "combined header and data "
                "(obsolete)"},
        { "vendor",     MODE_VENDOR,    "vendor specific"},
        { "data",       MODE_DATA,      "data"},
        { "dmc",        MODE_DNLD_MC,   "download microcode and activate"},
        { "dmc_save",   MODE_DNLD_MC_SAVE, "download microcode, save and "
                "activate"},
        { "dmc_offs",   MODE_DNLD_MC_OFFS, "download microcode with offsets "
                "and activate"},
        { "dmc_offs_save", MODE_DNLD_MC_OFFS_SAVE, "download microcode with "
                "offsets, save and\n\t\t\t\tactivate"},
        { "echo",       MODE_ECHO_BUFFER, "write data to echo buffer"},
        { "dmc_offs_ev_defer", MODE_DNLD_MC_EV_OFFS_DEFER, "download "
                "microcode with offsets, select\n\t\t\t\tactivation event, "
                "save and defer activation"},
        { "dmc_offs_defer", MODE_DNLD_MC_OFFS_DEFER, "download microcode "
                "with offsets, save and defer\n\t\t\t\tactivation"},
        { "activate_mc", MODE_ACTIVATE_MC,
                "activate deferred microcode"},
        { "en_ex",      MODE_EN_EX_ECHO, "enable expander communications "
                "protocol and echo\n\t\t\t\tbuffer (obsolete)"},
        { "dis_ex",     MODE_DIS_EX, "disable expander communications "
                "protocol\n\t\t\t\t(obsolete)"},
        { "deh",        MODE_DNLD_ERR_HISTORY, "download application client "
                "error history "},
};

#define NUM_MODES       ((int)(sizeof(modes)/sizeof(modes[0])))

static void
print_modes(void)
{
    int k;

    pr2serr("The modes parameter argument can be numeric (hex or decimal)\n"
            "or symbolic:\n");
    for (k = 0; k < NUM_MODES; k++) {
        pr2serr(" %2d (0x%02x)  %-18s%s\n", modes[k].mode, modes[k].mode,
                modes[k].mode_string, modes[k].comment);
    }
}

/* <<<< This function will be moved to the library in the future >>> */
/* Invokes a SCSI WRITE BUFFER command (SPC). Return of 0 ->
 * success, SG_LIB_CAT_INVALID_OP -> invalid opcode,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_NOT_READY -> device not ready, SG_LIB_CAT_ABORTED_COMMAND,
 * -1 -> other failure */
static int
sg_ll_write_buffer_v2(int sg_fd, int mode, int m_specific, int buffer_id,
                      int buffer_offset, void * paramp, int param_len,
                      int noisy, int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char wbufCmdBlk[WRITE_BUFFER_CMDLEN] =
        {WRITE_BUFFER_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    wbufCmdBlk[1] = (unsigned char)(mode & 0x1f);
    wbufCmdBlk[1] |= (unsigned char)((m_specific & 0x7) << 5);
    wbufCmdBlk[2] = (unsigned char)(buffer_id & 0xff);
    wbufCmdBlk[3] = (unsigned char)((buffer_offset >> 16) & 0xff);
    wbufCmdBlk[4] = (unsigned char)((buffer_offset >> 8) & 0xff);
    wbufCmdBlk[5] = (unsigned char)(buffer_offset & 0xff);
    wbufCmdBlk[6] = (unsigned char)((param_len >> 16) & 0xff);
    wbufCmdBlk[7] = (unsigned char)((param_len >> 8) & 0xff);
    wbufCmdBlk[8] = (unsigned char)(param_len & 0xff);
    if (verbose) {
        pr2serr("    Write buffer cmd: ");
        for (k = 0; k < WRITE_BUFFER_CMDLEN; ++k)
            pr2serr("%02x ", wbufCmdBlk[k]);
        pr2serr("\n");
        if ((verbose > 1) && paramp && param_len) {
            pr2serr("    Write buffer parameter list%s:\n",
                    ((param_len > 256) ? " (first 256 bytes)" : ""));
            dStrHexErr((const char *)paramp,
                       ((param_len > 256) ? 256 : param_len), -1);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("write buffer: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, wbufCmdBlk, sizeof(wbufCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "write buffer", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
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
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}


int
main(int argc, char * argv[])
{
    int sg_fd, infd, res, c, len, k, n, got_stdin;
    int bpw = 0;
    int bpw_then_activate = 0;
    int do_help = 0;
    int wb_id = 0;
    int wb_len = 0;
    int wb_len_given = 0;
    int wb_mode = 0;
    int wb_offset = 0;
    int wb_skip = 0;
    int wb_mspec = 0;
    int verbose = 0;
    const char * device_name = NULL;
    const char * file_name = NULL;
    unsigned char * dop = NULL;
    char * cp;
    char ebuff[EBUFF_SZ];
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "b:hi:I:l:m:o:rs:S:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            bpw = sg_get_num(optarg);
            if (bpw < 0) {
                pr2serr("argument to '--bpw' should be in a positive "
                        "number\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if ((cp = strchr(optarg, ','))) {
                if (0 == strncmp("act", cp + 1, 3))
                    ++bpw_then_activate;
            }
            break;
        case 'h':
        case '?':
            ++do_help;
            break;
        case 'i':
            wb_id = sg_get_num(optarg);
            if ((wb_id < 0) || (wb_id > 255)) {
                pr2serr("argument to '--id' should be in the range 0 to "
                        "255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'I':
            file_name = optarg;
            break;
        case 'l':
            wb_len = sg_get_num(optarg);
            if (wb_len < 0) {
                pr2serr("bad argument to '--length'\n");
                return SG_LIB_SYNTAX_ERROR;
             }
             wb_len_given = 1;
             break;
        case 'm':
            if (isdigit(*optarg)) {
                wb_mode = sg_get_num(optarg);
                if ((wb_mode < 0) || (wb_mode > 31)) {
                    pr2serr("argument to '--mode' should be in the range 0 "
                            "to 31\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                len = strlen(optarg);
                for (k = 0; k < NUM_MODES; ++k) {
                    if (0 == strncmp(modes[k].mode_string, optarg, len)) {
                        wb_mode = modes[k].mode;
                        break;
                    }
                }
                if (NUM_MODES == k) {
                    print_modes();
                    return SG_LIB_SYNTAX_ERROR;
                }
            }
            break;
        case 'o':
           wb_offset = sg_get_num(optarg);
           if (wb_offset < 0) {
                pr2serr("bad argument to '--offset'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            file_name = "-";
            break;
        case 's':
           wb_skip = sg_get_num(optarg);
           if (wb_skip < 0) {
                pr2serr("bad argument to '--skip'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'S':
           wb_mspec = sg_get_num(optarg);
           if ((wb_mspec < 0) || (wb_mspec > 7)) {
                pr2serr("expected argument to '--specific' to be 0 to 7\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return 0;
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

    if (NULL == device_name) {
        pr2serr("missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((wb_len > 0) && (bpw > wb_len)) {
        pr2serr("trim chunk size (CS) to be the same as LEN\n");
        bpw = wb_len;
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (verbose > 4)
        pr2serr("Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (file_name || (wb_len > 0)) {
        if (0 == wb_len)
            wb_len = DEF_XFER_LEN;
        if (NULL == (dop = (unsigned char *)malloc(wb_len))) {
            pr2serr(ME "out of memory\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        memset(dop, 0xff, wb_len);
        if (file_name) {
            got_stdin = (0 == strcmp(file_name, "-")) ? 1 : 0;
            if (got_stdin) {
                if (wb_skip > 0) {
                    pr2serr("Can't skip on stdin\n");
                    ret = SG_LIB_FILE_ERROR;
                    goto err_out;
                }
                infd = STDIN_FILENO;
            } else {
                if ((infd = open(file_name, O_RDONLY)) < 0) {
                    snprintf(ebuff, EBUFF_SZ,
                             ME "could not open %s for reading", file_name);
                    perror(ebuff);
                    ret = SG_LIB_FILE_ERROR;
                    goto err_out;
                } else if (sg_set_binary_mode(infd) < 0)
                    perror("sg_set_binary_mode");
                if (wb_skip > 0) {
                    if (lseek(infd, wb_skip, SEEK_SET) < 0) {
                        snprintf(ebuff,  EBUFF_SZ, ME "couldn't skip to "
                                 "required position on %s", file_name);
                        perror(ebuff);
                        close(infd);
                        ret = SG_LIB_FILE_ERROR;
                        goto err_out;
                    }
                }
            }
            res = read(infd, dop, wb_len);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "couldn't read from %s",
                         file_name);
                perror(ebuff);
                if (! got_stdin)
                    close(infd);
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            }
            if (res < wb_len) {
                if (wb_len_given) {
                    pr2serr("tried to read %d bytes from %s, got %d bytes\n",
                            wb_len, file_name, res);
                    pr2serr("pad with 0xff bytes and continue\n");
                } else {
                    if (verbose) {
                        pr2serr("tried to read %d bytes from %s, got %d "
                                "bytes\n", wb_len, file_name, res);
                        pr2serr("will write %d bytes\n", res);
                    }
                    wb_len = res;
                }
            }
            if (! got_stdin)
                close(infd);
        }
    }

    res = 0;
    if (bpw > 0) {
        for (k = 0; k < wb_len; k += n) {
            n = wb_len - k;
            if (n > bpw)
                n = bpw;
            if (verbose)
                pr2serr("sending write buffer, mode=0x%x, mspec=%d, id=%d, "
                        " offset=%d, len=%d\n", wb_mode, wb_mspec, wb_id,
                        wb_offset + k, n);
            res = sg_ll_write_buffer_v2(sg_fd, wb_mode, wb_mspec, wb_id,
                                        wb_offset + k, dop + k, n, 1,
                                        verbose);
            if (res)
                break;
        }
        if (bpw_then_activate) {
            if (verbose)
                pr2serr("sending Activate deferred microcode [0xf]\n");
            res = sg_ll_write_buffer_v2(sg_fd, 0xf, 0, 0, 0, NULL, 0, 1,
                                        verbose);
        }
    } else {
        if (verbose)
            pr2serr("sending single write buffer, mode=0x%x, mpsec=%d, "
                    "id=%d, offset=%d, len=%d\n", wb_mode, wb_mspec, wb_id,
                    wb_offset, wb_len);
        res = sg_ll_write_buffer_v2(sg_fd, wb_mode, wb_mspec, wb_id,
                                    wb_offset, dop, wb_len, 1, verbose);
    }
    if (0 != res) {
        char b[80];

        ret = res;
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("Write buffer failed: %s\n", b);
    }

err_out:
    if (dop)
        free(dop);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

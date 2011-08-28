/*
 * Copyright (c) 2006-2011 Luben Tuikov and Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
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

static char * version_str = "1.10 20110825";    /* spc4r32 */

#define ME "sg_write_buffer: "
#define DEF_XFER_LEN (8 * 1024 * 1024)
#define EBUFF_SZ 256

#define WRITE_BUFFER_CMD 0x3b
#define WRITE_BUFFER_CMDLEN 10
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT 60       /* 60 seconds */

static struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"id", 1, 0, 'i'},
        {"in", 1, 0, 'I'},
        {"length", 1, 0, 'l'},
        {"mode", 1, 0, 'm'},
        {"offset", 1, 0, 'o'},
        {"raw", 0, 0, 'r'},
        {"skip", 1, 0, 's'},
        {"specific", 1, 0, 'S'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    fprintf(stderr, "Usage: "
          "sg_write_buffer [--help] [--id=ID] [--in=FILE] "
          "[--length=LEN]\n"
          "                       [--mode=MO] [--offset=OFF] [--raw] "
          "[--skip=SKIP]\n"
          "                       [--specific=MS] [--verbose] [--version] "
          "DEVICE\n"
          "  where:\n"
          "    --help|-h              print out usage message then exit\n"
          "    --id=ID|-i ID          buffer identifier (0 (default) to "
          "255)\n"
          "    --in=FILE|-I FILE      read from FILE ('-I -' read "
          "from stdin)\n"
          "    --length=LEN|-l LEN    length in bytes to write; may be "
          "deduced from FILE\n"
          "    --mode=MO|-m MO        write buffer mode, MO is number or "
          "acronym (def: 0)\n"
          "    --off=OFF|-o OFF       buffer offset (unit: bytes, def: 0)\n"
          "    --raw|-r               read from stdin (same as '-I -')\n"
          "    --skip=SKIP|-s SKIP    bytes in file FILE to skip before "
          "reading\n"
          "    --specific=MS|-S MS    mode specific value; 3 bit field "
          "(0 to 7)\n"
          "    --verbose|-v           increase verbosity\n"
          "    --version|-V           print version string and exit\n\n"
          "  Numbers given in options are decimal unless they have a "
          "hex indicator\n"
          "Performs a SCSI WRITE BUFFER command\n"
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
        char *mode_string;
        int   mode;
        char *comment;
} modes[] = {
        { "hd",         MODE_HEADER_DATA, "combined header and data"},
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
                "protocol and echo\n\t\t\t\tbuffer"},
        { "dis_ex",     MODE_DIS_EX, "disable expander communications "
                "protocol"},
        { "deh",        MODE_DNLD_ERR_HISTORY, "download error history "},
};

#define NUM_MODES       ((int)(sizeof(modes)/sizeof(modes[0])))

static void
print_modes(void)
{
    int k;

    fprintf(stderr, "The modes parameter argument can be numeric "
                "(hex or decimal)\nor symbolic:\n");
    for (k = 0; k < NUM_MODES; k++) {
        fprintf(stderr, " %2d (0x%02x)  %-18s%s\n", modes[k].mode,
                modes[k].mode, modes[k].mode_string, modes[k].comment);
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
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (verbose) {
        fprintf(sg_warnings_strm, "    Write buffer cmd: ");
        for (k = 0; k < WRITE_BUFFER_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", wbufCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
        if ((verbose > 1) && paramp && param_len) {
            fprintf(sg_warnings_strm, "    Write buffer parameter list%s:\n",
                    ((param_len > 256) ? " (first 256 bytes)" : ""));
            dStrHex((const char *)paramp,
                    ((param_len > 256) ? 256 : param_len), -1);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "write buffer: out of memory\n");
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
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
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
    int sg_fd, infd, res, c, len, k, got_stdin;
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
    char ebuff[EBUFF_SZ];
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hi:I:l:m:o:rs:S:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            ++do_help;
            break;
        case 'i':
            wb_id = sg_get_num(optarg);
            if ((wb_id < 0) || (wb_id > 255)) {
                fprintf(stderr, "argument to '--id' should be in the range "
                        "0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'I':
            file_name = optarg;
            break;
        case 'l':
            wb_len = sg_get_num(optarg);
            if (wb_len < 0) {
                fprintf(stderr, "bad argument to '--length'\n");
                return SG_LIB_SYNTAX_ERROR;
             }
             wb_len_given = 1;
             break;
        case 'm':
            if (isdigit(*optarg)) {
                wb_mode = sg_get_num(optarg);
                if ((wb_mode < 0) || (wb_mode > 31)) {
                    fprintf(stderr, "argument to '--mode' should be in the "
                            "range 0 to 31\n");
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
                fprintf(stderr, "bad argument to '--offset'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            file_name = "-";
            break;
        case 's':
           wb_skip = sg_get_num(optarg);
           if (wb_skip < 0) {
                fprintf(stderr, "bad argument to '--skip'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'S':
           wb_mspec = sg_get_num(optarg);
           if ((wb_mspec < 0) || (wb_mspec > 7)) {
                fprintf(stderr, "expected argument to '--specific' to be "
                        "0 to 7\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (do_help) {
        if (do_help > 1) {
            usage();
            fprintf(stderr, "\n");
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
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (NULL == device_name) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

#ifdef SG_LIB_WIN32
#ifdef SG_LIB_WIN32_DIRECT
    if (verbose > 4)
        fprintf(stderr, "Initial win32 SPT interface state: %s\n",
                scsi_pt_win32_spt_state() ? "direct" : "indirect");
    scsi_pt_win32_direct(SG_LIB_WIN32_DIRECT /* SPT pt interface */);
#endif
#endif

    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, verbose);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (file_name || (wb_len > 0)) {
        if (0 == wb_len)
            wb_len = DEF_XFER_LEN;
        if (NULL == (dop = (unsigned char *)malloc(wb_len))) {
            fprintf(stderr, ME "out of memory\n");
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        memset(dop, 0xff, wb_len);
        if (file_name) {
            got_stdin = (0 == strcmp(file_name, "-")) ? 1 : 0;
            if (got_stdin) {
                if (wb_skip > 0) {
                    fprintf(stderr, "Can't skip on stdin\n");
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
                    fprintf(stderr, "tried to read %d bytes from %s, got "
                            "%d bytes\n", wb_len, file_name, res);
                    fprintf(stderr, "pad with 0xff bytes and continue\n");
                } else {
                    if (verbose) {
                        fprintf(stderr, "tried to read %d bytes from %s, got "
                                "%d bytes\n", wb_len, file_name, res);
                        fprintf(stderr, "will write %d bytes\n", res);
                    }
                    wb_len = res;
                }
            }
            if (! got_stdin)
                close(infd);
        }
    }

    res = sg_ll_write_buffer_v2(sg_fd, wb_mode, wb_mspec, wb_id, wb_offset,
                                dop, wb_len, 1, verbose);
    if (0 != res) {
        ret = res;
        switch (res) {
        case SG_LIB_CAT_NOT_READY:
            fprintf(stderr, "Write buffer failed, device not ready\n");
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            fprintf(stderr, "Write buffer not done, unit attention\n");
            break;
        case SG_LIB_CAT_ABORTED_COMMAND:
            fprintf(stderr, "Write buffer, aborted command\n");
            break;
        case SG_LIB_CAT_INVALID_OP:
            fprintf(stderr, "Write buffer command not supported\n");
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            fprintf(stderr, "bad field in Write buffer cdb\n");
            break;
        default:
            fprintf(stderr, "Write buffer failed res=%d\n", res);
            break;
        }
    }

err_out:
    if (dop)
        free(dop);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

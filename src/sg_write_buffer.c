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

static char * version_str = "1.09 20110216";    /* spc4r08 */

#define ME "sg_write_buffer: "
#define DEF_XFER_LEN (8 * 1024 * 1024)
#define EBUFF_SZ 256


static struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"id", 1, 0, 'i'},
        {"in", 1, 0, 'I'},
        {"length", 1, 0, 'l'},
        {"mode", 1, 0, 'm'},
        {"offset", 1, 0, 'o'},
        {"raw", 0, 0, 'r'},
        {"skip", 1, 0, 's'},
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
          "                       [--verbose] [--version] DEVICE\n"
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
                "offsets, save and activate"},
        { "echo",       MODE_ECHO_BUFFER, "echo (spc-2)"},
        { "dmc_offs_defer", MODE_DNLD_MC_OFFS_DEFER, "download microcode "
                "with offsets, save and defer activation (spc-4)"},
        { "activate_mc", MODE_ACTIVATE_MC,
                "Activate deferred microcode (spc-4)"},
        { "en_ex",      MODE_EN_EX_ECHO, "enable expander communications "
                "protocol and echo buffer (spc-3)"},
        { "dis_ex",     MODE_DIS_EX, "disable expander communications "
                "protocol (spc-3)"},
        { "deh",        MODE_DNLD_ERR_HISTORY, "Download error history "
                "(spc-4)"},
};

#define NUM_MODES       ((int)(sizeof(modes)/sizeof(modes[0])))

static void
print_modes(void)
{
    int k;

    fprintf(stderr, "The modes parameter argument can be numeric "
                "(hex or decimal)\nor symbolic:\n");
    for (k = 0; k < NUM_MODES; k++) {
        fprintf(stderr, " %2d (0x%02x)  %-16s%s\n", modes[k].mode,
                modes[k].mode, modes[k].mode_string, modes[k].comment);
    }
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
    int verbose = 0;
    const char * device_name = NULL;
    const char * file_name = NULL;
    unsigned char * dop = NULL;
    char ebuff[EBUFF_SZ];
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hi:I:l:m:o:rs:vV", long_options,
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

    res = sg_ll_write_buffer(sg_fd, wb_mode, wb_id, wb_offset, dop,
                            wb_len, 1, verbose);
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

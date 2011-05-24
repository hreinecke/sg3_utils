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
 * This utility issues the SCSI READ BUFFER command to the given device.
 */

static char * version_str = "1.07 20110216";


static struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"id", 1, 0, 'i'},
        {"length", 1, 0, 'l'},
        {"mode", 1, 0, 'm'},
        {"offset", 1, 0, 'o'},
        {"raw", 0, 0, 'r'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};


static void
usage()
{
    fprintf(stderr, "Usage: "
          "sg_read_buffer [--help] [--hex] [--id=ID] [--length=LEN] "
          "[--mode=MO]\n"
          "                      [--offset=OFF] [--raw] [--verbose] "
          "[--version] DEVICE\n"
          "  where:\n"
          "    --help|-h           print out usage message\n"
          "    --hex|-H            print output in hex\n"
          "    --id=ID|-i ID       buffer identifier (0 (default) to 255)\n"
          "    --length=LEN|-l LEN    length in bytes to read (def: 4)\n"
          "    --mode=MO|-m MO     read buffer mode, MO is number or "
          "acronym (def: 0)\n"
          "    --off=OFF|-o OFF    buffer offset (unit: bytes, def: 0)\n"
          "    --raw|-r            output response to stdout\n"
          "    --verbose|-v        increase verbosity\n"
          "    --version|-V        print version string and exit\n\n"
          "  Numbers given in options are decimal unless they have a "
          "hex indicator\n"
          "Performs a SCSI READ BUFFER command\n"
          );

}

#define MODE_HEADER_DATA        0
#define MODE_VENDOR             1
#define MODE_DATA               2
#define MODE_DESCRIPTOR         3
#define MODE_ECHO_BUFFER        0x0A
#define MODE_ECHO_BDESC         0x0B
#define MODE_EN_EX_ECHO         0x1A
#define MODE_ERR_HISTORY        0x1C

static struct mode_s {
        char *mode_string;
        int   mode;
        char *comment;
} modes[] = {
        { "hd",         MODE_HEADER_DATA, "combined header and data"},
        { "vendor",     MODE_VENDOR,    "vendor specific"},
        { "data",       MODE_DATA,      "data"},
        { "desc",       MODE_DESCRIPTOR, "descriptor"},
        { "echo",       MODE_ECHO_BUFFER, "read data from echo buffer "
          "(spc-2)"},
        { "echo_desc",  MODE_ECHO_BDESC, "echo buffer descriptor (spc-2)"},
        { "en_ex",      MODE_EN_EX_ECHO,
          "enable expander communications protocol and echo buffer (spc-3)"},
        { "err_hist",   MODE_ERR_HISTORY, "error history (spc-4)"},
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

static void
dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

int
main(int argc, char * argv[])
{
    int sg_fd, res, c, len, k;
    int do_help = 0;
    int do_hex = 0;
    int rb_id = 0;
    int rb_len = 4;
    int rb_mode = 0;
    int rb_offset = 0;
    int do_raw = 0;
    int verbose = 0;
    const char * device_name = NULL;
    unsigned char * resp;
    int ret = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHi:l:m:o:rvV", long_options,
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
                fprintf(stderr, "argument to '--id' should be in the range "
                        "0 to 255\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'l':
            rb_len = sg_get_num(optarg);
            if (rb_len < 0) {
                fprintf(stderr, "bad argument to '--length'\n");
                return SG_LIB_SYNTAX_ERROR;
             }
             break;
        case 'm':
            if (isdigit(*optarg)) {
                rb_mode = sg_get_num(optarg);
                if ((rb_mode < 0) || (rb_mode > 31)) {
                    fprintf(stderr, "argument to '--mode' should be in the "
                            "range 0 to 31\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else {
                len = strlen(optarg);
                for (k = 0; k < NUM_MODES; ++k) {
                    if (0 == strncmp(modes[k].mode_string, optarg, len)) {
                        rb_mode = modes[k].mode;
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
           rb_offset = sg_get_num(optarg);
           if (rb_offset < 0) {
                fprintf(stderr, "bad argument to '--offset'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'r':
            ++do_raw;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
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

    if (rb_len > 0) {
        resp = (unsigned char *)malloc(rb_len);
        if (NULL == resp) {
            fprintf(stderr, "unable to allocate %d bytes on the heap\n",
                    rb_len);
            return SG_LIB_CAT_OTHER;
        }
        memset(resp, 0, rb_len);
    } else
        resp = NULL;

    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
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
        fprintf(stderr, "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    res = sg_ll_read_buffer(sg_fd, rb_mode, rb_id, rb_offset, resp,
                            rb_len, 1, verbose);
    if (0 != res) {
        ret = res;
        switch (res) {
        case SG_LIB_CAT_NOT_READY:
            fprintf(stderr, "Read buffer failed, device not ready\n");
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            fprintf(stderr, "Read buffer not done, unit attention\n");
            break;
        case SG_LIB_CAT_ABORTED_COMMAND:
            fprintf(stderr, "Read buffer, aborted command\n");
            break;
        case SG_LIB_CAT_INVALID_OP:
            fprintf(stderr, "Read buffer command not supported\n");
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            fprintf(stderr, "bad field in Read buffer cdb\n");
            break;
        default:
            fprintf(stderr, "Read buffer failed res=%d\n", res);
            break;
        }
    } else if (rb_len > 0) {
        if (do_raw)
            dStrRaw((const char *)resp, rb_len);
        else if (do_hex || (rb_len < 4))
            dStrHex((const char *)resp, rb_len, ((do_hex > 1) ? 0 : 1));
        else {
            switch (rb_mode) {
            case MODE_DESCRIPTOR:
                k = (resp[1] << 16) | (resp[2] << 8) | resp[3];
                printf("OFFSET BOUNDARY: %d, Buffer offset alignment: %d-byte\n",
                       resp[0], (1 << resp[0]));
                printf("BUFFER CAPACITY: %d (0x%x)\n", k, k);
                break;
            case MODE_ECHO_BDESC:
                k = ((resp[2] & 0x1F) << 8) | resp[3];

                printf("EBOS:%d\n", resp[0] & 1 ? 1 : 0);
                printf("Echo buffer capacity: %d (0x%x)\n", k, k);
                break;
            default:
                dStrHex((const char *)resp, rb_len, 1);
                break;
            }
        }
    }

    if (resp)
        free(resp);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

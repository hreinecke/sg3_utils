/*
 * Copyright (c) 2011 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"

static char * version_str = "0.90 20110622";

/* Not all environments support the Unix sleep() */
#if defined(MSC_VER) || defined(__MINGW32__)
#define HAVE_MS_SLEEP
#endif
#ifdef HAVE_MS_SLEEP
#include <windows.h>
#define sleep_for(seconds)    Sleep( (seconds) * 1000)
#else
#define sleep_for(seconds)    sleep(seconds)
#endif


#define ME "sg_sanitize: "

#define SANITIZE_OP 0x48
#define SANITIZE_OP_LEN 10
#define DEF_REQS_RESP_LEN 252
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define MAX_XFER_LEN 65535
#define EBUFF_SZ 256

#define SHORT_TIMEOUT 20   /* 20 seconds unless immed=0 ... */
#define LONG_TIMEOUT (15 * 3600)       /* 15 hours ! */
                /* Seagate ST32000444SS 2TB disk takes 9.5 hours to format */
#define POLL_DURATION_SECS 60


static struct option long_options[] = {
    {"block", no_argument, 0, 'B'},
    {"count", required_argument, 0, 'c'},
    {"crypto", no_argument, 0, 'C'},
    {"early", no_argument, 0, 'e'},
    {"help", no_argument, 0, 'h'},
    {"invert", no_argument, 0, 'I'},
    {"ipl", required_argument, 0, 'i'},
    {"overwrite", no_argument, 0, 'O'},
    {"pattern", required_argument, 0, 'p'},
    {"quick", no_argument, 0, 'Q'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"wait", no_argument, 0, 'w'},
    {0, 0, 0, 0},
};

struct opts_t {
    int block;
    int count;
    int crypto;
    int early;
    int invert;
    int ipl;    /* initialization pattern length */
    int overwrite;
    int quick;
    int verbose;
    int wait;
    const char * pattern_fn;
};



static void
usage()
{
  fprintf(stderr, "Usage: "
          "sg_sanitize [--block] [--count=OC] [--crypto] [--early] "
          "[--help]\n"
          "                   [--invert] [--ipl=LEN] [--overwrite] "
          "[--pattern=PF]\n"
          "                   [--quick] [--verbose] [--version] [--wait] "
          "DEVICE\n"
          "  where:\n"
          "    --block|-B           do BLOCK ERASE sanitize\n"
          "    --count=OC|-c OC     OC is overwrite count field (from 1 "
          "(def) to 31)\n"
          "    --crypto|-C          do CRYPTOGRAPHIC ERASE sanitize\n"
          "    --early|-e           exit once sanitize started (IMMED set "
          "in cdb)\n"
          "                         user can monitor progress with REQUEST "
          "SENSE\n"
          "    --help|-h            print out usage message\n"
          "    --invert|-I          set INVERT bit in OVERWRITE parameter "
          "list\n"
          "    --ipl=LEN|-i LEN     initialization pattern length (in "
          "bytes)\n"
          "    --overwrite|-O       do OVERWRITE sanitize\n"
          "    --pattern=PF|-p PF    PF is file containing initialization "
          "pattern\n"
          "                          for OVERWRITE\n"
          "    --quick|-Q           start sanitize without pause for user\n"
          "                         intervention (i.e. no time to "
          "reconsider)\n"
          "    --verbose|-v         increase verbosity\n"
          "    --version|-V         print version string then exit\n"
          "    --wait|-w            wait for command to finish (could "
          "take hours)\n\n"
          "Performs a SCSI SANITIZE command.\n    <<<WARNING>>>: all data "
          "on DEVICE will lost.\nDefault action is to give user time to "
          "reconsider; then execute SANITIZE\ncommand with IMMED bit set; "
          "then use REQUEST SENSE command every 60\nseconds to poll for a "
          "progress indication; then exit when there is no\nmore progress "
          "indication.\n"
          );
}

/* Invoke SCSI SANITIZE command. Returns 0 if successful, otherwise error */
static int
do_sanitize(int sg_fd, const struct opts_t * op, const void * param_lstp,
            int param_lst_len)
{
    int k, ret, res, sense_cat, immed;
    unsigned char sanCmdBlk[SANITIZE_OP_LEN];
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (op->early || op->wait)
        immed = op->early ? 1 : 0;
    else
        immed = 1;
    memset(sanCmdBlk, 0, sizeof(sanCmdBlk));
    sanCmdBlk[0] = SANITIZE_OP;
    if (op->overwrite)
        sanCmdBlk[1] = 1;
    else if (op->block)
        sanCmdBlk[1] = 2;
    else if (op->crypto)
        sanCmdBlk[1] = 3;
    else
        return SG_LIB_SYNTAX_ERROR;
    if (immed)
        sanCmdBlk[1] |= 0x80;
    sanCmdBlk[7] = ((param_lst_len >> 8) & 0xff);
    sanCmdBlk[8] = (param_lst_len & 0xff);

    if (op->verbose > 1) {
        fprintf(stderr, "    Sanitize cmd: ");
        for (k = 0; k < SANITIZE_OP_LEN; ++k)
            fprintf(stderr, "%02x ", sanCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    if ((op->verbose > 2) && (param_lst_len > 0)) {
        fprintf(stderr, "    Parameter list contents:\n");
        dStrHex((const char *)param_lstp, param_lst_len, 1);
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "Sanitize: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, sanCmdBlk, sizeof(sanCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)param_lstp, param_lst_len);
    res = do_scsi_pt(ptvp, sg_fd, (immed ? SHORT_TIMEOUT : LONG_TIMEOUT),
                     op->verbose);
    ret = sg_cmds_process_resp(ptvp, "Sanitize", res, 0, sense_b,
                               1 /*noisy */, op->verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            {
                int valid, slen;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                if (valid)
                    fprintf(stderr, "Medium or hardware error starting at "
                            "lba=%"PRIu64" [0x%"PRIx64"]\n", ull, ull);
            }
            ret = sense_cat;
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
    int sg_fd, k, res, c, infd, progress, vb, n, desc, resp_len;
    int got_stdin = 0;
    int param_lst_len = 0;
    const char * device_name = NULL;
    char ebuff[EBUFF_SZ];
    char pdt_name[32];
    unsigned char requestSenseBuff[DEF_REQS_RESP_LEN];
    unsigned char * wBuff = NULL;
    int ret = -1;
    struct opts_t opts;
    struct stat a_stat;
    struct sg_simple_inquiry_resp inq_out;

    memset(&opts, 0, sizeof(opts));
    opts.count = 1;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "Bc:Cehi:IOp:QvVw", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'B':
            ++opts.block;
            break;
        case 'c':
            opts.count = sg_get_num(optarg);
            if ((opts.count < 1) || (opts.count > 31))  {
                fprintf(stderr, "bad argument to '--count', expect 1 to "
                        "31\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'C':
            ++opts.crypto;
            break;
        case 'e':
            ++opts.early;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            opts.ipl = sg_get_num(optarg);
            if ((opts.ipl < 1) || (opts.ipl > 65535))  {
                fprintf(stderr, "bad argument to '--ipl', expect 1 to "
                        "65535\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'I':
            ++opts.invert;
            break;
        case 'O':
            ++opts.overwrite;
            break;
        case 'p':
            opts.pattern_fn = optarg;
            break;
        case 'Q':
            ++opts.quick;
            break;
        case 'v':
            ++opts.verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        case 'w':
            ++opts.wait;
            break;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
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
    vb = opts.verbose;
    n = !!opts.block + !!opts.crypto + !!opts.overwrite;
    if (1 != n) {
        fprintf(stderr, "one and only one of '--block', '--crypto' or "
                "'--overwrite' please\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.overwrite) {
        if (NULL == opts.pattern_fn) {
            fprintf(stderr, "'--overwrite' requires '--pattern=PF' "
                    "option\n");
            return SG_LIB_SYNTAX_ERROR;
        }
        got_stdin = (0 == strcmp(opts.pattern_fn, "-")) ? 1 : 0;
        if (! got_stdin) {
            memset(&a_stat, 0, sizeof(a_stat));
            if (stat(opts.pattern_fn, &a_stat) < 0) {
                if (vb)
                    fprintf(stderr, "unable to stat(%s): %s\n",
                            opts.pattern_fn, safe_strerror(errno));
                return SG_LIB_FILE_ERROR;
            }
            if (opts.ipl <= 0) {
                opts.ipl = (int)a_stat.st_size;
                if (opts.ipl > MAX_XFER_LEN) {
                    fprintf(stderr, "pattern file length exceeds 65535 "
                            "bytes, need '--ipl=LEN' option\n");
                     return SG_LIB_FILE_ERROR;
                }
            }
        }
        if (opts.ipl < 1) {
            fprintf(stderr, "'--overwrite' requires '--ipl=LEN' "
                    "option if can't get PF length\n");
            return SG_LIB_SYNTAX_ERROR;
        }

    }
    
    sg_fd = sg_cmds_open_device(device_name, 0 /* rw */, vb);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: %s\n", device_name,
                safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }

    if (sg_simple_inquiry(sg_fd, &inq_out, 1, vb)) {
            fprintf(stderr, "%s doesn't respond to a SCSI INQUIRY\n",
                    device_name);
            ret = SG_LIB_CAT_OTHER;
            goto err_out;
    }
    printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n",
           inq_out.vendor, inq_out.product, inq_out.revision,
           sg_get_pdt_str(inq_out.peripheral_type, sizeof(pdt_name),
                          pdt_name),
           inq_out.peripheral_type);


    if (opts.overwrite) {
        param_lst_len = opts.ipl + 4;
        wBuff = (unsigned char*)calloc(opts.ipl + 4, 1);
        if (NULL == wBuff) {
            fprintf(stderr, "unable to allocate %d bytes of memory with "
                    "calloc()\n", opts.ipl + 4);
            ret = SG_LIB_SYNTAX_ERROR;
            goto err_out;
        }
        if (got_stdin) {
            infd = STDIN_FILENO;
            if (sg_set_binary_mode(STDIN_FILENO) < 0)
                perror("sg_set_binary_mode");
        } else {
            if ((infd = open(opts.pattern_fn, O_RDONLY)) < 0) {
                snprintf(ebuff, EBUFF_SZ,
                         ME "could not open %s for reading", opts.pattern_fn);
                perror(ebuff);
                ret = SG_LIB_FILE_ERROR;
                goto err_out;
            } else if (sg_set_binary_mode(infd) < 0)
                perror("sg_set_binary_mode");
        }
        res = read(infd, wBuff + 4, opts.ipl);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, ME "couldn't read from %s",
                     opts.pattern_fn);
            perror(ebuff);
            if (! got_stdin)
                close(infd);
            ret = SG_LIB_FILE_ERROR;
            goto err_out;
        }
        if (res < opts.ipl) {
            fprintf(stderr, "tried to read %d bytes from %s, got %d "
                    "bytes\n", opts.ipl, opts.pattern_fn, res);
            fprintf(stderr, "  so pad with 0x0 bytes and continue\n");
        }
        if (! got_stdin)
            close(infd);

        wBuff[0] = opts.count;
        if (opts.invert)
            wBuff[0] |= 0x80;
        wBuff[2] = ((opts.ipl >> 8) & 0xff);
        wBuff[3] = (opts.ipl & 0xff);
    }

    if (0 == opts.quick) {
        printf("\nA SANITIZE will commence in 15 seconds\n");
        printf("    ALL data on %s will be DESTROYED\n", device_name);
        printf("        Press control-C to abort\n");
        sleep_for(5);
        printf("\nA SANITIZE will commence in 10 seconds\n");
        printf("    ALL data on %s will be DESTROYED\n", device_name);
        printf("        Press control-C to abort\n");
        sleep_for(5);
        printf("\nA SANITIZE will commence in 5 seconds\n");
        printf("    ALL data on %s will be DESTROYED\n", device_name);
        printf("        Press control-C to abort\n");
        sleep_for(5);
    }

    ret = do_sanitize(sg_fd, &opts, wBuff, param_lst_len);
    if (ret) {
        switch (ret) {
        case SG_LIB_CAT_NOT_READY:
            fprintf(stderr, "Sanitize failed, device not ready\n");
            break;
        case SG_LIB_CAT_UNIT_ATTENTION:
            fprintf(stderr, "Sanitize, unit attention\n");
            break;
        case SG_LIB_CAT_ABORTED_COMMAND:
            fprintf(stderr, "Sanitize, aborted command\n");
            break;
        case SG_LIB_CAT_INVALID_OP:
            fprintf(stderr, "Sanitize command not supported\n");
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            fprintf(stderr, "bad field in Sanitize cdb, option "
                    "probably not supported\n");
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            fprintf(stderr, "Sanitize command reported medium or "
                    "hardware error\n");
            break;
        default:
            fprintf(stderr, "Sanitize command failed\n");
            break;
        }
    }

    if ((0 == ret) && (0 == opts.early) && (0 == opts.wait)) {
        for (k = 0, desc = 1 ;; ++k) {
            sleep_for(POLL_DURATION_SECS);
            memset(requestSenseBuff, 0x0, sizeof(requestSenseBuff));
            res = sg_ll_request_sense(sg_fd, desc, requestSenseBuff,
                                      sizeof(requestSenseBuff), 1, vb);
            if (res) {
                ret = res;
                if (SG_LIB_CAT_INVALID_OP == res)
                    fprintf(stderr, "Request Sense command not supported\n");
                else if (SG_LIB_CAT_ILLEGAL_REQ == res) {
                    fprintf(stderr, "bad field in Request Sense cdb\n");
                    if (1 == desc) {
                        fprintf(stderr, "Descriptor type sense may not be "
                                "supported, try again with fixed type\n");
                        desc = 0;
                        continue;
                    }
                }
                else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                    fprintf(stderr, "Request Sense, aborted command\n");
                else {
                    fprintf(stderr, "Request Sense command unexpectedly "
                            "failed\n");
                    if (0 == vb)
                        fprintf(stderr, "    try the '-v' option for "
                                "more information\n");
                }
                break;
            }
            /* "Additional sense length" same in descriptor and fixed */
            resp_len = requestSenseBuff[7] + 8;
            if (vb > 2) {
                fprintf(stderr, "Parameter data in hex\n");
                dStrHex((const char *)requestSenseBuff, resp_len, 1);
            }
            progress = -1;
            sg_get_sense_progress_fld(requestSenseBuff, resp_len,
                                      &progress);
            if (progress < 0) {
                ret = res;
                if (vb > 1)
                     fprintf(stderr, "No progress indication found, "
                             "iteration %d\n", k + 1);
                /* N.B. exits first time there isn't a progress indication */
                break;
            } else
                printf("Progress indication: %d%% done\n",
                       (progress * 100) / 65536);
        }
    }

err_out:
    if (wBuff)
        free(wBuff);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

/*
 * Copyright (c) 2011-2019 Douglas Gilbert.
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
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.14 20191220";

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
#define SANITIZE_SA_OVERWRITE 0x1
#define SANITIZE_SA_BLOCK_ERASE 0x2
#define SANITIZE_SA_CRYPTO_ERASE 0x3
#define SANITIZE_SA_EXIT_FAIL_MODE 0x1f
#define DEF_REQS_RESP_LEN 252
#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define MAX_XFER_LEN 65535
#define EBUFF_SZ 256

#define SHORT_TIMEOUT 20   /* 20 seconds unless immed=0 ... */
#define LONG_TIMEOUT (15 * 3600)       /* 15 hours ! */
                /* Seagate ST32000444SS 2TB disk takes 9.5 hours to format */
#define POLL_DURATION_SECS 60


static struct option long_options[] = {
    {"ause", no_argument, 0, 'A'},
    {"block", no_argument, 0, 'B'},
    {"count", required_argument, 0, 'c'},
    {"crypto", no_argument, 0, 'C'},
    {"desc", no_argument, 0, 'd'},
    {"dry-run", no_argument, 0, 'D'},
    {"dry_run", no_argument, 0, 'D'},
    {"early", no_argument, 0, 'e'},
    {"fail", no_argument, 0, 'F'},
    {"help", no_argument, 0, 'h'},
    {"invert", no_argument, 0, 'I'},
    {"ipl", required_argument, 0, 'i'},
    {"overwrite", no_argument, 0, 'O'},
    {"pattern", required_argument, 0, 'p'},
    {"quick", no_argument, 0, 'Q'},
    {"test", required_argument, 0, 'T'},
    {"timeout", required_argument, 0, 't'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"wait", no_argument, 0, 'w'},
    {"zero", no_argument, 0, 'z'},
    {0, 0, 0, 0},
};

struct opts_t {
    bool ause;
    bool block;
    bool crypto;
    bool desc;
    bool dry_run;
    bool early;
    bool fail;
    bool invert;
    bool overwrite;
    bool quick;
    bool verbose_given;
    bool version_given;
    bool wait;
    bool znr;
    int count;
    int ipl;    /* initialization pattern length */
    int test;
    int timeout;        /* in seconds */
    int verbose;
    int zero;
    const char * pattern_fn;
};


static void
usage()
{
  pr2serr("Usage: sg_sanitize [--ause] [--block] [--count=OC] [--crypto] "
          "[--dry-run]\n"
          "                   [--early] [--fail] [--help] [--invert] "
          "[--ipl=LEN]\n"
          "                   [--overwrite] [--pattern=PF] [--quick] "
          "[--test=TE]\n"
          "                   [--timeout=SECS] [--verbose] [--version] "
          "[--wait]\n"
          "                   [--zero] [--znr] DEVICE\n"
          "  where:\n"
          "    --ause|-A            set AUSE bit in cdb\n"
          "    --block|-B           do BLOCK ERASE sanitize\n"
          "    --count=OC|-c OC     OC is overwrite count field (from 1 "
          "(def) to 31)\n"
          "    --crypto|-C          do CRYPTOGRAPHIC ERASE sanitize\n"
          "    --desc|-d            polling request sense sets 'desc' "
          "field\n"
          "                         (def: clear 'desc' field)\n"
          "    --dry-run|-D         to preparation but bypass SANITIZE "
          "commnd\n"
          "    --early|-e           exit once sanitize started (IMMED set "
          "in cdb)\n"
          "                         user can monitor progress with REQUEST "
          "SENSE\n"
          "    --fail|-F            do EXIT FAILURE MODE sanitize\n"
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
          "    --test=TE|-T TE      TE is placed in TEST field of "
          "OVERWRITE\n"
          "                         parameter list (def: 0)\n"
          "    --timeout=SECS|-t SECS    SANITIZE command timeout in "
          "seconds\n"
          "    --verbose|-v         increase verbosity\n"
          "    --version|-V         print version string then exit\n"
          "    --wait|-w            wait for command to finish (could "
          "take hours)\n"
          "    --zero|-z            use pattern of zeros for "
          "OVERWRITE\n"
          "    --znr|-Z             set ZNR (zone no reset) bit in cdb\n\n"
          "Performs a SCSI SANITIZE command.\n    <<<WARNING>>>: all data "
          "on DEVICE will be lost.\nDefault action is to give user time to "
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
    bool immed;
    int ret, res, sense_cat, timeout;
    uint8_t san_cdb[SANITIZE_OP_LEN];
    uint8_t sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (op->early || op->wait)
        immed = op->early;
    else
        immed = true;
    timeout = (immed ? SHORT_TIMEOUT : LONG_TIMEOUT);
    /* only use command line timeout if it exceeds previous defaults */
    if (op->timeout > timeout)
        timeout = op->timeout;
    memset(san_cdb, 0, sizeof(san_cdb));
    san_cdb[0] = SANITIZE_OP;
    if (op->overwrite)
        san_cdb[1] = SANITIZE_SA_OVERWRITE;
    else if (op->block)
        san_cdb[1] = SANITIZE_SA_BLOCK_ERASE;
    else if (op->crypto)
        san_cdb[1] = SANITIZE_SA_CRYPTO_ERASE;
    else if (op->fail)
        san_cdb[1] = SANITIZE_SA_EXIT_FAIL_MODE;
    else
        return SG_LIB_SYNTAX_ERROR;
    if (immed)
        san_cdb[1] |= 0x80;
    if (op->znr)        /* added sbc4r07 */
        san_cdb[1] |= 0x40;
    if (op->ause)
        san_cdb[1] |= 0x20;
    sg_put_unaligned_be16((uint16_t)param_lst_len, san_cdb + 7);

    if (op->verbose > 1) {
        char b[128];

        pr2serr("    Sanitize cdb: %s\n",
                sg_get_command_str(san_cdb, SANITIZE_OP_LEN, false,
                                   sizeof(b), b));
        if (op->verbose > 2) {
            if (param_lst_len > 0) {
                pr2serr("    Parameter list contents:\n");
                hex2stderr((const uint8_t *)param_lstp, param_lst_len, -1);
            }
            pr2serr("    Sanitize command timeout: %d seconds\n", timeout);
        }
    }
    if (op->dry_run) {
        pr2serr("Due to --dry-run option, bypassing SANITIZE command\n");
        return 0;
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("Sanitize: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, san_cdb, sizeof(san_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (uint8_t *)param_lstp, param_lst_len);
    res = do_scsi_pt(ptvp, sg_fd, timeout, op->verbose);
    ret = sg_cmds_process_resp(ptvp, "Sanitize", res, true /*noisy */,
                               op->verbose, &sense_cat);
    if (-1 == ret)
        ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            {
                bool valid;
                int slen;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                if (valid)
                    pr2serr("Medium or hardware error starting at "
                            "lba=%" PRIu64 " [0x%" PRIx64 "]\n", ull, ull);
            }
            ret = sense_cat;
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

#define VPD_DEVICE_ID 0x83
#define VPD_ASSOC_LU 0
#define VPD_ASSOC_TPORT 1
#define TPROTO_ISCSI 5

static char *
get_lu_name(const uint8_t * bp, int u_len, char * b, int b_len)
{
    int len, off, sns_dlen, dlen, k;
    uint8_t u_sns[512];
    char * cp;

    len = u_len - 4;
    bp += 4;
    off = -1;
    if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                8 /* SCSI name string (sns) */,
                                3 /* UTF-8 */)) {
        sns_dlen = bp[off + 3];
        memcpy(u_sns, bp + off + 4, sns_dlen);
        /* now want to check if this is iSCSI */
        off = -1;
        if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_TPORT,
                                    8 /* SCSI name string (sns) */,
                                    3 /* UTF-8 */)) {
            if ((0x80 & bp[1]) && (TPROTO_ISCSI == (bp[0] >> 4))) {
                snprintf(b, b_len, "%.*s", sns_dlen, u_sns);
                return b;
            }
        }
    } else
        sns_dlen = 0;
    if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                3 /* NAA */, 1 /* binary */)) {
        dlen = bp[off + 3];
        if (! ((8 == dlen) || (16 ==dlen)))
            return b;
        cp = b;
        for (k = 0; ((k < dlen) && (b_len > 1)); ++k) {
            snprintf(cp, b_len, "%02x", bp[off + 4 + k]);
            cp += 2;
            b_len -= 2;
        }
    } else if (0 == sg_vpd_dev_id_iter(bp, len, &off, VPD_ASSOC_LU,
                                       2 /* EUI */, 1 /* binary */)) {
        dlen = bp[off + 3];
        if (! ((8 == dlen) || (12 == dlen) || (16 ==dlen)))
            return b;
        cp = b;
        for (k = 0; ((k < dlen) && (b_len > 1)); ++k) {
            snprintf(cp, b_len, "%02x", bp[off + 4 + k]);
            cp += 2;
            b_len -= 2;
        }
    } else if (sns_dlen > 0)
        snprintf(b, b_len, "%.*s", sns_dlen, u_sns);
    return b;
}

#define SAFE_STD_INQ_RESP_LEN 36
#define VPD_SUPPORTED_VPDS 0x0
#define VPD_UNIT_SERIAL_NUM 0x80
#define VPD_DEVICE_ID 0x83

static int
print_dev_id(int fd, uint8_t * sinq_resp, int max_rlen, int verbose)
{
    int res, k, n, verb, pdt, has_sn, has_di;
    uint8_t b[256];
    char a[256];
    char pdt_name[64];

    verb = (verbose > 1) ? verbose - 1 : 0;
    memset(sinq_resp, 0, max_rlen);
    res = sg_ll_inquiry(fd, false, false /* evpd */, 0 /* pg_op */, b,
                        SAFE_STD_INQ_RESP_LEN, 1, verb);
    if (res)
        return res;
    n = b[4] + 5;
    if (n > SAFE_STD_INQ_RESP_LEN)
        n = SAFE_STD_INQ_RESP_LEN;
    memcpy(sinq_resp, b, (n < max_rlen) ? n : max_rlen);
    if (n == SAFE_STD_INQ_RESP_LEN) {
        pdt = b[0] & 0x1f;
        printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n",
               (const char *)(b + 8), (const char *)(b + 16),
               (const char *)(b + 32),
               sg_get_pdt_str(pdt, sizeof(pdt_name), pdt_name), pdt);
        if (verbose)
            printf("      PROTECT=%d\n", !!(b[5] & 1));
        if (b[5] & 1)
            printf("      << supports protection information>>\n");
    } else {
        pr2serr("Short INQUIRY response: %d bytes, expect at least 36\n", n);
        return SG_LIB_CAT_OTHER;
    }
    res = sg_ll_inquiry(fd, false, true /* evpd */, VPD_SUPPORTED_VPDS, b,
                        SAFE_STD_INQ_RESP_LEN, 1, verb);
    if (res) {
        if (verbose)
            pr2serr("VPD_SUPPORTED_VPDS gave res=%d\n", res);
        return 0;
    }
    if (VPD_SUPPORTED_VPDS != b[1]) {
        if (verbose)
            pr2serr("VPD_SUPPORTED_VPDS corrupted\n");
        return 0;
    }
    n = sg_get_unaligned_be16(b + 2);
    if (n > (SAFE_STD_INQ_RESP_LEN - 4))
        n = (SAFE_STD_INQ_RESP_LEN - 4);
    for (k = 0, has_sn = 0, has_di = 0; k < n; ++k) {
        if (VPD_UNIT_SERIAL_NUM == b[4 + k])
            ++has_sn;
        else if (VPD_DEVICE_ID == b[4 + k]) {
            ++has_di;
            break;
        }
    }
    if (has_sn) {
        res = sg_ll_inquiry(fd, false, true /* evpd */, VPD_UNIT_SERIAL_NUM,
                            b, sizeof(b), 1, verb);
        if (res) {
            if (verbose)
                pr2serr("VPD_UNIT_SERIAL_NUM gave res=%d\n", res);
            return 0;
        }
        if (VPD_UNIT_SERIAL_NUM != b[1]) {
            if (verbose)
                pr2serr("VPD_UNIT_SERIAL_NUM corrupted\n");
            return 0;
        }
        n = sg_get_unaligned_be16(b + 2);
        if (n > (int)(sizeof(b) - 4))
            n = (sizeof(b) - 4);
        printf("      Unit serial number: %.*s\n", n, (const char *)(b + 4));
    }
    if (has_di) {
        res = sg_ll_inquiry(fd, false, true /* evpd */, VPD_DEVICE_ID, b,
                            sizeof(b), 1, verb);
        if (res) {
            if (verbose)
                pr2serr("VPD_DEVICE_ID gave res=%d\n", res);
            return 0;
        }
        if (VPD_DEVICE_ID != b[1]) {
            if (verbose)
                pr2serr("VPD_DEVICE_ID corrupted\n");
            return 0;
        }
        n = sg_get_unaligned_be16(b + 2);
        if (n > (int)(sizeof(b) - 4))
            n = (sizeof(b) - 4);
        n = strlen(get_lu_name(b, n + 4, a, sizeof(a)));
        if (n > 0)
            printf("      LU name: %.*s\n", n, a);
    }
    return 0;
}


int
main(int argc, char * argv[])
{
    bool got_stdin = false;
    int k, res, c, infd, progress, vb, n, resp_len, err;
    int sg_fd = -1;
    int param_lst_len = 0;
    int ret = -1;
    const char * device_name = NULL;
    char ebuff[EBUFF_SZ];
    char b[80];
    uint8_t rsBuff[DEF_REQS_RESP_LEN];
    uint8_t * wBuff = NULL;
    uint8_t * free_wBuff = NULL;
    struct opts_t opts;
    struct opts_t * op;
    struct stat a_stat;
    uint8_t inq_resp[SAFE_STD_INQ_RESP_LEN];

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->count = 1;
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "ABc:CdDeFhi:IOp:Qt:T:vVwzZ",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'A':
            op->ause = true;
            break;
        case 'B':
            op->block = true;
            break;
        case 'c':
            op->count = sg_get_num(optarg);
            if ((op->count < 1) || (op->count > 31))  {
                pr2serr("bad argument to '--count', expect 1 to 31\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'C':
            op->crypto = true;
            break;
        case 'd':
            op->desc = true;
            break;
        case 'D':
            op->dry_run = true;
            break;
        case 'e':
            op->early = true;
            break;
        case 'F':
            op->fail = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'i':
            op->ipl = sg_get_num(optarg);
            if ((op->ipl < 1) || (op->ipl > 65535))  {
                pr2serr("bad argument to '--ipl', expect 1 to 65535\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'I':
            op->invert = true;
            break;
        case 'O':
            op->overwrite = true;
            break;
        case 'p':
            op->pattern_fn = optarg;
            break;
        case 'Q':
            op->quick = true;
            break;
        case 't':
            op->timeout = sg_get_num(optarg);
            if (op->timeout < 0) {
                pr2serr("bad argument to '--timeout=SECS', want 0 or more\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'T':
            op->test = sg_get_num(optarg);
            if ((op->test < 0) || (op->test > 3))  {
                pr2serr("bad argument to '--test', expect 0 to 3\n");
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
        case 'w':
            op->wait = true;
            break;
        case 'z':
            ++op->zero;
            break;
        case 'Z':
            op->znr = true;
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n", c);
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
        pr2serr(ME "version: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("Missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    vb = op->verbose;
    n = (int)op->block + (int)op->crypto + (int)op->fail + (int)op->overwrite;
    if (1 != n) {
        pr2serr("one and only one of '--block', '--crypto', '--fail' or "
                "'--overwrite' please\n");
        return SG_LIB_CONTRADICT;
    }
    if (op->overwrite) {
        if (op->zero) {
            if (op->pattern_fn) {
                pr2serr("confused: both '--pattern=PF' and '--zero' "
                        "options\n");
                return SG_LIB_CONTRADICT;
            }
            op->ipl = 4;
        } else {
            if (NULL == op->pattern_fn) {
                pr2serr("'--overwrite' requires '--pattern=PF' or '--zero' "
                        "option\n");
                return SG_LIB_CONTRADICT;
            }
            got_stdin = (0 == strcmp(op->pattern_fn, "-"));
            if (! got_stdin) {
                memset(&a_stat, 0, sizeof(a_stat));
                if (stat(op->pattern_fn, &a_stat) < 0) {
                    err = errno;
                    pr2serr("pattern file: unable to stat(%s): %s\n",
                            op->pattern_fn, safe_strerror(err));
                    ret = sg_convert_errno(err);
                    goto err_out;
                }
                if (op->ipl <= 0) {
                    op->ipl = (int)a_stat.st_size;
                    if (op->ipl > MAX_XFER_LEN) {
                        pr2serr("pattern file length exceeds 65535 bytes, "
                                "need '--ipl=LEN' option\n");
                         return SG_LIB_FILE_ERROR;
                    }
                }
            }
            if (op->ipl < 1) {
                pr2serr("'--overwrite' requires '--ipl=LEN' option if can't "
                        "get PF length\n");
                return SG_LIB_CONTRADICT;
            }
        }
    }

    sg_fd = sg_cmds_open_device(device_name, false /* rw */, vb);
    if (sg_fd < 0) {
        if (op->verbose)
            pr2serr(ME "open error: %s: %s\n", device_name,
                    safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto err_out;
    }

    ret = print_dev_id(sg_fd, inq_resp, sizeof(inq_resp), op->verbose);
    if (ret)
        goto err_out;

    if (op->overwrite) {
        param_lst_len = op->ipl + 4;
        wBuff = (uint8_t*)sg_memalign(op->ipl + 4, 0, &free_wBuff, false);
        if (NULL == wBuff) {
            pr2serr("unable to allocate %d bytes of memory with calloc()\n",
                    op->ipl + 4);
            ret = sg_convert_errno(ENOMEM);
            goto err_out;
        }
        if (op->zero) {
            if (2 == op->zero)  /* treat -zz as fill with 0xff bytes */
                memset(wBuff + 4, 0xff, op->ipl);
            else
                memset(wBuff + 4, 0, op->ipl);
        } else {
            if (got_stdin) {
                infd = STDIN_FILENO;
                if (sg_set_binary_mode(STDIN_FILENO) < 0)
                    perror("sg_set_binary_mode");
            } else {
                if ((infd = open(op->pattern_fn, O_RDONLY)) < 0) {
                    err = errno;
                    snprintf(ebuff, EBUFF_SZ, ME "could not open %s for "
                             "reading", op->pattern_fn);
                    perror(ebuff);
                    ret = sg_convert_errno(err);
                    goto err_out;
                } else if (sg_set_binary_mode(infd) < 0)
                    perror("sg_set_binary_mode");
            }
            res = read(infd, wBuff + 4, op->ipl);
            if (res < 0) {
                err = errno;
                snprintf(ebuff, EBUFF_SZ, ME "couldn't read from %s",
                         op->pattern_fn);
                perror(ebuff);
                if (! got_stdin)
                    close(infd);
                ret = sg_convert_errno(err);
                goto err_out;
            }
            if (res < op->ipl) {
                pr2serr("tried to read %d bytes from %s, got %d bytes\n",
                         op->ipl, op->pattern_fn, res);
                pr2serr("  so pad with 0x0 bytes and continue\n");
            }
            if (! got_stdin)
                close(infd);
        }
        wBuff[0] = op->count & 0x1f;
        if (op->test)
            wBuff[0] |= ((op->test & 0x3) << 5);
        if (op->invert)
            wBuff[0] |= 0x80;
        sg_put_unaligned_be16((uint16_t)op->ipl, wBuff + 2);
    }

    if ((! op->quick) && (! op->fail)) {
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

    ret = do_sanitize(sg_fd, op, wBuff, param_lst_len);
    if (ret) {
        sg_get_category_sense_str(ret, sizeof(b), b, vb);
        pr2serr("Sanitize failed: %s\n", b);
    }

    if ((0 == ret) && (! op->early) && (! op->wait)) {
        for (k = 0; ;++k) {     /* unbounded, exits via break */
            if (op->dry_run && (k > 0)) {
                pr2serr("Due to --dry-run option, leave poll loop\n");
                break;
            }
            sleep_for(POLL_DURATION_SECS);
            memset(rsBuff, 0x0, sizeof(rsBuff));
            res = sg_ll_request_sense(sg_fd, op->desc, rsBuff, sizeof(rsBuff),
                                      1, vb);
            if (res) {
                ret = res;
                if (SG_LIB_CAT_INVALID_OP == res)
                    pr2serr("Request Sense command not supported\n");
                else if (SG_LIB_CAT_ILLEGAL_REQ == res) {
                    pr2serr("bad field in Request Sense cdb\n");
                    if (op->desc) {
                        pr2serr("Descriptor type sense may not be supported, "
                                "try again with fixed type\n");
                        op->desc = false;
                        continue;
                    }
                } else {
                    sg_get_category_sense_str(res, sizeof(b), b, vb);
                    pr2serr("Request Sense: %s\n", b);
                    if (0 == vb)
                        pr2serr("    try the '-v' option for more "
                                "information\n");
                }
                break;
            }
            /* "Additional sense length" same in descriptor and fixed */
            resp_len = rsBuff[7] + 8;
            if (vb > 2) {
                pr2serr("Parameter data in hex\n");
                hex2stderr(rsBuff, resp_len, -1);
            }
            progress = -1;
            sg_get_sense_progress_fld(rsBuff, resp_len, &progress);
            if (progress < 0) {
                ret = res;
                if (vb > 1)
                     pr2serr("No progress indication found, iteration %d\n",
                             k + 1);
                /* N.B. exits first time there isn't a progress indication */
                break;
            } else
                printf("Progress indication: %d%% done\n",
                       (progress * 100) / 65536);
        }
    }

err_out:
    if (free_wBuff)
        free(free_wBuff);
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == op->verbose) {
        if (! sg_if_can2stderr("sg_sanitize failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

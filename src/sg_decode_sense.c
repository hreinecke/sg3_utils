/*
 * Copyright (c) 2010-2019 Douglas Gilbert.
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
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_pr2serr.h"
#include "sg_unaligned.h"


static const char * version_str = "1.21 20190602";

#define MAX_SENSE_LEN 1024 /* max descriptor format actually: 255+8 */

static struct option long_options[] = {
    {"binary", required_argument, 0, 'b'},
    {"cdb", no_argument, 0, 'c'},
    {"err", required_argument, 0, 'e'},
    {"exit-status", required_argument, 0, 'e'},
    {"exit_status", required_argument, 0, 'e'},
    {"file", required_argument, 0, 'f'},
    {"help", no_argument, 0, 'h'},
    {"hex", no_argument, 0, 'H'},
    {"nospace", no_argument, 0, 'n'},
    {"status", required_argument, 0, 's'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {"write", required_argument, 0, 'w'},
    {0, 0, 0, 0},
};

struct opts_t {
    bool do_binary;
    bool do_cdb;
    bool do_help;
    bool do_hex;
    bool no_space;
    bool do_status;
    bool verbose_given;
    bool version_given;
    bool err_given;
    bool file_given;
    const char * fname;
    int es_val;
    int sense_len;
    int sstatus;
    int verbose;
    const char * wfname;
    const char * no_space_str;
    uint8_t sense[MAX_SENSE_LEN + 4];
};

static char concat_buff[1024];


static void
usage()
{
  pr2serr("Usage: sg_decode_sense [--binary=BFN] [--cdb] [--err=ES] "
          "[--file=HFN]\n"
          "                       [--help] [--hex] [--nospace] [--status=SS] "
          "[--verbose]\n"
          "                       [--version] [--write=WFN] H1 H2 H3 ...\n"
          "  where:\n"
          "    --binary=BFN|-b BFN    BFN is a file name to read sense "
          "data in\n"
          "                          binary from. If BFN is '-' then read "
          "from stdin\n"
          "    --cdb|-c              decode given hex as cdb rather than "
          "sense data\n"
          "    --err=ES|-e ES        ES is Exit Status from utility in this "
          "package\n"
          "    --file=HFN|-f HFN     HFN is a file name from which to read "
          "sense data\n"
          "                          in ASCII hexadecimal. Interpret '-' "
          "as stdin\n"
          "    --help|-h             print out usage message\n"
          "    --hex|-H              used together with --write=WFN, to "
          "write out\n"
          "                          C language style ASCII hex (instead "
          "of binary)\n"
          "    --nospace|-n          no spaces or other separators between "
          "pairs of\n"
          "                          hex digits (e.g. '3132330A')\n"
          "    --status=SS |-s SS    SCSI status value in hex\n"
          "    --verbose|-v          increase verbosity\n"
          "    --version|-V          print version string then exit\n"
          "    --write=WFN |-w WFN    write sense data in binary to WFN, "
          "create if\n"
          "                           required else truncate prior to "
          "writing\n\n"
          "Decodes SCSI sense data given on the command line as a sequence "
          "of\nhexadecimal bytes (H1 H2 H3 ...) . Alternatively the sense "
          "data can\nbe in a binary file or in a file containing ASCII "
          "hexadecimal. If\n'--cdb' is given then interpret hex as SCSI CDB "
          "rather than sense data.\n"
          );
}

static int
parse_cmd_line(struct opts_t *op, int argc, char *argv[])
{
    int c, n;
    unsigned int ui;
    long val;
    char * avp;
    char *endptr;

    while (1) {
        c = getopt_long(argc, argv, "b:ce:f:hHns:vVw:", long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            if (op->fname) {
                pr2serr("expect only one '--binary=BFN' or '--file=BFN' "
                        "option\n");
                return SG_LIB_CONTRADICT;
            }
            op->do_binary = true;
            op->fname = optarg;
            break;
        case 'c':
            op->do_cdb = true;
            break;
        case 'e':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 255)) {
                pr2serr("--err= expected number from 0 to 255 inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->err_given = true;
            op->es_val = n;
            break;
        case 'f':
            if (op->fname) {
                pr2serr("expect only one '--binary=HFN' or '--file=HFN' "
                        "option\n");
                return SG_LIB_CONTRADICT;
            }
            op->file_given = true;
            op->fname = optarg;
            break;
        case 'h':
        case '?':
            op->do_help = true;
            return 0;
        case 'H':
            op->do_hex = true;
            break;
        case 'n':
            op->no_space = true;
            break;
        case 's':
            if (1 != sscanf(optarg, "%x", &ui)) {
                pr2serr("'--status=SS' expects a byte value\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (ui > 0xff) {
                pr2serr("'--status=SS' byte value exceeds FF\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_status = true;
            op->sstatus = ui;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'w':
            op->wfname = optarg;
            break;
        default:
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (op->err_given)
        goto the_end;

    while (optind < argc) {
        avp = argv[optind++];
        if (op->no_space) {
            if (op->no_space_str) {
                if ('\0' == concat_buff[0]) {
                    if (strlen(op->no_space_str) > sizeof(concat_buff)) {
                        pr2serr("'--nospace' concat_buff overflow\n");
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    strcpy(concat_buff, op->no_space_str);
                }
                if ((strlen(concat_buff) + strlen(avp)) >=
                    sizeof(concat_buff)) {
                    pr2serr("'--nospace' concat_buff overflow\n");
                    return SG_LIB_SYNTAX_ERROR;
                }
                if (op->version_given)
                    pr2serr("'--nospace' and found whitespace so "
                            "concatenate\n");
                strcat(concat_buff, avp);
                op->no_space_str = concat_buff;
            } else
                op->no_space_str = avp;
            continue;
        }
        val = strtol(avp, &endptr, 16);
        if (*avp == '\0' || *endptr != '\0' || val < 0x00 || val > 0xff) {
            pr2serr("Invalid byte '%s'\n", avp);
            return SG_LIB_SYNTAX_ERROR;
        }

        if (op->sense_len > MAX_SENSE_LEN) {
            pr2serr("sense data too long (max. %d bytes)\n", MAX_SENSE_LEN);
            return SG_LIB_SYNTAX_ERROR;
        }
        op->sense[op->sense_len++] = (uint8_t)val;
    }
the_end:
    return 0;
}

static void
write2wfn(FILE * fp, struct opts_t * op)
{
    int k, n;
    size_t s;
    char b[128];

    if (op->do_hex) {
        for (k = 0, n = 0; k < op->sense_len; ++k) {
            n += sprintf(b + n, "0x%02x,", op->sense[k]);
            if (15 == (k % 16)) {
                b[n] = '\n';
                s = fwrite(b, 1, n + 1, fp);
                if ((int)s != (n + 1))
                    pr2serr("only able to write %d of %d bytes to %s\n",
                            (int)s, n + 1, op->wfname);
                n = 0;
            }
        }
        if (n > 0) {
            b[n] = '\n';
            s = fwrite(b, 1, n + 1, fp);
            if ((int)s != (n + 1))
                pr2serr("only able to write %d of %d bytes to %s\n", (int)s,
                        n + 1, op->wfname);
        }
    } else {
        s = fwrite(op->sense, 1, op->sense_len, fp);
        if ((int)s != op->sense_len)
            pr2serr("only able to write %d of %d bytes to %s\n", (int)s,
                    op->sense_len, op->wfname);
    }
}


int
main(int argc, char *argv[])
{
    int k, err;
    int ret = 0;
    unsigned int ui;
    size_t s;
    struct opts_t * op;
    FILE * fp = NULL;
    const char * cp;
    char b[2048];
    struct opts_t opts;

    op = &opts;
    memset(op, 0, sizeof(opts));
    memset(b, 0, sizeof(b));
    ret = parse_cmd_line(op, argc, argv);

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
    if (ret != 0) {
        usage();
        return ret;
    } else if (op->do_help) {
        usage();
        return 0;
    }

    if (op->err_given) {
        char d[128];
        const int dlen = sizeof(d);

        if (! sg_exit2str(op->es_val, op->verbose > 1, dlen, d))
            snprintf(d, dlen, "Unable to decode exit status %d", op->es_val);
        if (1 & op->verbose) /* odd values of verbose print to stderr */
            pr2serr("%s\n", d);
        else    /* even values of verbose (including not given) to stdout */
            printf("%s\n", d);
        goto fini;
    }

    if (op->do_status) {
        sg_get_scsi_status_str(op->sstatus, sizeof(b) - 1, b);
        printf("SCSI status: %s\n", b);
    }

    if ((0 == op->sense_len) && op->no_space_str) {
        if (op->verbose > 2)
            pr2serr("no_space str: %s\n", op->no_space_str);
        cp = op->no_space_str;
        for (k = 0; isxdigit(cp[k]) && isxdigit(cp[k + 1]); k += 2) {
            if (1 != sscanf(cp + k, "%2x", &ui)) {
                pr2serr("bad no_space hex string: %s\n", cp);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->sense[op->sense_len++] = (uint8_t)ui;
        }
    }

    if ((0 == op->sense_len) && (! op->do_binary) && (! op->file_given)) {
        if (op->do_status)
            return 0;
        pr2serr(">> Need sense data on the command line or in a file\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->sense_len && (op->do_binary || op->file_given)) {
        pr2serr(">> Need sense data on command line or in a file, not "
                "both\n\n");
        return SG_LIB_CONTRADICT;
    }
    if (op->do_binary && op->file_given) {
        pr2serr(">> Either a binary file or a ASCII hexadecimal, file not "
                "both\n\n");
        return SG_LIB_CONTRADICT;
    }

    if (op->do_binary) {
        fp = fopen(op->fname, "r");
        if (NULL == fp) {
            err = errno;
            pr2serr("unable to open file: %s: %s\n", op->fname,
                    safe_strerror(err));
            return sg_convert_errno(err);
        }
        s = fread(op->sense, 1, MAX_SENSE_LEN, fp);
        fclose(fp);
        if (0 == s) {
            pr2serr("read nothing from file: %s\n", op->fname);
            return SG_LIB_SYNTAX_ERROR;
        }
        op->sense_len = s;
    } else if (op->file_given) {
        ret = sg_f2hex_arr(op->fname, false, op->no_space, op->sense,
                           &op->sense_len, MAX_SENSE_LEN);
        if (ret) {
            pr2serr("unable to decode ASCII hex from file: %s\n", op->fname);
            return ret;
        }
    }

    if (op->sense_len) {
        if (op->wfname) {
            if ((fp = fopen(op->wfname, "w"))) {
                write2wfn(fp, op);
                fclose(fp);
            } else {
                err =errno;
                perror("open");
                pr2serr("trying to write to %s\n", op->wfname);
                ret = sg_convert_errno(err);
            }
        }
        if (op->do_cdb) {
            int sa, opcode;

            opcode = op->sense[0];
            if ((0x75 == opcode) || (0x7e == opcode) || (op->sense_len > 16))
                sa = sg_get_unaligned_be16(op->sense + 8);
            else if (op->sense_len > 1)
                sa = op->sense[1] & 0x1f;
            else
                sa = 0;
            sg_get_opcode_sa_name(opcode, sa, 0, sizeof(b), b);
        } else
            sg_get_sense_str(NULL, op->sense, op->sense_len,
                             op->verbose, sizeof(b) - 1, b);
        printf("%s\n", b);
    }
fini:
    return ret;
}

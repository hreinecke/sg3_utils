/*
 * Copyright (c) 2010-2017 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
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


static const char * version_str = "1.12 20171005";

#define MAX_SENSE_LEN 1024 /* max descriptor format actually: 256+8 */

static struct option long_options[] = {
    {"binary", required_argument, 0, 'b'},
    {"cdb", no_argument, 0, 'c'},
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
    bool no_space;
    bool do_status;
    bool do_version;
    const char * fname;
    int do_file;
    int do_help;
    int do_hex;
    int sstatus;
    int do_verbose;
    const char * wfname;
    unsigned char sense[MAX_SENSE_LEN + 4];
    const char * no_space_str;
    int sense_len;
};

static char concat_buff[1024];


static void
usage()
{
  pr2serr("Usage: sg_decode_sense [--binary=FN] [--cdb] [--file=FN] "
          "[--help] [--hex]\n"
          "                       [--nospace] [--status=SS] [--verbose] "
          "[--version]\n"
          "                       [--write=WFN] H1 H2 H3 ...\n"
          "  where:\n"
          "    --binary=FN|-b FN     FN is a file name to read sense "
          "data in\n"
          "                          binary from. If FN is '-' then read "
          "from stdin\n"
          "    --cdb|-c              decode given hex as cdb rather than "
          "sense data\n"
          "    --file=FN|-f FN       FN is a file name from which to read "
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
process_cl(struct opts_t *op, int argc, char *argv[])
{
    int c;
    unsigned int ui;
    long val;
    char * avp;
    char *endptr;

    while (1) {
        c = getopt_long(argc, argv, "b:cf:hHns:vVw:", long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            if (op->fname) {
                pr2serr("expect only one '--binary=FN' or '--file=FN' "
                        "option\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_binary = true;
            op->fname = optarg;
            break;
        case 'c':
            op->do_cdb = true;
            break;
        case 'f':
            if (op->fname) {
                pr2serr("expect only one '--binary=FN' or '--file=FN' "
                        "option\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++op->do_file;
            op->fname = optarg;
            break;
        case 'h':
        case '?':
            op->do_help = 1;
            return 0;
        case 'H':
            ++op->do_hex;
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
            ++op->do_verbose;
            break;
        case 'V':
            op->do_version = true;
            break;
        case 'w':
            op->wfname = optarg;
            break;
        default:
            return SG_LIB_SYNTAX_ERROR;
        }
    }

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
                if (op->do_version)
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
        op->sense[op->sense_len++] = (unsigned char)val;
    }
    return 0;
}

/* Read ASCII hex bytes from fname (a file named '-' taken as stdin).
 * There should be either one entry per line or a comma, space or tab
 * separated list of bytes. If no_space is set then a string of ACSII hex
 * digits is expected, 2 per byte. Everything from and including a '#'
 * on a line is ignored.  Returns 0 if ok, or 1 if error. */
static int
f2hex_arr(const char * fname, bool no_space, unsigned char * mp_arr,
          int * mp_arr_len, int max_arr_len)
{
    int fn_len, in_len, k, j, m, split_line;
    unsigned int h;
    const char * lcp;
    FILE * fp;
    char line[512];
    char carry_over[4];
    int off = 0;

    if ((NULL == fname) || (NULL == mp_arr) || (NULL == mp_arr_len))
        return 1;
    fn_len = strlen(fname);
    if (0 == fn_len)
        return 1;
    if ((1 == fn_len) && ('-' == fname[0]))        /* read from stdin */
        fp = stdin;
    else {
        fp = fopen(fname, "r");
        if (NULL == fp) {
            pr2serr("Unable to open %s for reading\n", fname);
            return 1;
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
                    pr2serr("f2hex_arr: carry_over error ['%s'] around line "
                            "%d\n", carry_over, j + 1);
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
            pr2serr("f2hex_arr: syntax error at line %d, pos %d\n", j + 1,
                    m + k + 1);
            goto bad;
        }
        if (no_space) {
            for (k = 0; isxdigit(*lcp) && isxdigit(*(lcp + 1));
                 ++k, lcp += 2) {
                if (1 != sscanf(lcp, "%2x", &h)) {
                    pr2serr("f2hex_arr: bad hex number in line %d, pos %d\n",
                            j + 1, (int)(lcp - line + 1));
                    goto bad;
                }
                if ((off + k) >= max_arr_len) {
                    pr2serr("f2hex_arr: array length exceeded\n");
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
                        pr2serr("f2hex_arr: hex number larger than 0xff in "
                                "line %d, pos %d\n", j + 1,
                                (int)(lcp - line + 1));
                        goto bad;
                    }
                    if (split_line && (1 == strlen(lcp))) {
                        /* single trailing hex digit might be a split pair */
                        carry_over[0] = *lcp;
                    }
                    if ((off + k) >= max_arr_len) {
                        pr2serr("f2hex_arr: array length exceeded\n");
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
                    pr2serr("f2hex_arr: error in line %d, at pos %d\n", j + 1,
                            (int)(lcp - line + 1));
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
    int k;
    int ret = 0;
    unsigned int ui;
    size_t s;
    struct opts_t opts;
    struct opts_t * op;
    char b[2048];
    FILE * fp = NULL;
    const char * cp;

    op = &opts;
    memset(op, 0, sizeof(opts));
    memset(b, 0, sizeof(b));
    ret = process_cl(op, argc, argv);
    if (ret != 0) {
        usage();
        return ret;
    } else if (op->do_help) {
        usage();
        return 0;
    } else if (op->do_version) {
        pr2serr("version: %s\n", version_str);
        return 0;
    }


    if (op->do_status) {
        sg_get_scsi_status_str(op->sstatus, sizeof(b) - 1, b);
        printf("SCSI status: %s\n", b);
    }

    if ((0 == op->sense_len) && op->no_space_str) {
        if (op->do_verbose > 2)
            pr2serr("no_space str: %s\n", op->no_space_str);
        cp = op->no_space_str;
        for (k = 0; isxdigit(cp[k]) && isxdigit(cp[k + 1]); k += 2) {
            if (1 != sscanf(cp + k, "%2x", &ui)) {
                pr2serr("bad no_space hex string: %s\n", cp);
                return SG_LIB_SYNTAX_ERROR;
            }
            op->sense[op->sense_len++] = (unsigned char)ui;
        }
    }

    if ((0 == op->sense_len) && (! op->do_binary) && (! op->do_file)) {
        if (op->do_status)
            return 0;
        pr2serr(">> Need sense data on the command line or in a file\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->sense_len && (op->do_binary || op->do_file)) {
        pr2serr(">> Need sense data on command line or in a file, not "
                "both\n\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->do_binary && op->do_file) {
        pr2serr(">> Either a binary file or a ASCII hexadecimal, file not "
                "both\n\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    if (op->do_binary) {
        fp = fopen(op->fname, "r");
        if (NULL == fp) {
            pr2serr("unable to open file: %s\n", op->fname);
            return SG_LIB_SYNTAX_ERROR;
        }
        s = fread(op->sense, 1, MAX_SENSE_LEN, fp);
        fclose(fp);
        if (0 == s) {
            pr2serr("read nothing from file: %s\n", op->fname);
            return SG_LIB_SYNTAX_ERROR;
        }
        op->sense_len = s;
    } else if (op->do_file) {
        ret = f2hex_arr(op->fname, op->no_space, op->sense, &op->sense_len,
                        MAX_SENSE_LEN);
        if (ret) {
            pr2serr("unable to decode ASCII hex from file: %s\n", op->fname);
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (op->sense_len) {
        if (op->wfname) {
            if ((fp = fopen(op->wfname, "w"))) {
                write2wfn(fp, op);
                fclose(fp);
            } else {
                perror("open");
                pr2serr("trying to write to %s\n", op->wfname);
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
                             op->do_verbose, sizeof(b) - 1, b);
        printf("%s\n", b);
    }

    return 0;
}

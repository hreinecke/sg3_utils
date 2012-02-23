/*
 * Copyright (c) 2010-2011 Douglas Gilbert.
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


static char * version_str = "1.03 20110524";

#define MAX_SENSE_LEN 1024 /* max descriptor format actually: 256+8 */

static struct option long_options[] = {
    {"binary", required_argument, 0, 'b'},
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
    int do_binary;
    const char * fname;
    int do_file;
    int do_help;
    int do_hex;
    int no_space;
    int do_status;
    int sstatus;
    int do_verbose;
    int do_version;
    const char * wfname;
    unsigned char sense[MAX_SENSE_LEN + 4];
    const char * no_space_str;
    int sense_len;
};


static void
usage()
{
  fprintf(stderr, "Usage: "
          "sg_decode_sense [--binary=FN] [--file=FN] [--help] [--hex] "
          "[--nospace]\n"
          "                       [--status=SS] [--verbose] [--version] "
          "[--write=WFN]\n"
          "                       [H1 H2 H3 ...]\n"
          "  where:\n"
          "    --binary=FN|-b FN     FN is a file name to read sense "
          "data in\n"
          "                          binary from. If FN is '-' then read "
          "from stdin\n"
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
          "hexadecimal.\n"
          );
}

static int
process_cl(struct opts_t *optsp, int argc, char *argv[])
{
    int c;
    unsigned int ui;
    char * opt;
    char *endptr;
    long val;

    while (1) {
        c = getopt_long(argc, argv, "b:f:hHns:vVw:", long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            if (optsp->fname) {
                fprintf(stderr, "expect only one '--binary=FN' or "
                        "'--file=FN' option\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++optsp->do_binary;
            optsp->fname = optarg;
            break;
        case 'f':
            if (optsp->fname) {
                fprintf(stderr, "expect only one '--binary=FN' or "
                        "'--file=FN' option\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++optsp->do_file;
            optsp->fname = optarg;
            break;
        case 'h':
        case '?':
            optsp->do_help = 1;
            return 0;
        case 'H':
            ++optsp->do_hex;
            break;
        case 'n':
            ++optsp->no_space;
            break;
        case 's':
            if (1 != sscanf(optarg, "%x", &ui)) {
                fprintf(stderr, "'--status=SS' expects a byte value\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (ui > 0xff) {
                fprintf(stderr, "'--status=SS' byte value exceeds FF\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++optsp->do_status;
            optsp->sstatus = ui;
            break;
        case 'v':
            ++optsp->do_verbose;
            break;
        case 'V':
            optsp->do_version = 1;
            return 0;
        case 'w':
            optsp->wfname = optarg;
            break;
        default:
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    while (optind < argc) {
        opt = argv[optind++];
        if (optsp->no_space) {
            if (optsp->no_space_str) {
                fprintf(stderr, "With '--nospace' only want a single string "
                        "of hex digits, extra: '%s'\n", opt);
                return SG_LIB_SYNTAX_ERROR;
            } else {
                optsp->no_space_str = opt;
                continue;
            }
        }
        val = strtol(opt, &endptr, 16);
        if (*opt == '\0' || *endptr != '\0' || val < 0x00 || val > 0xff) {
            fprintf(stderr, "Invalid byte '%s'\n", opt);
            return SG_LIB_SYNTAX_ERROR;
        }

        if (optsp->sense_len > MAX_SENSE_LEN) {
            fprintf(stderr, "sense data too long (max. %d bytes)\n",
                    MAX_SENSE_LEN);
            return SG_LIB_SYNTAX_ERROR;
        }
        optsp->sense[optsp->sense_len++] = (unsigned char)val;
    }
    return 0;
}

/* Read ASCII hex bytes from fname (a file named '-' taken as stdin).
 * There should be either one entry per line or a comma, space or tab
 * separated list of bytes. If no_space is set then a string of ACSII hex
 * digits is expected, 2 per byte. Everything from and including a '#'
 * on a line is ignored.  Returns 0 if ok, or 1 if error. */
static int
f2hex_arr(const char * fname, int no_space, unsigned char * mp_arr,
          int * mp_arr_len, int max_arr_len)
{
    int fn_len, in_len, k, j, m;
    unsigned int h;
    const char * lcp;
    FILE * fp;
    char line[512];
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
            fprintf(stderr, "Unable to open %s for reading\n", fname);
            return 1;
        }
    }

    for (j = 0; j < 512; ++j) {
        if (NULL == fgets(line, sizeof(line), fp))
            break;
        in_len = strlen(line);
        if (in_len > 0) {
            if ('\n' == line[in_len - 1]) {
                --in_len;
                line[in_len] = '\0';
            }
        }
        if (0 == in_len)
            continue;
        lcp = line;
        m = strspn(lcp, " \t");
        if (m == in_len)
            continue;
        lcp += m;
        in_len -= m;
        if ('#' == *lcp)
            continue;
        k = strspn(lcp, "0123456789aAbBcCdDeEfF ,\t");
        if ((k < in_len) && ('#' != lcp[k])) {
            fprintf(stderr, "f2hex_arr: syntax error at line %d, pos %d\n",
                    j + 1, m + k + 1);
            goto bad;
        }
        if (no_space) {
            for (k = 0; isxdigit(*lcp) && isxdigit(*(lcp + 1));
                 ++k, lcp += 2) {
                if (1 != sscanf(lcp, "%2x", &h)) {
                    fprintf(stderr, "f2hex_arr: bad hex number in line %d, "
                            "pos %d\n", j + 1, (int)(lcp - line + 1));
                    goto bad;
                }
                if ((off + k) >= max_arr_len) {
                    fprintf(stderr, "f2hex_arr: array length exceeded\n");
                    goto bad;
                }
                mp_arr[off + k] = h;
            }
            off += k;
        } else {
            for (k = 0; k < 1024; ++k) {
                if (1 == sscanf(lcp, "%x", &h)) {
                    if (h > 0xff) {
                        fprintf(stderr, "f2hex_arr: hex number larger than "
                                "0xff in line %d, pos %d\n", j + 1,
                                (int)(lcp - line + 1));
                        goto bad;
                    }
                    if ((off + k) >= max_arr_len) {
                        fprintf(stderr, "f2hex_arr: array length exceeded\n");
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
                    if ('#' == *lcp) {
                        --k;
                        break;
                    }
                    fprintf(stderr, "f2hex_arr: error in line %d, at pos "
                            "%d\n", j + 1, (int)(lcp - line + 1));
                    goto bad;
                }
            }
            off += (k + 1);
        }
    }
    *mp_arr_len = off;
    fclose(fp);
    return 0;
bad:
    fclose(fp);
    return 1;
}

static void
write2wfn(FILE * fp, struct opts_t * optsp)
{
    int k, n;
    size_t s;
    char b[128];

    if (optsp->do_hex) {
        for (k = 0, n = 0; k < optsp->sense_len; ++k) {
            n += sprintf(b + n, "0x%02x,", optsp->sense[k]);
            if (15 == (k % 16)) {
                b[n] = '\n';
                s = fwrite(b, 1, n + 1, fp);
                n = 0;
            }
        }
        if (n > 0) { 
            b[n] = '\n';
            s = fwrite(b, 1, n + 1, fp);
        }
    } else {
        s = fwrite(optsp->sense, 1, optsp->sense_len, fp);
        if ((int)s != optsp->sense_len)
            fprintf(stderr, "only able to write %d of %d bytes to %s\n",
                    (int)s, optsp->sense_len, optsp->wfname);
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
    char b[2048];
    FILE * fp = NULL;
    const char * cp;

    memset(&opts, 0, sizeof(opts));
    memset(b, 0, sizeof(b));
    ret = process_cl(&opts, argc, argv);
    if (ret != 0) {
        usage();
        return ret;
    } else if (opts.do_help) {
        usage();
        return 0;
    } else if (opts.do_version) {
        fprintf(stderr, "version: %s\n", version_str);
        return 0;
    }


    if (opts.do_status) {
        sg_get_scsi_status_str(opts.sstatus, sizeof(b) - 1, b);
        printf("SCSI status: %s\n", b);
    }

    if ((0 == opts.sense_len) && opts.no_space_str) {
        cp = opts.no_space_str;
        for (k = 0; isxdigit(cp[k]) && isxdigit(cp[k + 1]); k += 2) {
            if (1 != sscanf(cp + k, "%2x", &ui)) {
                fprintf(stderr, "bad no_space hex string: %s\n", cp);
                return SG_LIB_SYNTAX_ERROR;
            }
            opts.sense[opts.sense_len++] = (unsigned char)ui;
        }
    }

    if ((0 == opts.sense_len) && (! opts.do_binary) && (! opts.do_file)) {
        if (opts.do_status)
            return 0;
        fprintf(stderr, ">> Need sense data on the command line or in a "
                "file\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.sense_len && (opts.do_binary || opts.do_file)) {
        fprintf(stderr, ">> Need sense data on command line or in a file, "
                "not both\n\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    if (opts.do_binary && opts.do_file) {
        fprintf(stderr, ">> Either a binary file or a ASCII hexadecimal, "
                "file not both\n\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    if (opts.do_binary) {
        fp = fopen(opts.fname, "r");
        if (NULL == fp) {
            fprintf(stderr, "unable to open file: %s\n", opts.fname);
            return SG_LIB_SYNTAX_ERROR;
        }
        s = fread(opts.sense, 1, MAX_SENSE_LEN, fp);
        fclose(fp);
        if (0 == s) {
            fprintf(stderr, "read nothing from file: %s\n", opts.fname);
            return SG_LIB_SYNTAX_ERROR;
        }
        opts.sense_len = s;
    } else if (opts.do_file) {
        ret = f2hex_arr(opts.fname, opts.no_space, opts.sense,
                        &opts.sense_len, MAX_SENSE_LEN);
        if (ret) {
            fprintf(stderr, "unable to decode ASCII hex from file: %s\n",
                    opts.fname);
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (opts.sense_len) {
        if (opts.wfname) {
            if ((fp = fopen(opts.wfname, "w"))) {
                write2wfn(fp, &opts);
                fclose(fp);
            } else {
                perror("open");
                fprintf(stderr, "trying to write to %s\n", opts.wfname);
            }
        }
        sg_get_sense_str(NULL, opts.sense, opts.sense_len, opts.do_verbose,
                         sizeof(b) - 1, b);
        printf("%s\n", b);
    }

    return 0;
}

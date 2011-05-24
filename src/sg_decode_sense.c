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
#include <sys/types.h>
#include <sys/stat.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"


static char * version_str = "1.02 20110209";

#define MAX_SENSE_LEN (256 + 8) /* max descriptor format currently */

static struct option long_options[] = {
    {"binary", required_argument, 0, 'b'},
    {"file", required_argument, 0, 'f'},
    {"help", no_argument, 0, 'h'},
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
    int do_status;
    int sstatus;
    int do_verbose;
    int do_version;
    const char * wfname;
    unsigned char sense[MAX_SENSE_LEN + 4];
    int sense_len;
};


static void
usage()
{
  fprintf(stderr, "Usage: "
          "sg_decode_sense [--binary=FN] [--file=FN] [--help] [--status=SS]\n"
          "                       [--verbose] [--version] [--write=WFN] "
          "[H1 H2 H3 ...]\n"
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
    unsigned int ul;
    char * opt;
    char *endptr;
    long val;

    while (1) {
        c = getopt_long(argc, argv, "b:f:hs:vVw:", long_options, NULL);
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
        case 's':
            if (1 != sscanf(optarg, "%x", &ul)) {
                fprintf(stderr, "'--status=SS' expects a byte value\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            if (ul > 0xff) {
                fprintf(stderr, "'--status=SS' byte value exceeds FF\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            ++optsp->do_status;
            optsp->sstatus = ul;
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

/* Read hex numbers from file ('-' taken as stdin).
 * There should be either one entry per line, a comma separated list or
 * space separated list. Everything from and including a '#' on a line
 * is ignored.  Returns 0 if ok, or 1 if error. */
static int file2hex_arr(const char * fname, unsigned char * mp_arr,
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
            fprintf(stderr, "build_mode_page: syntax error at "
                    "line %d, pos %d\n", j + 1, m + k + 1);
            goto bad;
        }
        for (k = 0; k < 1024; ++k) {
            if (1 == sscanf(lcp, "%x", &h)) {
                if (h > 0xff) {
                    fprintf(stderr, "build_mode_page: hex number "
                            "larger than 0xff in line %d, pos %d\n",
                            j + 1, (int)(lcp - line + 1));
                    goto bad;
                }
                if ((off + k) >= max_arr_len) {
                    fprintf(stderr, "build_mode_page: array length "
                            "exceeded\n");
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
                fprintf(stderr, "build_mode_page: error in "
                        "line %d, at pos %d\n", j + 1,
                        (int)(lcp - line + 1));
                goto bad;
            }
        }
        off += (k + 1);
    }
    *mp_arr_len = off;
    fclose(fp);
    return 0;
bad:
    fclose(fp);
    return 1;
}


int
main(int argc, char *argv[])
{
    int ret = 0;
    size_t s;
    struct opts_t opts;
    char b[2048];
    FILE * fp = NULL;

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
        ret = file2hex_arr(opts.fname, opts.sense, &opts.sense_len,
                           MAX_SENSE_LEN);
        if (ret) {
            fprintf(stderr, "unable to decode ASCII hex from file: %s\n",
                    opts.fname);
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (opts.sense_len) {
        if (opts.wfname) {
            if ((fp = fopen(opts.wfname, "w"))) {
                s = fwrite(opts.sense, 1, opts.sense_len, fp);
                if ((int)s != opts.sense_len)
                    fprintf(stderr, "only able to write %d of %d bytes to "
                            "%s\n", s, opts.sense_len, opts.wfname);
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

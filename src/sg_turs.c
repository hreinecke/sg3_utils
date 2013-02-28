/* This program sends a user specified number of TEST UNIT READY commands
   to the given sg device. Since TUR is a simple command involing no
   data transfer (and no REQUEST SENSE command iff the unit is ready)
   then this can be used for timing per SCSI command overheads.

 * Copyright (C) 2000-2013 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifndef SG_LIB_MINGW
#include <sys/time.h>
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"


static char * version_str = "3.29 20130228";

#if defined(MSC_VER) || defined(__MINGW32__)
#define HAVE_MS_SLEEP
#endif

#ifdef HAVE_MS_SLEEP
#include <windows.h>
#define sleep_for(seconds)    Sleep( (seconds) * 1000)
#else
#define sleep_for(seconds)    sleep(seconds)
#endif

static struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"new", 0, 0, 'N'},
        {"number", 1, 0, 'n'},
        {"old", 0, 0, 'O'},
        {"progress", 0, 0, 'p'},
        {"time", 0, 0, 't'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    int do_help;
    int do_number;
    int do_progress;
    int do_time;
    int do_verbose;
    int do_version;
    const char * device_name;
    int opt_new;
};


static void usage()
{
    printf("Usage: sg_turs [--help] [--number=NUM] [--progress] [--time] "
           "[--verbose]\n"
           "               [--version] DEVICE\n"
           "  where:\n"
           "    --help|-h        print usage message then exit\n"
           "    --number=NUM|-n NUM    number of test_unit_ready commands "
           "(def: 1)\n"
           "    --progress|-p    outputs progress indication (percentage) "
           "if available\n"
           "    --time|-t        outputs total duration and commands per "
           "second\n"
           "    --verbose|-v     increase verbosity\n"
           "    --version|-V     print version string then exit\n\n"
           "Performs a SCSI TEST UNIT READY command (or many of them)\n");
}

static void usage_old()
{
    printf("Usage: sg_turs [-n=NUM] [-p] [-t] [-v] [-V] "
           "DEVICE\n"
           "  where:\n"
           "    -n=NUM    number of test_unit_ready commands "
           "(def: 1)\n"
           "    -p        outputs progress indication (percentage) "
           "if available\n"
           "    -t        outputs total duration and commands per "
           "second\n"
           "    -v        increase verbosity\n"
           "    -V        print version string then exit\n\n"
           "Performs a SCSI TEST UNIT READY command (or many of them)\n");
}

static void usage_for(const struct opts_t * optsp)
{
    if (optsp->opt_new)
        usage();
    else
        usage_old();
}

static int process_cl_new(struct opts_t * optsp, int argc, char * argv[])
{
    int c, n;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hn:NOptvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            ++optsp->do_help;
            break;
        case 'n':
            n = sg_get_num(optarg);
            if (n < 0) {
                fprintf(stderr, "bad argument to '--number='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            optsp->do_number = n;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            optsp->opt_new = 0;
            return 0;
        case 'p':
            ++optsp->do_progress;
            break;
        case 't':
            ++optsp->do_time;
            break;
        case 'v':
            ++optsp->do_verbose;
            break;
        case 'V':
            ++optsp->do_version;
            break;
        default:
            fprintf(stderr, "unrecognised option code %c [0x%x]\n", c, c);
            if (optsp->do_help)
                break;
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == optsp->device_name) {
            optsp->device_name = argv[optind];
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
    return 0;
}

static int process_cl_old(struct opts_t * optsp, int argc, char * argv[])
{
    int k, jmp_out, plen;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'N':
                    optsp->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'p':
                    ++optsp->do_progress;
                    break;
                case 't':
                    ++optsp->do_time;
                    break;
                case 'v':
                    ++optsp->do_verbose;
                    break;
                case 'V':
                    ++optsp->do_verbose;
                    break;
                case '?':
                    usage_old();
                    return 0;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("n=", cp, 2)) {
                optsp->do_number = sg_get_num(cp + 2);
                if (optsp->do_number <= 0) {
                    printf("Couldn't decode number after 'n=' option\n");
                    usage_old();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else if (0 == strncmp("-old", cp, 4))
                ;
            else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == optsp->device_name)
            optsp->device_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", optsp->device_name, cp);
            usage_old();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int process_cl(struct opts_t * optsp, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        optsp->opt_new = 0;
        res = process_cl_old(optsp, argc, argv);
        if ((0 == res) && optsp->opt_new)
            res = process_cl_new(optsp, argc, argv);
    } else {
        optsp->opt_new = 1;
        res = process_cl_new(optsp, argc, argv);
        if ((0 == res) && (0 == optsp->opt_new))
            res = process_cl_old(optsp, argc, argv);
    }
    return res;
}

int main(int argc, char * argv[])
{
    int sg_fd, k, res, progress, pr, rem;
    int num_errs = 0;
    int reported = 0;
    int ret = 0;
#ifndef SG_LIB_MINGW
    struct timeval start_tm, end_tm;
#endif
    struct opts_t opts;

    memset(&opts, 0, sizeof(opts));
    opts.do_number = 1;
    res = process_cl(&opts, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (opts.do_help) {
        usage_for(&opts);
        return 0;
    }
    if (opts.do_version) {
        fprintf(stderr, "Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == opts.device_name) {
        fprintf(stderr, "No DEVICE argument given\n");
        usage_for(&opts);
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((sg_fd = sg_cmds_open_device(opts.device_name, 1 /* ro */,
                                     opts.do_verbose)) < 0) {
        fprintf(stderr, "sg_turs: error opening file: %s: %s\n",
                opts.device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (opts.do_progress) {
        for (k = 0; k < opts.do_number; ++k) {
            if (k > 0)
                sleep_for(30);
            progress = -1;
            res = sg_ll_test_unit_ready_progress(sg_fd, k, &progress,
                     ((1 == opts.do_number) ? 1 : 0), opts.do_verbose);
            if (progress < 0) {
                ret = res;
                break;
            } else {
                pr = (progress * 100) / 65536;
                rem = ((progress * 100) % 65536) / 655;
                printf("Progress indication: %d.%02d%% done\n", pr, rem);
            }
        }
        if (opts.do_number > 1)
            printf("Completed %d Test Unit Ready commands\n",
                   ((k < opts.do_number) ? k + 1 : k));
    } else {
#ifndef SG_LIB_MINGW
        if (opts.do_time) {
            start_tm.tv_sec = 0;
            start_tm.tv_usec = 0;
            gettimeofday(&start_tm, NULL);
        }
#endif
        for (k = 0; k < opts.do_number; ++k) {
            /* Might get Unit Attention on first invocation */
            res = sg_ll_test_unit_ready(sg_fd, k, (0 == k), opts.do_verbose);
            if (res) {
                ++num_errs;
                ret = res;
                if ((1 == opts.do_number) && (SG_LIB_CAT_NOT_READY == res)) {
                    printf("device not ready\n");
                    reported = 1;
                    break;
                }
            }
        }
#ifndef SG_LIB_MINGW
        if ((opts.do_time) && (start_tm.tv_sec || start_tm.tv_usec)) {
            struct timeval res_tm;
            double a, b;

            gettimeofday(&end_tm, NULL);
            res_tm.tv_sec = end_tm.tv_sec - start_tm.tv_sec;
            res_tm.tv_usec = end_tm.tv_usec - start_tm.tv_usec;
            if (res_tm.tv_usec < 0) {
                --res_tm.tv_sec;
                res_tm.tv_usec += 1000000;
            }
            a = res_tm.tv_sec;
            a += (0.000001 * res_tm.tv_usec);
            b = (double)opts.do_number;
            printf("time to perform commands was %d.%06d secs",
                   (int)res_tm.tv_sec, (int)res_tm.tv_usec);
            if (a > 0.00001)
                printf("; %.2f operations/sec\n", b / a);
            else
                printf("\n");
        }
#endif

        if (((opts.do_number > 1) || (num_errs > 0)) && (! reported))
            printf("Completed %d Test Unit Ready commands with %d errors\n",
                   opts.do_number, num_errs);
    }
    sg_cmds_close_device(sg_fd);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

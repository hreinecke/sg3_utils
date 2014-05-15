/* This program sends a user specified number of TEST UNIT READY commands
 * to the given sg device. Since TUR is a simple command involing no
 * data transfer (and no REQUEST SENSE command iff the unit is ready)
 * then this can be used for timing per SCSI command overheads.
 *
 * Copyright (C) 2000-2014 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
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


static const char * version_str = "3.30 20140514";

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

static void usage_for(const struct opts_t * op)
{
    if (op->opt_new)
        usage();
    else
        usage_old();
}

static int process_cl_new(struct opts_t * op, int argc, char * argv[])
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
            ++op->do_help;
            break;
        case 'n':
            n = sg_get_num(optarg);
            if (n < 0) {
                fprintf(stderr, "bad argument to '--number='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_number = n;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opt_new = 0;
            return 0;
        case 'p':
            ++op->do_progress;
            break;
        case 't':
            ++op->do_time;
            break;
        case 'v':
            ++op->do_verbose;
            break;
        case 'V':
            ++op->do_version;
            break;
        default:
            fprintf(stderr, "unrecognised option code %c [0x%x]\n", c, c);
            if (op->do_help)
                break;
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == op->device_name) {
            op->device_name = argv[optind];
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

static int process_cl_old(struct opts_t * op, int argc, char * argv[])
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
                    op->opt_new = 1;
                    return 0;
                case 'O':
                    break;
                case 'p':
                    ++op->do_progress;
                    break;
                case 't':
                    ++op->do_time;
                    break;
                case 'v':
                    ++op->do_verbose;
                    break;
                case 'V':
                    ++op->do_verbose;
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
                op->do_number = sg_get_num(cp + 2);
                if (op->do_number <= 0) {
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
        } else if (0 == op->device_name)
            op->device_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", op->device_name, cp);
            usage_old();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int process_cl(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opt_new = 0;
        res = process_cl_old(op, argc, argv);
        if ((0 == res) && op->opt_new)
            res = process_cl_new(op, argc, argv);
    } else {
        op->opt_new = 1;
        res = process_cl_new(op, argc, argv);
        if ((0 == res) && (0 == op->opt_new))
            res = process_cl_old(op, argc, argv);
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
    struct opts_t * op;
    char b[80];

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->do_number = 1;
    res = process_cl(op, argc, argv);
    if (res)
        return SG_LIB_SYNTAX_ERROR;
    if (op->do_help) {
        usage_for(op);
        return 0;
    }
    if (op->do_version) {
        fprintf(stderr, "Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == op->device_name) {
        fprintf(stderr, "No DEVICE argument given\n");
        usage_for(op);
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((sg_fd = sg_cmds_open_device(op->device_name, 1 /* ro */,
                                     op->do_verbose)) < 0) {
        fprintf(stderr, "sg_turs: error opening file: %s: %s\n",
                op->device_name, safe_strerror(-sg_fd));
        return SG_LIB_FILE_ERROR;
    }
    if (op->do_progress) {
        for (k = 0; k < op->do_number; ++k) {
            if (k > 0)
                sleep_for(30);
            progress = -1;
            res = sg_ll_test_unit_ready_progress(sg_fd, k, &progress,
                     ((1 == op->do_number) ? 1 : 0), op->do_verbose);
            if (progress < 0) {
                ret = res;
                break;
            } else {
                pr = (progress * 100) / 65536;
                rem = ((progress * 100) % 65536) / 656;
                printf("Progress indication: %d.%02d%% done\n", pr, rem);
            }
        }
        if (op->do_number > 1)
            printf("Completed %d Test Unit Ready commands\n",
                   ((k < op->do_number) ? k + 1 : k));
    } else {
#ifndef SG_LIB_MINGW
        if (op->do_time) {
            start_tm.tv_sec = 0;
            start_tm.tv_usec = 0;
            gettimeofday(&start_tm, NULL);
        }
#endif
        for (k = 0; k < op->do_number; ++k) {
            /* Might get Unit Attention on first invocation */
            res = sg_ll_test_unit_ready(sg_fd, k, (0 == k), op->do_verbose);
            if (res) {
                ++num_errs;
                ret = res;
                if (1 == op->do_number) {
                    if (SG_LIB_CAT_NOT_READY == res)
                        printf("device not ready\n");
                    else {
                        sg_get_category_sense_str(res, sizeof(b), b,
                                                  op->do_verbose);
                        printf("%s\n", b);
                    }
                    reported = 1;
                    break;
                }
            }
        }
#ifndef SG_LIB_MINGW
        if ((op->do_time) && (start_tm.tv_sec || start_tm.tv_usec)) {
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
            b = (double)op->do_number;
            printf("time to perform commands was %d.%06d secs",
                   (int)res_tm.tv_sec, (int)res_tm.tv_usec);
            if (a > 0.00001)
                printf("; %.2f operations/sec\n", b / a);
            else
                printf("\n");
        }
#endif

        if (((op->do_number > 1) || (num_errs > 0)) && (! reported))
            printf("Completed %d Test Unit Ready commands with %d errors\n",
                   op->do_number, num_errs);
    }
    sg_cmds_close_device(sg_fd);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

/*
 * Copyright (C) 2000-2019 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This program sends a user specified number of TEST UNIT READY ("tur")
 * commands to the given sg device. Since TUR is a simple command involing
 * no data transfer (and no REQUEST SENSE command iff the unit is ready)
 * then this can be used for timing per SCSI command overheads.
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
#include <time.h>
#elif defined(HAVE_GETTIMEOFDAY)
#include <time.h>
#include <sys/time.h>
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"
#include "sg_pr2serr.h"


static const char * version_str = "3.46 20190618";

#if defined(MSC_VER) || defined(__MINGW32__)
#define HAVE_MS_SLEEP
#endif

#ifdef HAVE_MS_SLEEP
#include <windows.h>
#define sleep_for(seconds)    Sleep( (seconds) * 1000)
#else
#define sleep_for(seconds)    sleep(seconds)
#endif

#define DEF_PT_TIMEOUT  60       /* 60 seconds */


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"low", no_argument, 0, 'l'},
        {"new", no_argument, 0, 'N'},
        {"number", required_argument, 0, 'n'},
        {"num", required_argument, 0, 'n'}, /* added in v3.32 (sg3_utils
                                * v1.43) for sg_requests compatibility */
        {"old", no_argument, 0, 'O'},
        {"progress", no_argument, 0, 'p'},
        {"time", no_argument, 0, 't'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

struct opts_t {
    bool do_low;
    bool do_progress;
    bool do_time;
    bool opts_new;
    bool verbose_given;
    bool version_given;
    int do_help;
    int do_number;
    int verbose;
    const char * device_name;
};

struct loop_res_t {
    bool reported;
    int num_errs;
    int ret;
};


static void
usage()
{
    printf("Usage: sg_turs [--help] [--low] [--number=NUM] [--num=NUM] "
           "[--progress]\n"
           "               [--time] [--verbose] [--version] DEVICE\n"
           "  where:\n"
           "    --help|-h        print usage message then exit\n"
           "    --low|-l         use low level (sg_pt) interface for "
           "speed\n"
           "    --number=NUM|-n NUM    number of test_unit_ready commands "
           "(def: 1)\n"
           "    --num=NUM|-n NUM       same action as '--number=NUM'\n"
           "    --old|-O         use old interface (use as first option)\n"
           "    --progress|-p    outputs progress indication (percentage) "
           "if available\n"
           "    --time|-t        outputs total duration and commands per "
           "second\n"
           "    --verbose|-v     increase verbosity\n"
           "    --version|-V     print version string then exit\n\n"
           "Performs a SCSI TEST UNIT READY command (or many of them).\n");
}

static void
usage_old()
{
    printf("Usage: sg_turs [-l] [-n=NUM] [-p] [-t] [-v] [-V] "
           "DEVICE\n"
           "  where:\n"
           "    -l        use low level interface (sg_pt) for speed\n"
           "    -n=NUM    number of test_unit_ready commands "
           "(def: 1)\n"
           "    -p        outputs progress indication (percentage) "
           "if available\n"
           "    -t        outputs total duration and commands per "
           "second\n"
           "    -v        increase verbosity\n"
           "    -N|--new  use new interface\n"
           "    -V        print version string then exit\n\n"
           "Performs a SCSI TEST UNIT READY command (or many of them).\n");
}

static void
usage_for(const struct opts_t * op)
{
    if (op->opts_new)
        usage();
    else
        usage_old();
}

static int
new_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int c, n;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hln:NOptvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            ++op->do_help;
            break;
        case 'l':
            op->do_low = true;
            break;
        case 'n':
            n = sg_get_num(optarg);
            if (n < 0) {
                pr2serr("bad argument to '--number='\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            op->do_number = n;
            break;
        case 'N':
            break;      /* ignore */
        case 'O':
            op->opts_new = false;
            return 0;
        case 'p':
            op->do_progress = true;
            break;
        case 't':
            op->do_time = true;
            break;
        case 'v':
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        default:
            pr2serr("unrecognised option code %c [0x%x]\n", c, c);
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
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int
old_parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    bool jmp_out;
    int k, plen;
    const char * cp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'l':
                    op->do_low = true;
                    return 0;
                case 'N':
                    op->opts_new = true;
                    return 0;
                case 'O':
                    break;
                case 'p':
                    op->do_progress = true;
                    break;
                case 't':
                    op->do_time = true;
                    break;
                case 'v':
                    op->verbose_given = true;
                    ++op->verbose;
                    break;
                case 'V':
                    op->version_given = true;
                    break;
                case '?':
                    usage_old();
                    return 0;
                default:
                    jmp_out = true;
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
                pr2serr("Unrecognized option: %s\n", cp);
                usage_old();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == op->device_name)
            op->device_name = cp;
        else {
            pr2serr("too many arguments, got: %s, not expecting: %s\n",
                    op->device_name, cp);
            usage_old();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    return 0;
}

static int
parse_cmd_line(struct opts_t * op, int argc, char * argv[])
{
    int res;
    char * cp;

    cp = getenv("SG3_UTILS_OLD_OPTS");
    if (cp) {
        op->opts_new = false;
        res = old_parse_cmd_line(op, argc, argv);
        if ((0 == res) && op->opts_new)
            res = new_parse_cmd_line(op, argc, argv);
    } else {
        op->opts_new = true;
        res = new_parse_cmd_line(op, argc, argv);
        if ((0 == res) && (0 == op->opts_new))
            res = old_parse_cmd_line(op, argc, argv);
    }
    return res;
}

/* Returns number of TURs performed */
static int
loop_turs(struct sg_pt_base * ptvp, struct loop_res_t * resp,
          struct opts_t * op)
{
    int k, res;
    int packet_id = 0;
    int vb = op->verbose;
    char b[80];

    if (op->do_low) {
        int rs, n, sense_cat;
        uint8_t cdb[6];
        uint8_t sense_b[32];

        for (k = 0; k < op->do_number; ++k) {
            /* Might get Unit Attention on first invocation */
            memset(cdb, 0, sizeof(cdb));    /* TUR's cdb is 6 zeros */
            set_scsi_pt_cdb(ptvp, cdb, sizeof(cdb));
            set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
            set_scsi_pt_packet_id(ptvp, ++packet_id);
            rs = do_scsi_pt(ptvp, -1, DEF_PT_TIMEOUT, vb);
            n = sg_cmds_process_resp(ptvp, "Test unit ready", rs, (0 == k),
                                     vb, &sense_cat);
            if (-1 == n) {
                resp->ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
                return k;
            } else if (-2 == n) {
                switch (sense_cat) {
                case SG_LIB_CAT_RECOVERED:
                case SG_LIB_CAT_NO_SENSE:
                    break;
                case SG_LIB_CAT_NOT_READY:
                    ++resp->num_errs;
                    if (1 ==  op->do_number) {
                        resp->ret = sense_cat;
                        printf("device not ready\n");
                        resp->reported = true;
                    }
                    break;
                case SG_LIB_CAT_UNIT_ATTENTION:
                    ++resp->num_errs;
                    if (vb) {
                        pr2serr("Ignoring Unit attention (sense key)\n");
                        resp->reported = true;
                    }
                    break;
                default:
                    ++resp->num_errs;
                    if (1 == op->do_number) {
                        resp->ret = sense_cat;
                        sg_get_category_sense_str(sense_cat, sizeof(b), b, vb);
                        printf("%s\n", b);
                        resp->reported = true;
                        return k;
                    }
                    break;
                }
            }
            clear_scsi_pt_obj(ptvp);
        }
        return k;
    } else {
        for (k = 0; k < op->do_number; ++k) {
            /* Might get Unit Attention on first invocation */
            res = sg_ll_test_unit_ready_pt(ptvp, k, (0 == k), vb);
            if (res) {
                ++resp->num_errs;
                resp->ret = res;
                if (1 == op->do_number) {
                    if (SG_LIB_CAT_NOT_READY == res)
                        printf("device not ready\n");
                    else {
                        sg_get_category_sense_str(res, sizeof(b), b, vb);
                        printf("%s\n", b);
                    }
                    resp->reported = true;
                    break;
                }
            }
        }
        return k;
    }
}


int
main(int argc, char * argv[])
{
    bool start_tm_valid = false;
    int k, res, progress, pr, rem, num_done;
    int err = 0;
    int ret = 0;
    int sg_fd = -1;
    int64_t elapsed_usecs = 0;
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
    struct timespec start_tm, end_tm;
#elif defined(HAVE_GETTIMEOFDAY)
    struct timeval start_tm, end_tm;
#endif
    struct loop_res_t loop_res;
    struct loop_res_t * resp = &loop_res;
    struct sg_pt_base * ptvp = NULL;
    struct opts_t opts;
    struct opts_t * op = &opts;


    memset(op, 0, sizeof(opts));
    memset(resp, 0, sizeof(loop_res));
    op->do_number = 1;
    res = parse_cmd_line(op, argc, argv);
    if (res)
        return res;
    if (op->do_help) {
        usage_for(op);
        return 0;
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
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == op->device_name) {
        pr2serr("No DEVICE argument given\n");
        usage_for(op);
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((sg_fd = sg_cmds_open_device(op->device_name, true /* ro */,
                                     op->verbose)) < 0) {
        pr2serr("%s: error opening file: %s: %s\n", __func__,
                op->device_name, safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }
    ptvp = construct_scsi_pt_obj_with_fd(sg_fd, op->verbose);
    if ((NULL == ptvp) || ((err = get_scsi_pt_os_err(ptvp)))) {
        pr2serr("%s: unable to construct pt object\n", __func__);
        ret = sg_convert_errno(err ? err : ENOMEM);
        goto fini;
    }
    if (op->do_progress) {
        for (k = 0; k < op->do_number; ++k) {
            if (k > 0)
                sleep_for(30);
            progress = -1;
            res = sg_ll_test_unit_ready_progress_pt(ptvp, k, &progress,
                             (1 == op->do_number), op->verbose);
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
    } else {            /* --progress not given */
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
        if (op->do_time) {
            start_tm.tv_sec = 0;
            start_tm.tv_nsec = 0;
            if (0 == clock_gettime(CLOCK_MONOTONIC, &start_tm))
                start_tm_valid = true;
            else
                perror("clock_gettime(CLOCK_MONOTONIC)\n");
        }
#elif defined(HAVE_GETTIMEOFDAY)
        if (op->do_time) {
            start_tm.tv_sec = 0;
            start_tm.tv_usec = 0;
            gettimeofday(&start_tm, NULL);
            start_tm_valid = true;
        }
#else
        start_tm_valid = false;
#endif

        num_done = loop_turs(ptvp, resp, op);

        if (op->do_time && start_tm_valid) {
#if defined(HAVE_CLOCK_GETTIME) && defined(CLOCK_MONOTONIC)
            if (start_tm.tv_sec || start_tm.tv_nsec) {

                res = clock_gettime(CLOCK_MONOTONIC, &end_tm);
                if (res < 0) {
                    err = errno;
                    perror("clock_gettime");
                    if (EINVAL == err)
                        pr2serr("clock_gettime(CLOCK_MONOTONIC) not "
                                "supported\n");
                }
                elapsed_usecs = (end_tm.tv_sec - start_tm.tv_sec) * 1000000;
                /* Note: (end_tm.tv_nsec - start_tm.tv_nsec) may be negative */
                elapsed_usecs += (end_tm.tv_nsec - start_tm.tv_nsec) / 1000;
            }
#elif defined(HAVE_GETTIMEOFDAY)
            if (start_tm.tv_sec || start_tm.tv_usec) {
                gettimeofday(&end_tm, NULL);
                elapsed_usecs = (end_tm.tv_sec - start_tm.tv_sec) * 1000000;
                elapsed_usecs += (end_tm.tv_usec - start_tm.tv_usec);
            }
#endif
            if (elapsed_usecs > 0) {
                int64_t nom = num_done;

                printf("time to perform commands was %u.%06u secs",
                       (unsigned)(elapsed_usecs / 1000000),
                       (unsigned)(elapsed_usecs % 1000000));
                nom *= 1000000; /* scale for integer division */
                printf("; %d operations/sec\n", (int)(nom / elapsed_usecs));
            } else
                printf("Recorded 0 or less elapsed microseconds ??\n");
        }
        if (((op->do_number > 1) || (resp->num_errs > 0)) &&
            (! resp->reported))
            printf("Completed %d Test Unit Ready commands with %d errors\n",
                   op->do_number, resp->num_errs);
        if (1 == op->do_number)
            ret = resp->ret;
    }
fini:
    if (ptvp)
        destruct_scsi_pt_obj(ptvp);
    if (sg_fd >= 0)
        sg_cmds_close_device(sg_fd);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

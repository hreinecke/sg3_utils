/*
 * Utility program for the Linux OS SCSI generic ("sg") device driver.
 *     Copyright (C) 2000-2017 D. Gilbert
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later

   This shows the mapping from "sg" devices to other scsi devices
   (i.e. sd, scd or st) if any.

   Note: This program requires sg version 2 or better.

   Version 0.19 20041203

   Version 1.02 20050511
        - allow for sparse disk name with up to 3 letter SCSI
          disk device node names (e.g. /dev/sdaaa)
          [Nate Dailey < Nate dot Dailey at stratus dot com >]
*/

#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_io_linux.h"


static const char * version_str = "1.12 20171010";

static const char * devfs_id = "/dev/.devfsd";

#define NUMERIC_SCAN_DEF true /* set to false to make alpha scan default */

#define INQUIRY_RESP_INITIAL_LEN 36
#define MAX_SG_DEVS 4096
#define PRESENT_ARRAY_SIZE MAX_SG_DEVS

static const char * sysfs_sg_dir = "/sys/class/scsi_generic";
static char gen_index_arr[PRESENT_ARRAY_SIZE];
static int has_sysfs_sg = 0;


typedef struct my_map_info
{
    int active;
    int lin_dev_type;
    int oth_dev_num;
    struct sg_scsi_id sg_dat;
    char vendor[8];
    char product[16];
    char revision[4];
} my_map_info_t;


#define MAX_SD_DEVS (26 + 26*26 + 26*26*26) /* sdX, sdXX, sdXXX */
                 /* (26 + 676 + 17576) = 18278 */
#define MAX_SR_DEVS 128
#define MAX_ST_DEVS 128
#define MAX_OSST_DEVS 128
#define MAX_ERRORS 5

static my_map_info_t map_arr[MAX_SG_DEVS];

#define LIN_DEV_TYPE_UNKNOWN 0
#define LIN_DEV_TYPE_SD 1
#define LIN_DEV_TYPE_SR 2
#define LIN_DEV_TYPE_ST 3
#define LIN_DEV_TYPE_SCD 4
#define LIN_DEV_TYPE_OSST 5


typedef struct my_scsi_idlun {
/* why can't userland see this structure ??? */
    int dev_id;
    int host_unique_id;
} My_scsi_idlun;


#define EBUFF_SZ 256
static char ebuff[EBUFF_SZ];

static void scan_dev_type(const char * leadin, int max_dev, bool do_numeric,
                          int lin_dev_type, int last_sg_ind);

static void usage()
{
    printf("Usage: sg_map [-a] [-h] [-i] [-n] [-sd] [-scd or -sr] [-st] "
           "[-V] [-x]\n");
    printf("  where:\n");
    printf("    -a      do alphabetic scan (ie sga, sgb, sgc)\n");
    printf("    -h or -?    show this usage message then exit\n");
    printf("    -i      also show device INQUIRY strings\n");
    printf("    -n      do numeric scan (i.e. sg0, sg1, sg2) "
           "(default)\n");
    printf("    -sd     show mapping to disks\n");
    printf("    -scd    show mapping to cdroms (look for /dev/scd<n>\n");
    printf("    -sr     show mapping to cdroms (look for /dev/sr<n>\n");
    printf("    -st     show mapping to tapes (st and osst devices)\n");
    printf("    -V      print version string then exit\n");
    printf("    -x      also show bus,chan,id,lun and type\n\n");
    printf("If no '-s*' arguments given then show all mappings. This "
           "utility\nis DEPRECATED, do not use in Linux 2.6 series or "
           "later.\n");
}

static int scandir_select(const struct dirent * s)
{
    int k;

    if (1 == sscanf(s->d_name, "sg%d", &k)) {
        if ((k >= 0) && (k < PRESENT_ARRAY_SIZE)) {
            gen_index_arr[k] = 1;
            return 1;
        }
    }
    return 0;
}

static int sysfs_sg_scan(const char * dir_name)
{
    struct dirent ** namelist;
    int num, k;

    num = scandir(dir_name, &namelist, scandir_select, NULL);
    if (num < 0)
        return -errno;
    for (k = 0; k < num; ++k)
        free(namelist[k]);
    free(namelist);
    return num;
}

static void make_dev_name(char * fname, const char * leadin, int k,
                          bool do_numeric)
{
    char buff[64];
    int  ones,tens,hundreds; /* for lack of a better name */
    int  buff_idx;

    strcpy(fname, leadin ? leadin : "/dev/sg");
    if (do_numeric) {
        sprintf(buff, "%d", k);
        strcat(fname, buff);
    }
    else if (k >= (26 + 26*26 + 26*26*26)) {
        strcat(fname, "xxxx");
    }
    else {
        ones = k % 26;

        if ((k - 26) >= 0)
            tens = ((k-26)/26) % 26;
        else tens = -1;

        if ((k - (26 + 26*26)) >= 0)
             hundreds = ((k - (26 + 26*26))/(26*26)) % 26;
        else hundreds = -1;

        buff_idx = 0;
        if (hundreds >= 0) buff[buff_idx++] = 'a' + (char)hundreds;
        if (tens >= 0) buff[buff_idx++] = 'a' + (char)tens;
        buff[buff_idx++] = 'a' + (char)ones;
        buff[buff_idx] = '\0';
        strcat(fname, buff);
    }
}


int main(int argc, char * argv[])
{
    bool do_all_s = true;
    bool do_extra = false;
    bool do_inquiry = false;
    bool do_numeric = NUMERIC_SCAN_DEF;
    bool do_osst = false;
    bool do_scd = false;
    bool do_sd = false;
    bool do_sr = false;
    bool do_st = false;
    bool eacces_err = false;
    int sg_fd, res, k;
    int num_errors = 0;
    int num_silent = 0;
    int last_sg_ind = -1;
    char fname[64];
    struct stat a_stat;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-n", argv[k]))
            do_numeric = true;
        else if (0 == strcmp("-a", argv[k]))
            do_numeric = false;
        else if (0 == strcmp("-x", argv[k]))
            do_extra = true;
        else if (0 == strcmp("-i", argv[k]))
            do_inquiry = true;
        else if (0 == strcmp("-sd", argv[k])) {
            do_sd = true;
            do_all_s = false;
        } else if (0 == strcmp("-st", argv[k])) {
            do_st = true;
            do_osst = true;
            do_all_s = false;
        } else if (0 == strcmp("-sr", argv[k])) {
            do_sr = true;
            do_all_s = false;
        } else if (0 == strcmp("-scd", argv[k])) {
            do_scd = true;
            do_all_s = false;
        } else if (0 == strcmp("-V", argv[k])) {
            fprintf(stderr, "Version string: %s\n", version_str);
            exit(0);
        } else if ((0 == strcmp("-?", argv[k])) ||
                   (0 == strncmp("-h", argv[k], 2))) {
            printf(
            "Show mapping from sg devices to other scsi device names\n\n");
            usage();
            return SG_LIB_SYNTAX_ERROR;
        } else if (*argv[k] == '-') {
            printf("Unknown switch: %s\n", argv[k]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        } else if (*argv[k] != '-') {
            printf("Unknown argument\n");
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if ((stat(sysfs_sg_dir, &a_stat) >= 0) && (S_ISDIR(a_stat.st_mode)))
        has_sysfs_sg = sysfs_sg_scan(sysfs_sg_dir);

    if (stat(devfs_id, &a_stat) == 0)
        printf("# Note: the devfs pseudo file system is present\n");

    for (k = 0, res = 0; (k < MAX_SG_DEVS) && (num_errors < MAX_ERRORS);
         ++k, res = (sg_fd >= 0) ? close(sg_fd) : 0) {
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, "Error closing %s ", fname);
            perror("sg_map: close error");
            return SG_LIB_FILE_ERROR;
        }
        if (has_sysfs_sg) {
           if (0 == gen_index_arr[k]) {
                sg_fd = -1;
                continue;
            }
            make_dev_name(fname, "/dev/sg", k, true);
        } else
            make_dev_name(fname, "/dev/sg", k, do_numeric);

        sg_fd = open(fname, O_RDONLY | O_NONBLOCK);
        if (sg_fd < 0) {
            if (EBUSY == errno) {
                map_arr[k].active = -2;
                continue;
            }
            else if ((ENODEV == errno) || (ENOENT == errno) ||
                     (ENXIO == errno)) {
                ++num_errors;
                ++num_silent;
                map_arr[k].active = -1;
                continue;
            }
            else {
                if (EACCES == errno)
                    eacces_err = true;
                snprintf(ebuff, EBUFF_SZ, "Error opening %s ", fname);
                perror(ebuff);
                ++num_errors;
                continue;
            }
        }
        res = ioctl(sg_fd, SG_GET_SCSI_ID, &map_arr[k].sg_dat);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ,
                     "device %s failed on sg ioctl, skip", fname);
            perror(ebuff);
            ++num_errors;
            continue;
        }
        if (do_inquiry) {
            char buff[INQUIRY_RESP_INITIAL_LEN];

            if (0 == sg_ll_inquiry(sg_fd, false, false, 0, buff, sizeof(buff),
                                   true, 0)) {
                memcpy(map_arr[k].vendor, &buff[8], 8);
                memcpy(map_arr[k].product, &buff[16], 16);
                memcpy(map_arr[k].revision, &buff[32], 4);
            }
        }
        map_arr[k].active = 1;
        map_arr[k].oth_dev_num = -1;
        last_sg_ind = k;
    }
    if ((num_errors >= MAX_ERRORS) && (num_silent < num_errors)) {
        printf("Stopping because there are too many error\n");
        if (eacces_err)
            printf("    root access may be required\n");
        return SG_LIB_FILE_ERROR;
    }
    if (last_sg_ind < 0) {
        printf("Stopping because no sg devices found\n");
    }

    if (do_all_s || do_sd)
        scan_dev_type("/dev/sd", MAX_SD_DEVS, 0, LIN_DEV_TYPE_SD, last_sg_ind);
    if (do_all_s || do_sr)
        scan_dev_type("/dev/sr", MAX_SR_DEVS, 1, LIN_DEV_TYPE_SR, last_sg_ind);
    if (do_all_s || do_scd)
        scan_dev_type("/dev/scd", MAX_SR_DEVS, 1, LIN_DEV_TYPE_SCD,
                      last_sg_ind);
    if (do_all_s || do_st)
        scan_dev_type("/dev/nst", MAX_ST_DEVS, 1, LIN_DEV_TYPE_ST,
                      last_sg_ind);
    if (do_all_s || do_osst)
        scan_dev_type("/dev/osst", MAX_OSST_DEVS, 1, LIN_DEV_TYPE_OSST,
                      last_sg_ind);

    for (k = 0; k <= last_sg_ind; ++k) {
        if (has_sysfs_sg) {
           if (0 == gen_index_arr[k]) {
                continue;
            }
            make_dev_name(fname, "/dev/sg", k, true);
        } else
            make_dev_name(fname, "/dev/sg", k, do_numeric);
        printf("%s", fname);
        switch (map_arr[k].active)
        {
        case -2:
            printf(do_extra ? "  -2 -2 -2 -2  -2" : "  busy");
            break;
        case -1:
            printf(do_extra ? "  -1 -1 -1 -1  -1" : "  not present");
            break;
        case 0:
            printf(do_extra ? "  -3 -3 -3 -3  -3" : "  some error");
            break;
        case 1:
            if (do_extra)
                printf("  %d %d %d %d  %d", map_arr[k].sg_dat.host_no,
                       map_arr[k].sg_dat.channel, map_arr[k].sg_dat.scsi_id,
                       map_arr[k].sg_dat.lun, map_arr[k].sg_dat.scsi_type);
            switch (map_arr[k].lin_dev_type)
            {
            case LIN_DEV_TYPE_SD:
                make_dev_name(fname, "/dev/sd" , map_arr[k].oth_dev_num, 0);
                printf("  %s", fname);
                break;
            case LIN_DEV_TYPE_ST:
                make_dev_name(fname, "/dev/nst" , map_arr[k].oth_dev_num, 1);
                printf("  %s", fname);
                break;
            case LIN_DEV_TYPE_OSST:
                make_dev_name(fname, "/dev/osst" , map_arr[k].oth_dev_num, 1);
                printf("  %s", fname);
                break;
            case LIN_DEV_TYPE_SR:
                make_dev_name(fname, "/dev/sr" , map_arr[k].oth_dev_num, 1);
                printf("  %s", fname);
                break;
            case LIN_DEV_TYPE_SCD:
                make_dev_name(fname, "/dev/scd" , map_arr[k].oth_dev_num, 1);
                printf("  %s", fname);
                break;
            default:
                break;
            }
            if (do_inquiry)
                printf("  %.8s  %.16s  %.4s", map_arr[k].vendor,
                       map_arr[k].product, map_arr[k].revision);
            break;
        default:
            printf("  bad logic\n");
            break;
        }
        printf("\n");
    }
    return 0;
}

static int find_dev_in_sg_arr(My_scsi_idlun * my_idlun, int host_no,
                              int last_sg_ind)
{
    int k;
    struct sg_scsi_id * sidp;

    for (k = 0; k <= last_sg_ind; ++k) {
        sidp = &(map_arr[k].sg_dat);
        if ((host_no == sidp->host_no) &&
            ((my_idlun->dev_id & 0xff) == sidp->scsi_id) &&
            (((my_idlun->dev_id >> 8) & 0xff) == sidp->lun) &&
            (((my_idlun->dev_id >> 16) & 0xff) == sidp->channel))
            return k;
    }
    return -1;
}

static void scan_dev_type(const char * leadin, int max_dev, bool do_numeric,
                          int lin_dev_type, int last_sg_ind)
{
    int k, res, ind, sg_fd = 0;
    int num_errors = 0;
    int num_silent = 0;
    int host_no = -1;
    My_scsi_idlun my_idlun;
    char fname[64];

    for (k = 0, res = 0; (k < max_dev)  && (num_errors < MAX_ERRORS);
         ++k, res = (sg_fd >= 0) ? close(sg_fd) : 0) {

/* ignore close() errors */
#if 0
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, "Error closing %s ", fname);
            perror("sg_map: close error");
#ifndef IGN_CLOSE_ERR
            return;
#else
            ++num_errors;
            sg_fd = 0;
#endif
        }
#endif
        make_dev_name(fname, leadin, k, do_numeric);
#ifdef DEBUG
        printf ("Trying %s: ", fname);
#endif

        sg_fd = open(fname, O_RDONLY | O_NONBLOCK);
        if (sg_fd < 0) {
#ifdef DEBUG
            printf ("ERROR %i\n", errno);
#endif
            if (EBUSY == errno) {
                printf("Device %s is busy\n", fname);
                ++num_errors;
            } else if ((ENODEV == errno) || (ENXIO == errno)) {
                ++num_errors;
                ++num_silent;
            } else if (ENOENT != errno) { /* ignore ENOENT for sparse names */
                snprintf(ebuff, EBUFF_SZ, "Error opening %s ", fname);
                perror(ebuff);
                ++num_errors;
            }
            continue;
        }

        res = ioctl(sg_fd, SCSI_IOCTL_GET_IDLUN, &my_idlun);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ,
                     "device %s failed on scsi ioctl(idlun), skip", fname);
            perror(ebuff);
            ++num_errors;
#ifdef DEBUG
            printf ("Couldn't get IDLUN!\n");
#endif
            continue;
        }
        res = ioctl(sg_fd, SCSI_IOCTL_GET_BUS_NUMBER, &host_no);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ,
                 "device %s failed on scsi ioctl(bus_number), skip", fname);
            perror(ebuff);
            ++num_errors;
#ifdef DEBUG
            printf ("Couldn't get BUS!\n");
#endif
            continue;
        }
#ifdef DEBUG
        printf ("%i(%x) %i %i %i %i\n", host_no, my_idlun.host_unique_id,
                (my_idlun.dev_id>>24)&0xff, (my_idlun.dev_id>>16)&0xff,
                (my_idlun.dev_id>>8)&0xff, my_idlun.dev_id&0xff);
#endif
        ind = find_dev_in_sg_arr(&my_idlun, host_no, last_sg_ind);
        if (ind >= 0) {
            map_arr[ind].oth_dev_num = k;
            map_arr[ind].lin_dev_type = lin_dev_type;
        }
        else
            printf("Strange, could not find device %s mapped to sg device??\n",
                   fname);
    }
}

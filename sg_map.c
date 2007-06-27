#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* Utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2000-2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This shows the mapping from "sg" devices to other scsi devices
   (i.e. sd, scd or st) if any.
   Options: -n   numeric scan: scan /dev/sg0,1,2, .... [default]
            -a   alphabetical scan: scan /dev/sga,b,c, ....
            -x   also show bus,chan,id,lun and type
            -i   also show device INQUIRY information
            -sd  only scan for sd devices [disks]
            -st  only scan for st (and osst) devices [tapes]
            -scd (or -sr)  only scan for scd devices [cdroms]

   Note: This program requires sg version 2 or better.

   Version 0.18 20030812
        - additions for osst [Kurt Garloff <garloff at suse dot de>]
*/


#ifndef SG_GET_RESERVED_SIZE
#error "Need version 2 sg driver (linux kernel >= 2.2.6)"
#endif

static const char * devfs_id = "/dev/.devfsd";

#define NUMERIC_SCAN_DEF 1   /* change to 0 to make alpha scan default */


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


#define MAX_SG_DEVS 256
#define MAX_SD_DEVS 128
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

static void scan_dev_type(const char * leadin, int max_dev, int do_numeric,
                          int lin_dev_type, int last_sg_ind);

static void usage()
{
    printf("Usage: 'sg_map [-a] [-n] [-x] [-sd] [-scd or -sr] [-st]'\n");
    printf("    where: -a   do alphabetic scan (ie sga, sgb, sgc)\n");
    printf("           -n   do numeric scan (ie sg0, sg1, sg2)\n");
    printf("           -x   also show bus,chan,id,lun and type\n");
    printf("           -i   also show device INQUIRY strings\n");
    printf("           -? or -h  show this usage message\n");
    printf("           -sd  show mapping to disks\n");
    printf("           -scd show mapping to cdroms (look for /dev/scd<n>\n");
    printf("           -sr  show mapping to cdroms (look for /dev/sr<n>\n");
    printf("           -st  show mapping to tapes (st and osst devices)\n");
    printf("    If no '-s*' arguments given then show all mappings\n");
}


static void make_dev_name(char * fname, const char * leadin, int k, 
                          int do_numeric)
{
    char buff[64];
    int  big,little;

    strcpy(fname, leadin ? leadin : "/dev/sg");
    if (do_numeric) {
        sprintf(buff, "%d", k);
        strcat(fname, buff);
    }
    else {
        if (k < 26) {
            buff[0] = 'a' + (char)k;
            buff[1] = '\0';
            strcat(fname, buff);
        }
        else if (k <= 255) { /* assumes sequence goes x,y,z,aa,ab,ac etc */
            big    = k/26;
            little = k - (26 * big);
            big    = big - 1;

            buff[0] = 'a' + (char)big;
            buff[1] = 'a' + (char)little;
            buff[2] = '\0';
            strcat(fname, buff);
        }
        else
            strcat(fname, "xxxx");
    }
}


int main(int argc, char * argv[])
{
    int sg_fd, res, k;
    int do_numeric = NUMERIC_SCAN_DEF;
    int do_all_s = 1;
    int do_sd = 0;
    int do_st = 0;
    int do_osst = 0;
    int do_sr = 0;
    int do_scd = 0;
    int do_extra = 0;
    int do_inquiry = 0;
    char fname[64];
    int num_errors = 0;
    int num_silent = 0;
    int eacces_err = 0;
    int last_sg_ind = -1;
    struct stat stat_buf;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-n", argv[k]))
            do_numeric = 1;
        else if (0 == strcmp("-a", argv[k]))
            do_numeric = 0;
        else if (0 == strcmp("-x", argv[k]))
            do_extra = 1;
        else if (0 == strcmp("-i", argv[k]))
            do_inquiry = 1;
        else if (0 == strcmp("-sd", argv[k])) {
            do_sd = 1;
            do_all_s = 0;
        }
        else if (0 == strcmp("-st", argv[k])) {
            do_st = 1;
            do_osst = 1;
            do_all_s = 0;
        }
        else if (0 == strcmp("-sr", argv[k])) {
            do_sr = 1;
            do_all_s = 0;
        }
        else if (0 == strcmp("-scd", argv[k])) {
            do_scd = 1;
            do_all_s = 0;
        }
        else if ((0 == strcmp("-?", argv[k])) ||
                 (0 == strncmp("-h", argv[k], 2))) {
            printf(
            "Show mapping from sg devices to other scsi device names\n\n");
            usage();
            return 1;
        }
        else if (*argv[k] == '-') {
            printf("Unknown switch: %s\n", argv[k]);
            usage();
            return 1;
        }
        else if (*argv[k] != '-') {
            printf("Unknown argument\n");
            usage();
            return 1;
        }
    }

    if (stat(devfs_id, &stat_buf) == 0)
        printf("# Note: the devfs pseudo file system is present\n");

    for (k = 0, res = 0; (k < MAX_SG_DEVS)  && (num_errors < MAX_ERRORS);
         ++k, res = (sg_fd >= 0) ? close(sg_fd) : 0) {
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, "Error closing %s ", fname);
            perror("sg_map: close error");
            return 1;
        }
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
                    eacces_err = 1;
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
            char buff[36];

            if (0 == sg_ll_inquiry(sg_fd, 0, 0, 0, buff, sizeof(buff),
				   1, 0)) {
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
        return 1;
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
        scan_dev_type("/dev/st", MAX_ST_DEVS, 1, LIN_DEV_TYPE_ST, last_sg_ind);
    if (do_all_s || do_osst)
        scan_dev_type("/dev/osst", MAX_OSST_DEVS, 1, LIN_DEV_TYPE_OSST, last_sg_ind);

    for (k = 0; k <= last_sg_ind; ++k) {
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
            printf(do_extra ? "  -3 -3 -3 -3  -3" : "  some error\n");
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
                make_dev_name(fname, "/dev/st" , map_arr[k].oth_dev_num, 1);
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

static void scan_dev_type(const char * leadin, int max_dev, int do_numeric,
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
                continue;
            }
            else if ((ENODEV == errno) || (ENOENT == errno) ||
                     (ENXIO == errno)) {
                ++num_errors;
                ++num_silent;
                continue;
            }
            else {
                snprintf(ebuff, EBUFF_SZ, "Error opening %s ", fname);
                perror(ebuff);
                ++num_errors;
                continue;
            }
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


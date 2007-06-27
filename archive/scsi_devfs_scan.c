#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include "sg_include.h"
#include "sg_err.h"

/* Code for scanning for SCSI devices within a Linux device pseudo file
   system.
   *  Copyright (C) 2001 D. Gilbert
   *  This program is free software; you can redistribute it and/or modify
   *  it under the terms of the GNU General Public License as published by
   *  the Free Software Foundation; either version 2, or (at your option)
   *  any later version.

      This program scans the /dev directory structure looking for the
      devfs "primary" scsi (and optionally IDE) device names.

   Version 0.13 20030430
*/

void usage()
{
    printf("Usage: 'scsi_devfs_scan [-d <dir>] [-i] [-ide] [-l [-x]] "
           "[-q]'\n");
    printf("    where: -d <dir> location of devfs [default: /dev ]\n");
    printf("           -i   show INQUIRY data for each SCSI device\n");
    printf("           -ide show scan of IDE devices after SCSI devices\n");
    printf("           -l   show device file names in leaf directory\n");
    printf("           -q   just output host, bus, target, lun numbers\n");
    printf("           -x   add (major,minor) information to '-l'\n");
}

#define NAME_LEN_MAX 256
#define LEVELS 4

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */
#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6

static const char * level_arr[LEVELS] = {"host", "bus", "target", "lun"};

static int do_ide = 0;
static int do_inq = 0;
static int do_leaf = 0;
static int do_extra = 0;
static int do_quiet = 0;
static int checked_sg = 0;

static void dStrHex(const char* str, int len)
{
    const char* p = str;
    unsigned char c;
    char buff[82];
    int a = 0;
    const int bpstart = 5;
    const int cpstart = 60;
    int cpos = cpstart;
    int bpos = bpstart;
    int i, k;

    if (len <= 0) return;
    memset(buff,' ',80);
    buff[80]='\0';
    k = sprintf(buff + 1, "%.2x", a);
    buff[k + 1] = ' ';
    if (bpos >= ((bpstart + (9 * 3))))
        bpos++;

    for(i = 0; i < len; i++)
    {
        c = *p++;
        bpos += 3;
        if (bpos == (bpstart + (9 * 3)))
            bpos++;
        sprintf(&buff[bpos], "%.2x", (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
        if ((c < ' ') || (c >= 0x7f))
            c='.';
        buff[cpos++] = c;
        if (cpos > (cpstart+15))
        {
            printf("%s\n", buff);
            bpos = bpstart;
            cpos = cpstart;
            a += 16;
            memset(buff,' ',80);
            k = sprintf(buff + 1, "%.2x", a);
            buff[k + 1] = ' ';
        }
    }
    if (cpos > cpstart)
    {
        printf("%s\n", buff);
    }
}

static int do_inquiry(int sg_fd, void * resp, int mx_resp_len)
{
    int res;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;

    inqCmdBlk[4] = (unsigned char)mx_resp_len;
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inqCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_TO_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = inqCmdBlk;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (inquiry) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        return 0;
    default:
        sg_chk_n_print3("Failed INQUIRY", &io_hdr);
        return -1;
    }
}

void leaf_dir(const char * lf, unsigned int * larr)
{
    char name[NAME_LEN_MAX * 2];
    int res;

    if (do_quiet) {
        printf("%u\t%u\t%u\t%u\n", larr[0], larr[1], larr[2], larr[3]);
        return;
    }
    printf("%u\t%u\t%u\t%u\t%s\n", larr[0], larr[1], larr[2], larr[3], lf);
    if (do_leaf) {
        struct dirent * de_entry;
        struct dirent * de_result;
        DIR * sdir;
        int outpos;

        if (NULL == (sdir = opendir(lf))) {
            fprintf(stderr, "leaf_dir: opendir of %s: failed\n", lf);
            return;
        }
        de_entry = (struct dirent *)malloc(sizeof(struct dirent) + 
                                           NAME_LEN_MAX);
        if (NULL == de_entry)
            return;
        res = 0;
        printf("\t");
        outpos = 8;
        while (1) {
            res = readdir_r(sdir, de_entry, &de_result);
            if (0 != res) {
                fprintf(stderr, "leaf_dir: readdir_r of %s: %s\n", 
                        lf, strerror(res));
                res = -2;
                break;
            }
            if (de_result == NULL) 
                break;
            strncpy(name, de_entry->d_name, NAME_LEN_MAX * 2);
            if ((0 == strcmp("..", name)) ||(0 == strcmp(".", name))) 
                continue;
            if (do_extra) {
                struct stat st;
                char devname[NAME_LEN_MAX * 2];

                strncpy(devname, lf, NAME_LEN_MAX * 2);
                strcat(devname, "/");
                strcat(devname, name);
                if (stat(devname, &st) < 0)
                    return;
                if (S_ISCHR(st.st_mode)) {
                    strcat(name, "(c ");
                    sprintf(name + strlen(name), "%d %d)", major(st.st_rdev),
                            minor(st.st_rdev));
                }
                else if (S_ISBLK(st.st_mode)) {
                    strcat(name, "(b ");
                    sprintf(name + strlen(name), "%d %d)", major(st.st_rdev),
                            minor(st.st_rdev));
                }
            }
            res = strlen(name);
            if ((outpos + res + 2) > 80) {
                printf("\n\t");
                outpos = 8;
            }
            printf("%s  ", name);
            outpos += res + 2;
        }
        printf("\n");
    }
    if (do_inq) {
        int sg_fd;
        char buff[64];

        memset(buff, 0, sizeof(buff));
        strncpy(name, lf, NAME_LEN_MAX * 2);
        strcat(name, "/generic");
        if ((sg_fd = open(name, O_RDONLY)) < 0) {
            if (! checked_sg) {
                checked_sg = 1;
                if ((sg_fd = open("/dev/sg0", O_RDONLY)) >= 0)
                    close(sg_fd);  /* try and get sg module loaded */
                sg_fd = open(name, O_RDONLY);
            }
            if (sg_fd < 0) {
                printf("Unable to open sg device: %s, %s\n", name, 
                       strerror(errno));
                return;
            }
        }
        if (0 != do_inquiry(sg_fd, buff, 64))
            return;
        close(sg_fd);
        dStrHex(buff, 64);
    }
}

/* Return 0 -> ok, -1 -> opendir() error, -2 -> readdir_r error, 
         -3 -> malloc error */
int hbtl_scan(const char * path, int level, unsigned int *larr)
{
    struct dirent * de_entry;
    struct dirent * de_result;
    char new_path[NAME_LEN_MAX * 2];
    DIR * sdir;
    int res;
    size_t level_slen;

    level_slen = strlen(level_arr[level]);
    if (NULL == (sdir = opendir(path))) {
        fprintf(stderr, "hbtl_scan: opendir of %s: failed\n", path);
        return -1;
    }
    de_entry = (struct dirent *)malloc(sizeof(struct dirent) + NAME_LEN_MAX);
    if (NULL == de_entry)
        return -3;
    res = 0;
    while (1) {
        res = readdir_r(sdir, de_entry, &de_result);
        if (0 != res) {
            fprintf(stderr, "hbtl_scan: readdir_r of %s: %s\n", 
                    path, strerror(res));
            res = -2;
            break;
        }
        if (de_result == NULL) 
            break;
        if (0 == strncmp(level_arr[level], de_entry->d_name, level_slen)) {
            if (1 != sscanf(de_entry->d_name + level_slen, "%u", larr + level))
                larr[level] = UINT_MAX;
            strncpy(new_path, path, NAME_LEN_MAX * 2);
            strcat(new_path, "/");
            strcat(new_path, de_entry->d_name);
            if ((level + 1) < LEVELS) {
                res = hbtl_scan(new_path, level + 1, larr);
                if (res < 0)
                    break;
            }
            else 
                leaf_dir(new_path, larr);
        }
    }
    free(de_entry);
    closedir(sdir);
    return res;
}

#define D_ROOT_SZ 512


int main(int argc, char * argv[])
{
    int k, res;
    char ds_root[D_ROOT_SZ];
    char di_root[D_ROOT_SZ];
    unsigned int larr[LEVELS];
    struct stat st;

    strncpy(ds_root, "/dev", D_ROOT_SZ);
    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-ide", argv[k]))
            do_ide = 1;
        else if (0 == strcmp("-i", argv[k]))
            do_inq = 1;
        else if (0 == strcmp("-l", argv[k]))
            do_leaf = 1;
        else if (0 == strcmp("-x", argv[k]))
            do_extra = 1;
        else if (0 == strcmp("-q", argv[k]))
            do_quiet = 1;
        else if (0 == strncmp("-d", argv[k], 2)) {
            if (strlen(argv[k]) > 2)
                strncpy(ds_root, argv[k] + 2, D_ROOT_SZ);
            else if (++k < argc)
                strncpy(ds_root, argv[k], D_ROOT_SZ);
        }
        else if ((0 == strcmp("-?", argv[k])) ||
                 (0 == strncmp("-h", argv[k], 2))) {
            printf("Scan SCSI devices within a devfs tree\n\n");
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
    strncpy(di_root, ds_root, D_ROOT_SZ);
    strcat(di_root, "/.devfsd");
    if (stat(di_root, &st) < 0)
        printf("Didn't find %s so perhaps devfs is not present,"
                " continuing ...\n", di_root);
    strncpy(di_root, ds_root, D_ROOT_SZ);
    strcat(ds_root, "/scsi");
    strcat(di_root, "/ide");

    if (do_ide)
        printf("SCSI scan:\n");
    res = hbtl_scan(ds_root, 0, larr);
    if (res < 0)
        printf("main: scsi hbtl_scan res=%d\n", res);
    do_inq = 0;  /* won't try SCSI INQUIRY on IDE devices */
    if (do_ide) {
        printf("\nIDE scan:\n");
        res = hbtl_scan(di_root, 0, larr);
        if (res < 0)
            printf("main: ide hbtl_scan res=%d\n", res);
    }
    return 0;
}

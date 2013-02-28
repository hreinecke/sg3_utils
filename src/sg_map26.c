/*
 * Copyright (c) 2005-2013 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

/* A utility program for the Linux OS SCSI subsystem.
 *
 *
 * This program maps a primary SCSI device node name to the corresponding
 * SCSI generic device node name (or vice versa). Targets linux
 * kernel 2.6 or 3 series. Sysfs device names can also be mapped.
 */

/* #define _XOPEN_SOURCE 500 */
/* needed to see DT_REG and friends when compiled with: c99 pedantic */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/major.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"

static char * version_str = "1.09 20130228";

#define ME "sg_map26: "

#define NT_NO_MATCH 0
#define NT_SD 1
#define NT_SR 2
#define NT_HD 3
#define NT_ST 4
#define NT_OSST 5
#define NT_SG 6
#define NT_CH 7
#define NT_REG 8
#define NT_DIR 9

#define NAME_LEN_MAX 260
#define D_NAME_LEN_MAX 516

#ifndef SCSI_CHANGER_MAJOR
#define SCSI_CHANGER_MAJOR 86
#endif
#ifndef OSST_MAJOR
#define OSST_MAJOR 206
#endif

/* scandir() and stat() categories */
#define FT_OTHER 0
#define FT_REGULAR 1
#define FT_BLOCK 2
#define FT_CHAR 3
#define FT_DIR 4

/* older major.h headers may not have these */
#ifndef SCSI_DISK8_MAJOR
#define SCSI_DISK8_MAJOR        128
#define SCSI_DISK9_MAJOR        129
#define SCSI_DISK10_MAJOR       130
#define SCSI_DISK11_MAJOR       131
#define SCSI_DISK12_MAJOR       132
#define SCSI_DISK13_MAJOR       133
#define SCSI_DISK14_MAJOR       134
#define SCSI_DISK15_MAJOR       135
#endif

/* st minor decodes from Kai Makisara 20081008 */
#define ST_NBR_MODE_BITS 2
#define ST_MODE_SHIFT (7 - ST_NBR_MODE_BITS)
#define TAPE_NR(minor) ( (((minor) & ~255) >> (ST_NBR_MODE_BITS + 1)) | \
    ((minor) & ~(-1 << ST_MODE_SHIFT)) )

static const char * sys_sg_dir = "/sys/class/scsi_generic/";
static const char * sys_sd_dir = "/sys/block/";
static const char * sys_sr_dir = "/sys/block/";
static const char * sys_hd_dir = "/sys/block/";
static const char * sys_st_dir = "/sys/class/scsi_tape/";
static const char * sys_sch_dir = "/sys/class/scsi_changer/";
static const char * sys_osst_dir = "/sys/class/onstream_tape/";
static const char * def_dev_dir = "/dev";


static struct option long_options[] = {
        {"dev_dir", 1, 0, 'd'},
        {"given_is", 1, 0, 'g'},
        {"help", 0, 0, 'h'},
        {"result", 1, 0, 'r'},
        {"symlink", 0, 0, 's'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static const char * nt_names[] = {
        "No matching",
        "disk",
        "cd/dvd",
        "hd",
        "tape",
        "tape (osst)",
        "generic (sg)",
        "changer",
        "regular file",
        "directory",
};

static void
usage()
{
        fprintf(stderr, "Usage: "
                "sg_map26 [--dev_dir=DIR] [--given_is=0...1] [--help] "
                "[--result=0...3]\n"
                "                [--symlink] [--verbose] [--version] "
                "DEVICE\n"
                "  where:\n"
                "    --dev_dir=DIR | -d DIR    search in DIR for "
                "resulting special\n"
                "                            (def: directory of DEVICE "
                "or '/dev')\n"
                "    --given_is=0...1 | -g 0...1    variety of given "
                "DEVICE\n"
                "                                   0->block or char special "
                "(or symlink to)\n"
                "                                   1->sysfs device, 'dev' or "
                "parent\n"
                "    --help | -h       print out usage message\n"
                "    --result=0...3 | -r 0...3    variety of file(s) to "
                "find\n"
                "                                 0->mapped block or char "
                "special(def)\n"
                "                                 1->mapped sysfs path\n"
                "                                 2->matching block or "
                "char special\n"
                "                                 3->matching sysfs "
                "path\n"
                "    --symlink | -s    symlinks to special included in "
                "result\n"
                "    --verbose | -v    increase verbosity of output\n"
                "    --version | -V    print version string and exit\n\n"
                "Maps SCSI device node to corresponding generic node (and "
                "vv)\n"
                );
}


/* ssafe_strerror() contributed by Clayton Weaver <cgweav at email dot com>
   Allows for situation in which strerror() is given a wild value (or the
   C library is incomplete) and returns NULL. Still not thread safe.
 */

static char safe_errbuf[64] = {'u', 'n', 'k', 'n', 'o', 'w', 'n', ' ',
                               'e', 'r', 'r', 'n', 'o', ':', ' ', 0};

static char *
ssafe_strerror(int errnum)
{
        size_t len;
        char * errstr;

        errstr = strerror(errnum);
        if (NULL == errstr) {
                len = strlen(safe_errbuf);
                snprintf(safe_errbuf + len, sizeof(safe_errbuf) - len, "%i",
                         errnum);
                safe_errbuf[sizeof(safe_errbuf) - 1] = '\0';  /* bombproof */
                return safe_errbuf;
        }
        return errstr;
}

static int
nt_typ_from_filename(const char * filename, int * majj, int * minn)
{
        struct stat st;
        int ma, mi;

        if (stat(filename, &st) < 0)
                return -errno;
        ma = major(st.st_rdev);
        mi = minor(st.st_rdev);
        if (majj)
                *majj = ma;
        if (minn)
                *minn = mi;
        if (S_ISCHR(st.st_mode)) {
                switch(ma) {
                case OSST_MAJOR:
                        return NT_OSST;
                case SCSI_GENERIC_MAJOR:
                        return NT_SG;
                case SCSI_TAPE_MAJOR:
                        return NT_ST;
                case SCSI_CHANGER_MAJOR:
                        return NT_CH;
                default:
                        return NT_NO_MATCH;
                }
        } else if (S_ISBLK(st.st_mode)) {
                switch(ma) {
                case SCSI_DISK0_MAJOR: case SCSI_DISK1_MAJOR:
                case SCSI_DISK2_MAJOR: case SCSI_DISK3_MAJOR:
                case SCSI_DISK4_MAJOR: case SCSI_DISK5_MAJOR:
                case SCSI_DISK6_MAJOR: case SCSI_DISK7_MAJOR:
                case SCSI_DISK8_MAJOR: case SCSI_DISK9_MAJOR:
                case SCSI_DISK10_MAJOR: case SCSI_DISK11_MAJOR:
                case SCSI_DISK12_MAJOR: case SCSI_DISK13_MAJOR:
                case SCSI_DISK14_MAJOR: case SCSI_DISK15_MAJOR:
                        return NT_SD;
                case SCSI_CDROM_MAJOR:
                        return NT_SR;
                case IDE0_MAJOR: case IDE1_MAJOR:
                case IDE2_MAJOR: case IDE3_MAJOR:
                case IDE4_MAJOR: case IDE5_MAJOR:
                case IDE6_MAJOR: case IDE7_MAJOR:
                case IDE8_MAJOR: case IDE9_MAJOR:
                        return NT_HD;
                default:
                        return NT_NO_MATCH;
                }
        } else if (S_ISREG(st.st_mode))
                return NT_REG;
        else if (S_ISDIR(st.st_mode))
                return NT_DIR;
        return NT_NO_MATCH;
}

static int
nt_typ_from_major(int ma)
{
        switch(ma) {
        case SCSI_DISK0_MAJOR: case SCSI_DISK1_MAJOR:
        case SCSI_DISK2_MAJOR: case SCSI_DISK3_MAJOR:
        case SCSI_DISK4_MAJOR: case SCSI_DISK5_MAJOR:
        case SCSI_DISK6_MAJOR: case SCSI_DISK7_MAJOR:
        case SCSI_DISK8_MAJOR: case SCSI_DISK9_MAJOR:
        case SCSI_DISK10_MAJOR: case SCSI_DISK11_MAJOR:
        case SCSI_DISK12_MAJOR: case SCSI_DISK13_MAJOR:
        case SCSI_DISK14_MAJOR: case SCSI_DISK15_MAJOR:
                return NT_SD;
        case SCSI_CDROM_MAJOR:
                return NT_SR;
        case IDE0_MAJOR: case IDE1_MAJOR:
        case IDE2_MAJOR: case IDE3_MAJOR:
        case IDE4_MAJOR: case IDE5_MAJOR:
        case IDE6_MAJOR: case IDE7_MAJOR:
        case IDE8_MAJOR: case IDE9_MAJOR:
                return NT_HD;
        case OSST_MAJOR:
                return NT_OSST;
        case SCSI_GENERIC_MAJOR:
                return NT_SG;
        case SCSI_TAPE_MAJOR:
                return NT_ST;
        case SCSI_CHANGER_MAJOR:
                return NT_CH;
        default:
                return NT_NO_MATCH;
        }
        return NT_NO_MATCH;
}


struct node_match_item {
        const char * dir_name;
        int file_type;
        int majj;
        int minn;
        int follow_symlink;
};

static struct node_match_item nd_match;

static int
nd_match_scandir_select(const struct dirent * s)
{
        struct stat st;
        char name[D_NAME_LEN_MAX];
        int symlnk = 0;

        switch (s->d_type) {
        case DT_BLK:
                if (FT_BLOCK != nd_match.file_type)
                        return 0;
                break;
        case DT_CHR:
                if (FT_CHAR != nd_match.file_type)
                        return 0;
                break;
        case DT_DIR:
                return (FT_DIR == nd_match.file_type) ? 1 : 0;
        case DT_REG:
                return (FT_REGULAR == nd_match.file_type) ? 1 : 0;
        case DT_LNK:    /* follow symlinks */
                if (! nd_match.follow_symlink)
                        return 0;
                symlnk = 1;
                break;
        default:
                return 0;
        }
        if ((! symlnk) && (-1 == nd_match.majj) && (-1 == nd_match.minn))
                return 1;
        strncpy(name, nd_match.dir_name, NAME_LEN_MAX);
        strcat(name, "/");
        strncat(name, s->d_name, NAME_LEN_MAX);
        memset(&st, 0, sizeof(st));
        if (stat(name, &st) < 0)
                return 0;
        if (symlnk) {
                if (S_ISCHR(st.st_mode)) {
                        if (FT_CHAR != nd_match.file_type)
                                return 0;
                } else if (S_ISBLK(st.st_mode)) {
                        if (FT_BLOCK != nd_match.file_type)
                                return 0;
                } else
                        return 0;
        }
        return (((-1 == nd_match.majj) ||
                 ((unsigned)major(st.st_rdev) == (unsigned)nd_match.majj)) &&
                ((-1 == nd_match.minn) ||
                 ((unsigned)minor(st.st_rdev) == (unsigned)nd_match.minn)))
               ? 1 : 0;
}

static int
list_matching_nodes(const char * dir_name, int file_type, int majj, int minn,
                    int follow_symlink, int verbose)
{
        struct dirent ** namelist;
        int num, k;

        nd_match.dir_name = dir_name;
        nd_match.file_type = file_type;
        nd_match.majj = majj;
        nd_match.minn = minn;
        nd_match.follow_symlink = follow_symlink;
        num = scandir(dir_name, &namelist, nd_match_scandir_select, NULL);
        if (num < 0) {
                if (verbose)
                        fprintf(stderr, "scandir: %s %s\n", dir_name,
                                ssafe_strerror(errno));
                return -errno;
        }
        for (k = 0; k < num; ++k) {
                printf("%s/%s\n", dir_name, namelist[k]->d_name);
                free(namelist[k]);
        }
        free(namelist);
        return num;
}

struct sg_item_t {
        char name[NAME_LEN_MAX];
        int ft;
        int nt;
        int d_type;
};

static struct sg_item_t for_first;

static int
first_scandir_select(const struct dirent * s)
{
        if (FT_OTHER != for_first.ft)
                return 0;
        if ((DT_LNK != s->d_type) &&
            ((DT_DIR != s->d_type) || ('.' == s->d_name[0])))
                return 0;
        strncpy(for_first.name, s->d_name, NAME_LEN_MAX);
        for_first.ft = FT_CHAR;  /* dummy */
        for_first.d_type =  s->d_type;
        return 1;
}

/* scan for directory entry that is either a symlink or a directory */
static int
scan_for_first(const char * dir_name, int verbose)
{
        char name[NAME_LEN_MAX];
        struct dirent ** namelist;
        int num, k;

        for_first.ft = FT_OTHER;
        num = scandir(dir_name, &namelist, first_scandir_select, NULL);
        if (num < 0) {
                if (verbose > 0) {
                        snprintf(name, NAME_LEN_MAX, "scandir: %s", dir_name);
                        perror(name);
                }
                return -1;
        }
        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);
        return num;
}

static struct sg_item_t from_sg;

static int
from_sg_scandir_select(const struct dirent * s)
{
        int len;

        if (FT_OTHER != from_sg.ft)
                return 0;
        if ((DT_LNK != s->d_type) &&
            ((DT_DIR != s->d_type) || ('.' == s->d_name[0])))
                return 0;
        from_sg.d_type = s->d_type;
        if (0 == strncmp("scsi_changer", s->d_name, 12)) {
                strncpy(from_sg.name, s->d_name, NAME_LEN_MAX);
                from_sg.ft = FT_CHAR;
                from_sg.nt = NT_CH;
                return 1;
        } else if (0 == strncmp("block", s->d_name, 5)) {
                strncpy(from_sg.name, s->d_name, NAME_LEN_MAX);
                from_sg.ft = FT_BLOCK;
                return 1;
        } else if (0 == strcmp("tape", s->d_name)) {
                strcpy(from_sg.name, s->d_name);
                from_sg.ft = FT_CHAR;
                from_sg.nt = NT_ST;
                return 1;
        } else if (0 == strncmp("scsi_tape:st", s->d_name, 12)) {
                len = strlen(s->d_name);
                if (isdigit(s->d_name[len - 1])) {
                        /* want 'st<num>' symlink only */
                        strcpy(from_sg.name, s->d_name);
                        from_sg.ft = FT_CHAR;
                        from_sg.nt = NT_ST;
                        return 1;
                } else
                        return 0;
        } else if (0 == strncmp("onstream_tape:os", s->d_name, 16)) {
                strcpy(from_sg.name, s->d_name);
                from_sg.ft = FT_CHAR;
                from_sg.nt = NT_OSST;
                return 1;
        } else
                return 0;
}

static int
from_sg_scan(const char * dir_name, int verbose)
{
        struct dirent ** namelist;
        int num, k;

        from_sg.ft = FT_OTHER;
        from_sg.nt = NT_NO_MATCH;
        num = scandir(dir_name, &namelist, from_sg_scandir_select, NULL);
        if (num < 0) {
                if (verbose)
                        fprintf(stderr, "scandir: %s %s\n", dir_name,
                                ssafe_strerror(errno));
                return -errno;
        }
        if (verbose) {
                for (k = 0; k < num; ++k)
                        fprintf(stderr, "    %s/%s\n", dir_name,
                                namelist[k]->d_name);
        }
        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);
        return num;
}

static struct sg_item_t to_sg;

static int
to_sg_scandir_select(const struct dirent * s)
{
        if (FT_OTHER != to_sg.ft)
                return 0;
        if (DT_LNK != s->d_type)
                return 0;
        if (0 == strncmp("scsi_generic", s->d_name, 12)) {
                strncpy(to_sg.name, s->d_name, NAME_LEN_MAX);
                to_sg.ft = FT_CHAR;
                to_sg.nt = NT_SG;
                return 1;
        } else
                return 0;
}

static int
to_sg_scan(const char * dir_name)
{
        struct dirent ** namelist;
        int num, k;

        to_sg.ft = FT_OTHER;
        to_sg.nt = NT_NO_MATCH;
        num = scandir(dir_name, &namelist, to_sg_scandir_select, NULL);
        if (num < 0)
                return -errno;
        for (k = 0; k < num; ++k)
                free(namelist[k]);
        free(namelist);
        return num;
}

/* Return 1 if directory, else 0 */
static int
if_directory_chdir(const char * dir_name, const char * base_name)
{
        char buff[D_NAME_LEN_MAX];
        struct stat a_stat;

        strcpy(buff, dir_name);
        strcat(buff, "/");
        strcat(buff, base_name);
        if (stat(buff, &a_stat) < 0)
                return 0;
        if (S_ISDIR(a_stat.st_mode)) {
                if (chdir(buff) < 0)
                        return 0;
                return 1;
        }
        return 0;
}

/* Return 1 if directory, else 0 */
static int
if_directory_ch2generic(const char * dir_name)
{
        char buff[NAME_LEN_MAX];
        struct stat a_stat;
        const char * old_name = "generic";

        strcpy(buff, dir_name);
        strcat(buff, "/");
        strcat(buff, old_name);
        if ((stat(buff, &a_stat) >= 0) && S_ISDIR(a_stat.st_mode)) {
                if (chdir(buff) < 0)
                        return 0;
                return 1;
        }
        /* No "generic", so now look for "scsi_generic:sg<n>" */
        if (1 != to_sg_scan(dir_name))
                return 0;
        strcpy(buff, dir_name);
        strcat(buff, "/");
        strcat(buff, to_sg.name);
        if (stat(buff, &a_stat) < 0)
                return 0;
        if (S_ISDIR(a_stat.st_mode)) {
                if (chdir(buff) < 0)
                        return 0;
                return 1;
        }
        return 0;
}

/* Return 1 if found, else 0 if problems */
static int
get_value(const char * dir_name, const char * base_name, char * value,
          int max_value_len)
{
        char buff[D_NAME_LEN_MAX];
        FILE * f;
        int len;

        if ((NULL == dir_name) && (NULL == base_name))
                return 0;
        if (dir_name) {
                strcpy(buff, dir_name);
                if (base_name && (strlen(base_name) > 0)) {
                        strcat(buff, "/");
                        strcat(buff, base_name);
                }
        } else
                strcpy(buff, base_name);
        if (NULL == (f = fopen(buff, "r"))) {
                return 0;
        }
        if (NULL == fgets(value, max_value_len, f)) {
                fclose(f);
                return 0;
        }
        len = strlen(value);
        if ((len > 0) && (value[len - 1] == '\n'))
                value[len - 1] = '\0';
        fclose(f);
        return 1;
}

static int
map_hd(const char * device_dir, int ma, int mi, int result,
       int follow_symlink, int verbose)
{
        char c, num;

        if (2 == result) {
                num = list_matching_nodes(device_dir, FT_BLOCK,
                                          ma, mi, follow_symlink,
                                          verbose);
                return (num > 0) ? 0 : 1;
        }
        switch (ma) {
        case IDE0_MAJOR: c = 'a'; break;
        case IDE1_MAJOR: c = 'c'; break;
        case IDE2_MAJOR: c = 'e'; break;
        case IDE3_MAJOR: c = 'g'; break;
        case IDE4_MAJOR: c = 'i'; break;
        case IDE5_MAJOR: c = 'k'; break;
        case IDE6_MAJOR: c = 'm'; break;
        case IDE7_MAJOR: c = 'o'; break;
        case IDE8_MAJOR: c = 'q'; break;
        case IDE9_MAJOR: c = 's'; break;
        default: c = '?'; break;
        }
        if (mi > 63)
                ++c;
        printf("%shd%c\n", sys_hd_dir, c);
        return 0;
}

static int
map_sd(const char * device_name, const char * device_dir, int ma, int mi,
       int result, int follow_symlink, int verbose)
{
        int index, m_mi, m_ma, num;
        char value[D_NAME_LEN_MAX];
        char name[D_NAME_LEN_MAX];

        if (2 == result) {
                num = list_matching_nodes(device_dir, FT_BLOCK, ma, mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        }
        if (SCSI_DISK0_MAJOR == ma)
                index = mi / 16;
        else if (ma >= SCSI_DISK8_MAJOR)
                index = (mi / 16) + 128 +
                        ((ma - SCSI_DISK8_MAJOR) * 16);
        else
                index = (mi / 16) + 16 +
                        ((ma - SCSI_DISK1_MAJOR) * 16);
        if (index < 26)
                snprintf(name, sizeof(name), "%ssd%c",
                         sys_sd_dir, 'a' + index % 26);
        else if (index < (26 + 1) * 26)
                snprintf(name, sizeof(name), "%ssd%c%c",
                         sys_sd_dir,
                         'a' + index / 26 - 1,'a' + index % 26);
        else {
                const unsigned int m1 = (index / 26 - 1) / 26 - 1;
                const unsigned int m2 = (index / 26 - 1) % 26;
                const unsigned int m3 =  index % 26;

                snprintf(name, sizeof(name), "%ssd%c%c%c",
                         sys_sd_dir, 'a' + m1, 'a' + m2, 'a' + m3);
        }
        if (3 == result) {
                printf("%s\n", name);
                return 0;
        }
        if (! get_value(name, "dev", value, sizeof(value))) {
                fprintf(stderr, "Couldn't find sysfs match for "
                        "device: %s\n", device_name);
                return 1;
        }
        if (verbose)
                fprintf(stderr, "sysfs sd dev: %s\n", value);
        if (! if_directory_chdir(name, "device")) {
                fprintf(stderr, "sysfs problem with device: %s\n",
                        device_name);
                return 1;
        }
        if (if_directory_ch2generic(".")) {
                if (1 == result) {
                        if (NULL == getcwd(value, sizeof(value)))
                                value[0] = '\0';
                        printf("%s\n", value);
                        return 0;
                }
                if (! get_value(".", "dev", value, sizeof(value))) {
                        fprintf(stderr, "Couldn't find sysfs generic"
                                "dev\n");
                        return 1;
                }
                if (verbose)
                        printf("matching dev: %s\n", value);
                if (2 != sscanf(value, "%d:%d", &m_ma, &m_mi)) {
                        fprintf(stderr, "Couldn't decode mapped "
                                "dev\n");
                        return 1;
                }
                num = list_matching_nodes(device_dir, FT_CHAR, m_ma, m_mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        } else {
                fprintf(stderr, "sd device: %s does not match any "
                        "SCSI generic device\n", device_name);
                fprintf(stderr, "    perhaps sg module is not "
                        "loaded\n");
                return 1;
        }
}

static int
map_sr(const char * device_name, const char * device_dir, int ma, int mi,
       int result, int follow_symlink, int verbose)
{
        int m_mi, m_ma, num;
        char value[D_NAME_LEN_MAX];
        char name[D_NAME_LEN_MAX];

        if (2 == result) {
                num = list_matching_nodes(device_dir, FT_BLOCK, ma, mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        }
        snprintf(name, sizeof(name), "%ssr%d", sys_sr_dir, mi);
        if (3 == result) {
                printf("%s\n", name);
                return 0;
        }
        if (! get_value(name, "dev", value, sizeof(value))) {
                fprintf(stderr, "Couldn't find sysfs match for "
                        "device: %s\n", device_name);
                return 1;
        }
        if (verbose)
                fprintf(stderr, "sysfs sr dev: %s\n", value);
        if (! if_directory_chdir(name, "device")) {
                fprintf(stderr, "sysfs problem with device: %s\n",
                        device_name);
                return 1;
        }
        if (if_directory_ch2generic(".")) {
                if (1 == result) {
                        if (NULL == getcwd(value, sizeof(value)))
                                value[0] = '\0';
                        printf("%s\n", value);
                        return 0;
                }
                if (! get_value(".", "dev", value, sizeof(value))) {
                        fprintf(stderr, "Couldn't find sysfs generic"
                                "dev\n");
                        return 1;
                }
                if (verbose)
                        printf("matching dev: %s\n", value);
                if (2 != sscanf(value, "%d:%d", &m_ma, &m_mi)) {
                        fprintf(stderr, "Couldn't decode mapped "
                                "dev\n");
                        return 1;
                }
                num = list_matching_nodes(device_dir, FT_BLOCK, m_ma, m_mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        } else {
                fprintf(stderr, "sr device: %s does not match any "
                        "SCSI generic device\n", device_name);
                fprintf(stderr, "    perhaps sg module is not "
                        "loaded\n");
                return 1;
        }
}

static int
map_st(const char * device_name, const char * device_dir, int ma, int mi,
       int result, int follow_symlink, int verbose)
{
        int m_mi, m_ma, num;
        char value[D_NAME_LEN_MAX];
        char name[D_NAME_LEN_MAX];

        if (2 == result) {
                num = list_matching_nodes(device_dir, FT_CHAR, ma, mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        }
        snprintf(name, sizeof(name), "%sst%d", sys_st_dir,
                 TAPE_NR(mi));
        if (3 == result) {
                printf("%s\n", name);
                return 0;
        }
        if (! get_value(name, "dev", value, sizeof(value))) {
                fprintf(stderr, "Couldn't find sysfs match for "
                        "device: %s\n", device_name);
                return 1;
        }
        if (verbose)
                fprintf(stderr, "sysfs st dev: %s\n", value);
        if (! if_directory_chdir(name, "device")) {
                fprintf(stderr, "sysfs problem with device: %s\n",
                        device_name);
                return 1;
        }
        if (if_directory_ch2generic(".")) {
                if (1 == result) {
                        if (NULL == getcwd(value, sizeof(value)))
                                value[0] = '\0';
                        printf("%s\n", value);
                        return 0;
                }
                if (! get_value(".", "dev", value, sizeof(value))) {
                        fprintf(stderr, "Couldn't find sysfs generic"
                                "dev\n");
                        return 1;
                }
                if (verbose)
                        printf("matching dev: %s\n", value);
                if (2 != sscanf(value, "%d:%d", &m_ma, &m_mi)) {
                        fprintf(stderr, "Couldn't decode mapped "
                                "dev\n");
                        return 1;
                }
                num = list_matching_nodes(device_dir, FT_CHAR, m_ma, m_mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        } else {
                fprintf(stderr, "st device: %s does not match any "
                        "SCSI generic device\n", device_name);
                fprintf(stderr, "    perhaps sg module is not "
                        "loaded\n");
                return 1;
        }
}

static int
map_osst(const char * device_name, const char * device_dir, int ma, int mi,
         int result, int follow_symlink, int verbose)
{
        int m_mi, m_ma, num;
        char value[D_NAME_LEN_MAX];
        char name[D_NAME_LEN_MAX];

        if (2 == result) {
                num = list_matching_nodes(device_dir, FT_CHAR, ma, mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        }
        snprintf(name, sizeof(name), "%sosst%d", sys_osst_dir,
                 TAPE_NR(mi));
        if (3 == result) {
                printf("%s\n", name);
                return 0;
        }
        if (! get_value(name, "dev", value, sizeof(value))) {
                fprintf(stderr, "Couldn't find sysfs match for "
                        "device: %s\n", device_name);
                return 1;
        }
        if (verbose)
                fprintf(stderr, "sysfs osst dev: %s\n", value);
        if (! if_directory_chdir(name, "device")) {
                fprintf(stderr, "sysfs problem with device: %s\n",
                        device_name);
                return 1;
        }
        if (if_directory_ch2generic(".")) {
                if (1 == result) {
                        if (NULL == getcwd(value, sizeof(value)))
                                value[0] = '\0';
                        printf("%s\n", value);
                        return 0;
                }
                if (! get_value(".", "dev", value, sizeof(value))) {
                        fprintf(stderr, "Couldn't find sysfs generic"
                                "dev\n");
                        return 1;
                }
                if (verbose)
                        printf("matching dev: %s\n", value);
                if (2 != sscanf(value, "%d:%d", &m_ma, &m_mi)) {
                        fprintf(stderr, "Couldn't decode mapped "
                                "dev\n");
                        return 1;
                }
                num = list_matching_nodes(device_dir, FT_CHAR, m_ma, m_mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        } else {
                fprintf(stderr, "osst device: %s does not match any "
                        "SCSI generic device\n", device_name);
                fprintf(stderr, "    perhaps sg module is not "
                        "loaded\n");
                return 1;
        }
}

static int
map_ch(const char * device_name, const char * device_dir, int ma, int mi,
       int result, int follow_symlink, int verbose)
{
        int m_mi, m_ma, num;
        char value[D_NAME_LEN_MAX];
        char name[D_NAME_LEN_MAX];

        if (2 == result) {
                num = list_matching_nodes(device_dir, FT_CHAR, ma, mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        }
        snprintf(name, sizeof(name), "%ssch%d", sys_sch_dir, mi);
        if (3 == result) {
                printf("%s\n", name);
                return 0;
        }
        if (! get_value(name, "dev", value, sizeof(value))) {
                fprintf(stderr, "Couldn't find sysfs match for "
                        "device: %s\n", device_name);
                return 1;
        }
        if (verbose)
                fprintf(stderr, "sysfs sch dev: %s\n", value);
        if (! if_directory_chdir(name, "device")) {
                fprintf(stderr, "sysfs problem with device: %s\n",
                        device_name);
                return 1;
        }
        if (if_directory_ch2generic(".")) {
                if (1 == result) {
                        if (NULL == getcwd(value, sizeof(value)))
                                value[0] = '\0';
                        printf("%s\n", value);
                        return 0;
                }
                if (! get_value(".", "dev", value, sizeof(value))) {
                        fprintf(stderr, "Couldn't find sysfs generic"
                                "dev\n");
                        return 1;
                }
                if (verbose)
                        printf("matching dev: %s\n", value);
                if (2 != sscanf(value, "%d:%d", &m_ma, &m_mi)) {
                        fprintf(stderr, "Couldn't decode mapped "
                                "dev\n");
                        return 1;
                }
                num = list_matching_nodes(device_dir, FT_CHAR, m_ma, m_mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        } else {
                fprintf(stderr, "sch device: %s does not match any "
                        "SCSI generic device\n", device_name);
                fprintf(stderr, "    perhaps sg module is not "
                        "loaded\n");
                return 1;
        }
}

static int
map_sg(const char * device_name, const char * device_dir, int ma, int mi,
       int result, int follow_symlink, int verbose)
{
        int m_mi, m_ma, num;
        char value[D_NAME_LEN_MAX];
        char name[D_NAME_LEN_MAX];

        if (2 == result) {
                num = list_matching_nodes(device_dir, FT_CHAR, ma, mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        }
        snprintf(name, sizeof(name), "%ssg%d", sys_sg_dir, mi);
        if (3 == result) {
                printf("%s\n", name);
                return 0;
        }
        if (! get_value(name, "dev", value, sizeof(value))) {
                fprintf(stderr, "Couldn't find sysfs match for "
                        "device: %s\n", device_name);
                return 1;
        }
        if (verbose)
                fprintf(stderr, "sysfs sg dev: %s\n", value);
        if (! if_directory_chdir(name, "device")) {
                fprintf(stderr, "sysfs problem with device: %s\n",
                        device_name);
                return 1;
        }
        if ((1 == from_sg_scan(".", verbose)) &&
            (if_directory_chdir(".", from_sg.name))) {
                if (DT_DIR == from_sg.d_type) {
                        if ((1 == scan_for_first(".", verbose)) &&
                            (if_directory_chdir(".", for_first.name))) {
                                ;
                        } else {
                                fprintf(stderr, "unexpected scan_for_first "
                                        "error\n");
                        }
                }
                if (1 == result) {
                        if (NULL == getcwd(value, sizeof(value)))
                                value[0] = '\0';
                        printf("%s\n", value);
                        return 0;
                }
                if (! get_value(".", "dev", value, sizeof(value))) {
                        fprintf(stderr, "Couldn't find sysfs block "
                                "dev\n");
                        return 1;
                }
                if (verbose)
                        printf("matching dev: %s\n", value);
                if (2 != sscanf(value, "%d:%d", &m_ma, &m_mi)) {
                        fprintf(stderr, "Couldn't decode mapped "
                                "dev\n");
                        return 1;
                }
                num = list_matching_nodes(device_dir, from_sg.ft, m_ma, m_mi,
                                          follow_symlink, verbose);
                return (num > 0) ? 0 : 1;
        } else {
                fprintf(stderr, "sg device: %s does not match any "
                        "other SCSI device\n", device_name);
                return 1;
        }
}


int
main(int argc, char * argv[])
{
        int c, num, tt, cont, res;
        int do_dev_dir = 0;
        int given_is = -1;
        int result = 0;
        int follow_symlink = 0;
        int verbose = 0;
        char device_name[D_NAME_LEN_MAX];
        char device_dir[D_NAME_LEN_MAX];
        char value[D_NAME_LEN_MAX];
        int ret = 1;
        int ma, mi;

        memset(device_name, 0, sizeof(device_name));
        memset(device_dir, 0, sizeof(device_dir));
        while (1) {
                int option_index = 0;

                c = getopt_long(argc, argv, "d:hg:r:svV", long_options,
                                &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'd':
                        strncpy(device_dir, optarg, sizeof(device_dir));
                        do_dev_dir = 1;
                        break;
                case 'g':
                        num = sscanf(optarg, "%d", &res);
                        if ((1 == num) && ((0 == res) || (1 == res)))
                                given_is = res;
                        else {
                                fprintf(stderr, "value for '--given_to=' "
                                        "must be 0 or 1\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'h':
                case '?':
                        usage();
                        return 0;
                case 'r':
                        num = sscanf(optarg, "%d", &res);
                        if ((1 == num) && (res >= 0) && (res < 4))
                                result = res;
                        else {
                                fprintf(stderr, "value for '--result=' "
                                        "must be 0..3\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 's':
                        follow_symlink = 1;
                        break;
                case 'v':
                        ++verbose;
                        break;
                case 'V':
                        fprintf(stderr, ME "version: %s\n", version_str);
                        return 0;
                default:
                        fprintf(stderr, "unrecognised option code 0x%x ??\n",
                                c);
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
        }
        if (optind < argc) {
                if ('\0' == device_name[0]) {
                        strncpy(device_name, argv[optind],
                                sizeof(device_name) - 1);
                        device_name[sizeof(device_name) - 1] = '\0';
                        ++optind;
                }
                if (optind < argc) {
                        for (; optind < argc; ++optind)
                                fprintf(stderr, "Unexpected extra argument: "
                                        "%s\n", argv[optind]);
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
        }

        if (0 == device_name[0]) {
                fprintf(stderr, "missing device name!\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }

        ma = 0;
        mi = 0;
        if (do_dev_dir) {
                if (if_directory_chdir(".", device_dir)) {
                        if (getcwd(device_dir, sizeof(device_dir)))
                                device_dir[sizeof(device_dir) - 1] = '\0';
                        else
                                device_dir[0] = '\0';
                        if (verbose > 1)
                                fprintf(stderr, "Absolute path to "
                                        "dev_dir: %s\n", device_dir);
                } else {
                        fprintf(stderr, "dev_dir: %s invalid\n", device_dir);
                        return SG_LIB_FILE_ERROR;
                }
        } else {
                strcpy(device_dir, device_name);
                dirname(device_dir);
                if (0 == strcmp(device_dir, device_name)) {
                        if (NULL == getcwd(device_dir, sizeof(device_dir)))
                                device_dir[0] = '\0';
                }
        }
        ret = nt_typ_from_filename(device_name, &ma, &mi);
        if (ret < 0) {
                fprintf(stderr, "stat failed on %s: %s\n", device_name,
                        ssafe_strerror(-ret));
                return SG_LIB_FILE_ERROR;
        }
        if (verbose)
                fprintf(stderr, " %s: %s device [maj=%d, min=%d]\n",
                        device_name, nt_names[ret], ma, mi);
        res = 0;
        switch (ret) {
        case NT_SD:
        case NT_SR:
        case NT_HD:
                if (given_is > 0) {
                        fprintf(stderr, "block special but '--given_is=' "
                                "suggested sysfs device\n");
                        return SG_LIB_FILE_ERROR;
                }
                break;
        case NT_ST:
        case NT_OSST:
        case NT_CH:
        case NT_SG:
                if (given_is > 0) {
                        fprintf(stderr, "character special but '--given_is=' "
                                "suggested sysfs device\n");
                        return SG_LIB_FILE_ERROR;
                }
                break;
        case NT_REG:
                if (0 == given_is) {
                        fprintf(stderr, "regular file but '--given_is=' "
                                "suggested block or char special\n");
                        return SG_LIB_FILE_ERROR;
                }
                strcpy(device_dir, def_dev_dir);
                break;
        case NT_DIR:
                if (0 == given_is) {
                        fprintf(stderr, "directory but '--given_is=' "
                                "suggested block or char special\n");
                        return SG_LIB_FILE_ERROR;
                }
                strcpy(device_dir, def_dev_dir);
                break;
        default:
                break;
        }

        tt = NT_NO_MATCH;
        do {
                cont = 0;
                switch (ret) {
                case NT_NO_MATCH:
                        res = 1;
                        break;
                case NT_SD:
                        res = map_sd(device_name, device_dir, ma, mi, result,
                                     follow_symlink, verbose);
                        break;
                case NT_SR:
                        res = map_sr(device_name, device_dir, ma, mi, result,
                                     follow_symlink, verbose);
                        break;
                case NT_HD:
                        if (result < 2) {
                                fprintf(stderr, "a hd device does not map "
                                        "to a sg device\n");
                                return SG_LIB_FILE_ERROR;
                        }
                        res = map_hd(device_dir, ma, mi, result,
                                     follow_symlink, verbose);
                        break;
                case NT_ST:
                        res = map_st(device_name, device_dir, ma, mi, result,
                                     follow_symlink, verbose);
                        break;
                case NT_OSST:
                        res = map_osst(device_name, device_dir, ma, mi,
                                       result, follow_symlink, verbose);
                        break;
                case NT_CH:
                        res = map_ch(device_name, device_dir, ma, mi, result,
                                     follow_symlink, verbose);
                        break;
                case NT_SG:
                        res = map_sg(device_name, device_dir, ma, mi, result,
                                     follow_symlink, verbose);
                        break;
                case NT_REG:
                        if (! get_value(NULL, device_name, value,
                                        sizeof(value))) {
                                fprintf(stderr, "Couldn't fetch value "
                                        "from: %s\n", device_name);
                                return SG_LIB_FILE_ERROR;
                        }
                        if (verbose)
                                fprintf(stderr, "value: %s\n", value);
                        if (2 != sscanf(value, "%d:%d", &ma, &mi)) {
                                fprintf(stderr, "Couldn't decode value\n");
                                return SG_LIB_FILE_ERROR;
                        }
                        tt = nt_typ_from_major(ma);
                        cont = 1;
                        break;
                case NT_DIR:
                        if (! get_value(device_name, "dev", value,
                                        sizeof(value))) {
                                fprintf(stderr, "Couldn't fetch value from: "
                                        "%s/dev\n", device_name);
                                return SG_LIB_FILE_ERROR;
                        }
                        if (verbose)
                                fprintf(stderr, "value: %s\n", value);
                        if (2 != sscanf(value, "%d:%d", &ma, &mi)) {
                                fprintf(stderr, "Couldn't decode value\n");
                                return SG_LIB_FILE_ERROR;
                        }
                        tt = nt_typ_from_major(ma);
                        cont = 1;
                        break;
                default:
                        break;
                }
                ret = tt;
        } while (cont);
        return res;
}

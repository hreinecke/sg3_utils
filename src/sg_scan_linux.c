/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 1999 - 2018 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program scans the "sg" device space (ie actual + simulated SCSI
 * generic devices). Optionally sg_scan can be given other device names
 * to scan (in place of the sg devices).
 * Options: -a   alpha scan: scan /dev/sga,b,c, ....
 *          -i   do SCSI inquiry on device (implies -w)
 *          -n   numeric scan: scan /dev/sg0,1,2, ....
 *          -V   output version string and exit
 *          -w   open writable (new driver opens readable unless -i)
 *          -x   extra information output
 *
 * By default this program will look for /dev/sg0 first (i.e. numeric scan)
 *
 * Note: This program is written to work under both the original and
 * the new sg driver.
 *
 * F. Jansen - modification to extend beyond 26 sg devices.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <dirent.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <scsi/scsi_ioctl.h>

#include "sg_lib.h"
#include "sg_io_linux.h"
#include "sg_pr2serr.h"


static const char * version_str = "4.17 20180219";

#define ME "sg_scan: "

#define NUMERIC_SCAN_DEF true /* change to false to make alpha scan default */

#define INQ_REPLY_LEN 36
#define INQ_CMD_LEN 6
#define MAX_ERRORS 4

#define EBUFF_SZ 256
#define FNAME_SZ 64
#define PRESENT_ARRAY_SIZE 8192

static const char * sysfs_sg_dir = "/sys/class/scsi_generic";
static int * gen_index_arr;

typedef struct my_scsi_idlun {
/* why can't userland see this structure ??? */
    int dev_id;
    int host_unique_id;
} My_scsi_idlun;

typedef struct my_sg_scsi_id {
    int host_no;        /* as in "scsi<n>" where 'n' is one of 0, 1, 2 etc */
    int channel;
    int scsi_id;        /* scsi id of target device */
    int lun;
    int scsi_type;      /* TYPE_... defined in scsi/scsi.h */
    short h_cmd_per_lun;/* host (adapter) maximum commands per lun */
    short d_queue_depth;/* device (or adapter) maximum queue length */
    int unused1;        /* probably find a good use, set 0 for now */
    int unused2;        /* ditto */
} My_sg_scsi_id;

int sg3_inq(int sg_fd, uint8_t * inqBuff, bool do_extra);
int scsi_inq(int sg_fd, uint8_t * inqBuff);
int try_ata_identity(const char * file_namep, int ata_fd, bool do_inq);

static uint8_t inq_cdb[INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};


void usage()
{
    printf("Usage: sg_scan [-a] [-i] [-n] [-v] [-V] [-w] [-x] "
           "[DEVICE]*\n");
    printf("  where:\n");
    printf("    -a    do alpha scan (ie sga, sgb, sgc)\n");
    printf("    -i    do SCSI INQUIRY, output results\n");
    printf("    -n    do numeric scan (ie sg0, sg1...) [default]\n");
    printf("    -v    increase verbosity\n");
    printf("    -V    output version string then exit\n");
    printf("    -w    force open with read/write flag\n");
    printf("    -x    extra information output about queuing\n");
    printf("   DEVICE    name of device\n");
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

void make_dev_name(char * fname, int k, bool do_numeric)
{
    char buff[FNAME_SZ];
    int  big,little;

    strcpy(fname, "/dev/sg");
    if (do_numeric) {
        snprintf(buff, sizeof(buff), "%d", k);
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
    bool do_extra = false;
    bool do_inquiry = false;
    bool do_numeric = NUMERIC_SCAN_DEF;
    bool eacces_err = false;
    bool has_file_args = false;
    bool has_sysfs_sg = false;
    bool jmp_out;
    bool sg_ver3 = false;
    bool sg_ver3_set = false;
    bool writeable = false;
    int sg_fd, res, k, j, f, plen;
    int emul = -1;
    int flags;
    int host_no;
    const int max_file_args = PRESENT_ARRAY_SIZE;
    int num_errors = 0;
    int num_silent = 0;
    int verbose = 0;
    char * file_namep;
    const char * cp;
    char fname[FNAME_SZ];
    char ebuff[EBUFF_SZ];
    uint8_t inqBuff[INQ_REPLY_LEN];
    My_scsi_idlun my_idlun;
    struct stat a_stat;

    if (NULL == (gen_index_arr =
                 (int *)calloc(max_file_args + 1, sizeof(int)))) {
        printf(ME "Out of memory\n");
        return SG_LIB_CAT_OTHER;
    }

    for (k = 1, j = 0; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = false; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'a':
                    do_numeric = false;
                    break;
                case 'h':
                case '?':
                    printf("Scan sg device names and optionally do an "
                           "INQUIRY\n\n");
                    usage();
                    return 0;
                case 'i':
                    do_inquiry = true;
                    break;
                case 'n':
                    do_numeric = true;
                    break;
                case 'v':
                    ++verbose;
                    break;
                case 'V':
                    pr2serr("Version string: %s\n", version_str);
                    exit(0);
                case 'w':
                    writeable = true;
                    break;
                case 'x':
                    do_extra = true;
                    break;
                default:
                    jmp_out = true;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (jmp_out) {
                pr2serr("Unrecognized option: %s\n", cp);
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else {
            if (j < max_file_args) {
                has_file_args = true;
                gen_index_arr[j++] = k;
            } else {
                printf("Too many command line arguments\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        }
    }

    if ((! has_file_args) && (stat(sysfs_sg_dir, &a_stat) >= 0) &&
        (S_ISDIR(a_stat.st_mode)))
        has_sysfs_sg = !! sysfs_sg_scan(sysfs_sg_dir);

    flags = O_NONBLOCK | (writeable ? O_RDWR : O_RDONLY);

    for (k = 0, res = 0, j = 0, sg_fd = -1;
         (k < max_file_args)  && (has_file_args || (num_errors < MAX_ERRORS));
         ++k, res = ((sg_fd >= 0) ? close(sg_fd) : 0)) {
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, ME "Error closing %s ", fname);
            perror(ebuff);
            return SG_LIB_FILE_ERROR;
        }
        if (has_file_args) {
            if (gen_index_arr[j])
                file_namep = argv[gen_index_arr[j++]];
            else
                break;
        } else if (has_sysfs_sg) {
            if (0 == gen_index_arr[k]) {
                sg_fd = -1;
                continue;
            }
            make_dev_name(fname, k, 1);
            file_namep = fname;
        } else {
            make_dev_name(fname, k, do_numeric);
            file_namep = fname;
        }

        sg_fd = open(file_namep, flags);
        if (sg_fd < 0) {
            if (EBUSY == errno) {
                printf("%s: device busy (O_EXCL lock), skipping\n",
                       file_namep);
                continue;
            }
            else if ((ENODEV == errno) || (ENOENT == errno) ||
                     (ENXIO == errno)) {
                if (verbose)
                    pr2serr("Unable to open: %s, errno=%d\n", file_namep,
                            errno);
                ++num_errors;
                ++num_silent;
                continue;
            }
            else {
                if (EACCES == errno)
                    eacces_err = true;
                snprintf(ebuff, EBUFF_SZ, ME "Error opening %s ", file_namep);
                perror(ebuff);
                ++num_errors;
                continue;
            }
        }
        res = ioctl(sg_fd, SCSI_IOCTL_GET_IDLUN, &my_idlun);
        if (res < 0) {
            res = try_ata_identity(file_namep, sg_fd, do_inquiry);
            if (res == 0)
                continue;
            snprintf(ebuff, EBUFF_SZ, ME "device %s failed on scsi+ata "
                     "ioctl, skip", file_namep);
            perror(ebuff);
            ++num_errors;
            continue;
        }
        res = ioctl(sg_fd, SCSI_IOCTL_GET_BUS_NUMBER, &host_no);
        if (res < 0) {
            snprintf(ebuff, EBUFF_SZ, ME "device %s failed on scsi "
                     "ioctl(2), skip", file_namep);
            perror(ebuff);
            ++num_errors;
            continue;
        }
        res = ioctl(sg_fd, SG_EMULATED_HOST, &emul);
        if (res < 0)
            emul = -1;
        printf("%s: scsi%d channel=%d id=%d lun=%d", file_namep, host_no,
               (my_idlun.dev_id >> 16) & 0xff, my_idlun.dev_id & 0xff,
               (my_idlun.dev_id >> 8) & 0xff);
        if (1 == emul)
            printf(" [em]");
#if 0
        printf(", huid=%d", my_idlun.host_unique_id);
#endif
        if (! has_file_args) {
            My_sg_scsi_id m_id; /* compatible with sg_scsi_id_t in sg.h */

            res = ioctl(sg_fd, SG_GET_SCSI_ID, &m_id);
            if (res < 0) {
                snprintf(ebuff, EBUFF_SZ, ME "device %s failed "
                         "SG_GET_SCSI_ID ioctl(4), skip", file_namep);
                perror(ebuff);
                ++num_errors;
                continue;
            }
            /* printf("  type=%d", m_id.scsi_type); */
            if (do_extra)
                printf("  cmd_per_lun=%hd queue_depth=%hd\n",
                       m_id.h_cmd_per_lun, m_id.d_queue_depth);
            else
                printf("\n");
        }
        else
            printf("\n");
        if (do_inquiry) {
            if (! sg_ver3_set) {
                sg_ver3 = false;
                sg_ver3_set = true;
                if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &f) >= 0) &&
                    (f >= 30000))
                    sg_ver3 = true;
            }
            if (sg_ver3) {
                res = sg3_inq(sg_fd, inqBuff, do_extra);
                if (res)
                    ++num_errors;
            }
        }
    }
    if ((num_errors >= MAX_ERRORS) && (num_silent < num_errors) &&
        (! has_file_args)) {
        printf("Stopping because there are too many error\n");
        if (eacces_err)
            printf("    root access may be required\n");
    }
    return 0;
}

int sg3_inq(int sg_fd, uint8_t * inqBuff, bool do_extra)
{
    bool ok;
    int err, sg_io;
    uint8_t sense_buffer[32];
    struct sg_io_hdr io_hdr;

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    memset(inqBuff, 0, INQ_REPLY_LEN);
    inqBuff[0] = 0x7f;
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inq_cdb);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = INQ_REPLY_LEN;
    io_hdr.dxferp = inqBuff;
    io_hdr.cmdp = inq_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */

    ok = true;
    sg_io = 0;
    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        if ((err = scsi_inq(sg_fd, inqBuff)) < 0) {
            perror(ME "Inquiry SG_IO + SCSI_IOCTL_SEND_COMMAND ioctl error");
            return 1;
        } else if (err) {
            printf(ME "SCSI_IOCTL_SEND_COMMAND ioctl error=0x%x\n", err);
            return 1;
        }
    } else {
        sg_io = 1;
        /* now for the error processing */
        switch (sg_err_category3(&io_hdr)) {
        case SG_LIB_CAT_RECOVERED:
            sg_chk_n_print3("Inquiry, continuing", &io_hdr, true);
#if defined(__GNUC__)
#if (__GNUC__ >= 7)
            __attribute__((fallthrough));
            /* FALL THROUGH */
#endif
#endif
        case SG_LIB_CAT_CLEAN:
            break;
        default: /* won't bother decoding other categories */
            ok = false;
            sg_chk_n_print3("INQUIRY command error", &io_hdr, true);
            break;
        }
    }

    if (ok) { /* output result if it is available */
        char * p = (char *)inqBuff;

        printf("    %.8s  %.16s  %.4s ", p + 8, p + 16, p + 32);
        printf("[rmb=%d cmdq=%d pqual=%d pdev=0x%x] ",
               !!(p[1] & 0x80), !!(p[7] & 2), (p[0] & 0xe0) >> 5,
               (p[0] & 0x1f));
        if (do_extra && sg_io)
            printf("dur=%ums\n", io_hdr.duration);
        else
            printf("\n");
    }
    return 0;
}

struct lscsi_ioctl_command {
        unsigned int inlen;  /* _excluding_ scsi command length */
        unsigned int outlen;
        uint8_t data[1];  /* was 0 but that's not ISO C!! */
                /* on input, scsi command starts here then opt. data */
};

/* fallback INQUIRY using scsi mid-level's SCSI_IOCTL_SEND_COMMAND ioctl */
int scsi_inq(int sg_fd, uint8_t * inqBuff)
{
    int res;
    uint8_t buff[1024];
    struct lscsi_ioctl_command * sicp = (struct lscsi_ioctl_command *)buff;

    memset(buff, 0, sizeof(buff));
    sicp->inlen = 0;
    sicp->outlen = INQ_REPLY_LEN;
    memcpy(sicp->data, inq_cdb, INQ_CMD_LEN);
    res = ioctl(sg_fd, SCSI_IOCTL_SEND_COMMAND, sicp);
    if (0 == res)
        memcpy(inqBuff, sicp->data, INQ_REPLY_LEN);
    return res;
}

/* Following code permits ATA IDENTIFY commands to be performed on
   ATA non "Packet Interface" devices (e.g. ATA disks).
   GPL-ed code borrowed from smartmontools (smartmontools.sf.net).
   Copyright (C) 2002-4 Bruce Allen
                <smartmontools-support@lists.sourceforge.net>
 */
#ifndef ATA_IDENTIFY_DEVICE
#define ATA_IDENTIFY_DEVICE 0xec
#endif
#ifndef HDIO_DRIVE_CMD
#define HDIO_DRIVE_CMD    0x031f
#endif

/* Needed parts of the ATA DRIVE IDENTIFY Structure. Those labeled
 * word* are NOT used.
 */
struct ata_identify_device {
  unsigned short words000_009[10];
  uint8_t  serial_no[20];
  unsigned short words020_022[3];
  uint8_t  fw_rev[8];
  uint8_t  model[40];
  unsigned short words047_079[33];
  unsigned short major_rev_num;
  unsigned short minor_rev_num;
  unsigned short command_set_1;
  unsigned short command_set_2;
  unsigned short command_set_extension;
  unsigned short cfs_enable_1;
  unsigned short word086;
  unsigned short csf_default;
  unsigned short words088_255[168];
};

/* Copies n bytes (or n-1 if n is odd) from in to out, but swaps adjacents
 * bytes.
 */
void swapbytes(char *out, const char *in, size_t n)
{
    size_t k;

    if (n > 1) {
        for (k = 0; k < (n - 1); k += 2) {
            out[k] = in[k + 1];
            out[k + 1] = in[k];
        }
    }
}

/* Copies in to out, but removes leading and trailing whitespace. */
void trim(char *out, const char *in)
{
    int k, first, last, num;

    /* Find the first non-space character (maybe none). */
    first = -1;
    for (k = 0; in[k]; k++) {
        if (! isspace((int)in[k])) {
            first = k;
            break;
        }
    }

    if (first == -1) {
        /* There are no non-space characters. */
        out[0] = '\0';
        return;
    }

    /* Find the last non-space character. */
    for (k = strlen(in) - 1; k >= first && isspace((int)in[k]); k--)
        ;
    last = k;
    num = last - first + 1;
    for (k = 0; k < num; ++k)
        out[k] = in[first + k];
    out[num] = '\0';
}

/* Convenience function for formatting strings from ata_identify_device */
void formatdriveidstring(char *out, const char *in, int n)
{
    char tmp[65];

    n = n > 64 ? 64 : n;
    swapbytes(tmp, in, n);
    tmp[n] = '\0';
    trim(out, tmp);
}

/* Function for printing ASCII byte-swapped strings, skipping white
 * space. Please note that this is needed on both big- and
 * little-endian hardware.
 */
void printswap(char *output, char *in, unsigned int n)
{
    formatdriveidstring(output, in, n);
    if (*output)
        printf("%.*s   ", (int)n, output);
    else
        printf("%.*s   ", (int)n, "[No Information Found]\n");
}

#define ATA_IDENTIFY_BUFF_SZ  sizeof(struct ata_identify_device)
#define HDIO_DRIVE_CMD_OFFSET 4

int ata_command_interface(int device, char *data)
{
    uint8_t buff[ATA_IDENTIFY_BUFF_SZ + HDIO_DRIVE_CMD_OFFSET];
    int retval;

    buff[0] = ATA_IDENTIFY_DEVICE;
    buff[3] = 1;
    /* We are now doing the HDIO_DRIVE_CMD type ioctl. */
    if ((retval = ioctl(device, HDIO_DRIVE_CMD, buff)))
        return retval;

    /* if the command returns data, copy it back */
    memcpy(data, buff + HDIO_DRIVE_CMD_OFFSET, ATA_IDENTIFY_BUFF_SZ);
    return 0;
}

int try_ata_identity(const char * file_namep, int ata_fd, bool do_inq)
{
    struct ata_identify_device ata_ident;
    char model[64];
    char serial[64];
    char firm[64];
    int res;

    res = ata_command_interface(ata_fd, (char *)&ata_ident);
    if (res)
        return res;
    printf("%s: ATA device\n", file_namep);
    if (do_inq) {
        printf("    ");
        printswap(model, (char *)ata_ident.model, 40);
        printswap(serial, (char *)ata_ident.serial_no, 20);
        printswap(firm, (char *)ata_ident.fw_rev, 8);
        printf("\n");
    }
    return res;
}

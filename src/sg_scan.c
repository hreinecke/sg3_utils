/* N.B. There are two programs in this file, the first is for linux
 *      and the second is for Windows.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef SG3_UTILS_LINUX

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
#include <dirent.h>
#include <libgen.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <scsi/scsi_ioctl.h>

#include "sg_lib.h"
#include "sg_io_linux.h"

/* Test code for D. Gilbert's extensions to the Linux OS SCSI generic ("sg")
   device driver.
*  Copyright (C) 1999 - 2007 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program scans the "sg" device space (ie actual + simulated SCSI
   generic devices). Optionally sg_scan can be given other device names
   to scan (in place of the sg devices).
   Options: -a   alpha scan: scan /dev/sga,b,c, ....
            -i   do SCSI inquiry on device (implies -w)
            -n   numeric scan: scan /dev/sg0,1,2, ....
            -V   output version string and exit
            -w   open writable (new driver opens readable unless -i)
            -x   extra information output

   By default this program will look for /dev/sg0 first (i.e. numeric scan)

   Note: This program is written to work under both the original and
   the new sg driver.

   F. Jansen - modification to extend beyond 26 sg devices.
*/

static char * version_str = "4.09 20070714";

#define ME "sg_scan: "

#define NUMERIC_SCAN_DEF 1   /* change to 0 to make alpha scan default */

#define INQ_REPLY_LEN 36
#define INQ_CMD_LEN 6
#define MAX_ERRORS 4

#define EBUFF_SZ 256
#define FNAME_SZ 64
#define PRESENT_ARRAY_SIZE 4096

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

int sg3_inq(int sg_fd, unsigned char * inqBuff, int do_extra);
int scsi_inq(int sg_fd, unsigned char * inqBuff);
int try_ata_identity(const char * file_namep, int ata_fd, int do_inq);

static unsigned char inqCmdBlk[INQ_CMD_LEN] =
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

void make_dev_name(char * fname, int k, int do_numeric)
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
    int sg_fd, res, k, j, f, plen, jmp_out;
    unsigned char inqBuff[INQ_REPLY_LEN];
    int do_numeric = NUMERIC_SCAN_DEF;
    int do_inquiry = 0;
    int do_extra = 0;
    int verbose = 0;
    int writeable = 0;
    int num_errors = 0;
    int num_silent = 0;
    int sg_ver3 = -1;
    int eacces_err = 0;
    char fname[FNAME_SZ];
    char * file_namep;
    char ebuff[EBUFF_SZ];
    My_scsi_idlun my_idlun;
    int host_no;
    int flags;
    int emul = -1;
    int has_file_args = 0;
    int has_sysfs_sg = 0;
    const int max_file_args = PRESENT_ARRAY_SIZE;
    const char * cp;
    struct stat a_stat;

    if ((gen_index_arr = (int *)malloc(max_file_args * sizeof(int))))
        memset(gen_index_arr, 0, max_file_args * sizeof(int));
    else {
        printf(ME "Out of memory\n");
        return SG_LIB_CAT_OTHER;
    }

    for (k = 1, j = 0; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'a':
                    do_numeric = 0;
                    break;
                case 'h':
                case '?':
                    printf("Scan sg device names and optionally do an "
                           "INQUIRY\n\n");
                    usage();
                    return 0;
                case 'i':
                    do_inquiry = 1;
                    break;
                case 'n':
                    do_numeric = 1;
                    break;
                case 'v':
                    ++verbose;
                    break;
                case 'V':
                    fprintf(stderr, "Version string: %s\n", version_str);
                    exit(0);
                case 'w':
                    writeable = 1;
                    break;
                case 'x':
                    do_extra = 1;
                    break;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else {
            if (j < max_file_args) {
                has_file_args = 1;
                gen_index_arr[j++] = k;
            } else {
                printf("Too many command line arguments\n");
                return SG_LIB_SYNTAX_ERROR;
            }
        }
    }

    if ((! has_file_args) && (stat(sysfs_sg_dir, &a_stat) >= 0) &&
        (S_ISDIR(a_stat.st_mode)))
        has_sysfs_sg = sysfs_sg_scan(sysfs_sg_dir);
    
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
                printf("%s: device busy (O_EXCL lock), skipping\n", file_namep);
                continue;
            }
            else if ((ENODEV == errno) || (ENOENT == errno) ||
                     (ENXIO == errno)) {
                if (verbose)
                    fprintf(stderr, "Unable to open: %s, errno=%d\n",
                            file_namep, errno);
                ++num_errors;
                ++num_silent;
                continue;
            }
            else {
                if (EACCES == errno)
                    eacces_err = 1;
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
            if (-1 == sg_ver3) {
                sg_ver3 = 0;
                if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &f) >= 0) && 
                    (f >= 30000))
                    sg_ver3 = 1;
            }
            if (1 == sg_ver3)
                res = sg3_inq(sg_fd, inqBuff, do_extra);
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

int sg3_inq(int sg_fd, unsigned char * inqBuff, int do_extra)
{
    struct sg_io_hdr io_hdr;
    unsigned char sense_buffer[32];
    int ok, err, sg_io;

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    memset(inqBuff, 0, INQ_REPLY_LEN);
    inqBuff[0] = 0x7f;
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inqCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = INQ_REPLY_LEN;
    io_hdr.dxferp = inqBuff;
    io_hdr.cmdp = inqCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */

    ok = 1;
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
            sg_chk_n_print3("Inquiry, continuing", &io_hdr, 1);
            /* fall through */
        case SG_LIB_CAT_CLEAN:
            break;
        default: /* won't bother decoding other categories */
            ok = 0;
            sg_chk_n_print3("INQUIRY command error", &io_hdr, 1);
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
        unsigned char data[1];  /* was 0 but that's not ISO C!! */
                /* on input, scsi command starts here then opt. data */
};

/* fallback INQUIRY using scsi mid-level's SCSI_IOCTL_SEND_COMMAND ioctl */
int scsi_inq(int sg_fd, unsigned char * inqBuff)
{
    int res;
    unsigned char buff[512];
    struct lscsi_ioctl_command * sicp = (struct lscsi_ioctl_command *)buff;

    memset(buff, 0, sizeof(buff));
    sicp->inlen = 0;
    sicp->outlen = INQ_REPLY_LEN;
    memcpy(sicp->data, inqCmdBlk, INQ_CMD_LEN);
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
  unsigned char  serial_no[20];
  unsigned short words020_022[3];
  unsigned char  fw_rev[8];
  unsigned char  model[40];
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
    int k, first, last;

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
    strncpy(out, in + first, last - first + 1);
    out[last - first + 1] = '\0';
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
    unsigned char buff[ATA_IDENTIFY_BUFF_SZ + HDIO_DRIVE_CMD_OFFSET];
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

int try_ata_identity(const char * file_namep, int ata_fd, int do_inq)
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

#endif

#ifdef SG3_UTILS_WIN32

/*
 * Copyright (c) 2006 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/*
 * This utility shows the relationship between various SCSI device naming
 * schemes in Windows OSes (Windows 200, 2003 and XP) as seen by
 * The SCSI Pass Through (SPT) interface. N.B. ASPI32 is not used.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#include "sg_lib.h"
#include "sg_pt_win32.h"

#define MAX_SCSI_ELEMS 1024
#define MAX_ADAPTER_NUM 64
#define MAX_PHYSICALDRIVE_NUM 512
#define MAX_CDROM_NUM 512
#define MAX_TAPE_NUM 512
#define MAX_HOLE_COUNT 8
#define SCSI2_INQ_RESP_LEN 36
#define DEF_TIMEOUT 20
#define INQUIRY_CMD 0x12
#define INQUIRY_CMDLEN 6

static char * version_str = "1.04 (win32) 20070101";

struct w_scsi_elem {
    char    in_use;
    char    scsi_adapter_valid;
    UCHAR   port_num;           /* <n> in '\\.\SCSI<n>:' adapter name */
    UCHAR   bus;                /* also known as pathId */
    UCHAR   target;
    UCHAR   lun;
    UCHAR   device_claimed;     /* class driver claimed this lu */
    UCHAR   dubious_scsi;       /* set if inq_resp[4] is zero */
    char    pdt;                /* peripheral device type (see SPC-4) */
    char    volume_valid;
    char    volume_multiple;    /* multiple partitions mapping to volumes */
    UCHAR   volume_letter;      /* lowest 'C:' through to 'Z:' */
    char    physicaldrive_valid;
    char    cdrom_valid;
    char    tape_valid;
    int     physicaldrive_num;
    int     cdrom_num;
    int     tape_num;
    unsigned char inq_resp[SCSI2_INQ_RESP_LEN];
};

static struct w_scsi_elem * w_scsi_arr;

static int next_unused_scsi_elem = 0;
static int next_elem_after_scsi_adapter_valid = 0;


static struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"letter", 1, 0, '1'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr,
            "Usage: sg_scan  [--help] [--letter=VL] [--verbose] "
            "[--version]\n");
    fprintf(stderr,
            "       --help|-h       output this usage message then exit\n"
            "       --letter=VL|-l VL    volume letter (e.g. 'F' for F:) "
            "to find\n"
            "       --verbose|-v    increase verbosity\n"
            "       --version|-V    print version string and exit\n\n"
            "Scan for SCSI and related device names\n");
}

static char * get_err_str(DWORD err, int max_b_len, char * b)
{
    LPVOID lpMsgBuf;
    int k, num, ch;

    if (max_b_len < 2) {
        if (1 == max_b_len)
            b[0] = '\0';
        return b;
    }
    memset(b, 0, max_b_len);
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL, err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf, 0, NULL );
    num = lstrlen((LPCTSTR)lpMsgBuf);
    if (num < 1)
        return b;
    num = (num < max_b_len) ? num : (max_b_len - 1);
    for (k = 0; k < num; ++k) {
        ch = *((LPCTSTR)lpMsgBuf + k);
        if ((ch >= 0x0) && (ch < 0x7f))
            b[k] = ch & 0x7f;
        else
            b[k] = '?';
    }
    return b;
}

static int findElemIndex(UCHAR port_num, UCHAR bus, UCHAR target, UCHAR lun)
{
    int k;
    struct w_scsi_elem * sep;

    for (k = 0; k < next_unused_scsi_elem; ++k) {
        sep = w_scsi_arr + k;
        if ((port_num == sep->port_num) && (bus == sep->bus) &&
            (target == sep->target) && (lun == sep->lun))
            return k;
#if 0
        if (port_num < sep->port_num)
            break;      /* assume port_num sorted ascending */
#endif
    }
    return -1;
}

static BOOL fetchInquiry(HANDLE fh, unsigned char * resp, int max_resp_len,
                         SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER * afterCall,
                         int verbose)
{
    BOOL success;
    int len;
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdw;
    ULONG dummy;        /* also acts to align next array */
    BYTE inqResp[SCSI2_INQ_RESP_LEN];
    unsigned char inqCdb[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0,
                                            SCSI2_INQ_RESP_LEN, 0};
    DWORD err;
    char b[256];

    memset(&sptdw, 0, sizeof(sptdw));
    memset(inqResp, 0, sizeof(inqResp));
    sptdw.spt.Length = sizeof (SCSI_PASS_THROUGH_DIRECT);
    sptdw.spt.CdbLength = sizeof(inqCdb);
    sptdw.spt.SenseInfoLength = SCSI_MAX_SENSE_LEN;
    sptdw.spt.DataIn = SCSI_IOCTL_DATA_IN;
    sptdw.spt.DataTransferLength = SCSI2_INQ_RESP_LEN;
    sptdw.spt.TimeOutValue = DEF_TIMEOUT;
    sptdw.spt.DataBuffer = inqResp;
    sptdw.spt.SenseInfoOffset =
                offsetof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, ucSenseBuf);
    memcpy(sptdw.spt.Cdb, inqCdb, sizeof(inqCdb));

    success = DeviceIoControl(fh, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                              &sptdw, sizeof(sptdw),
                              &sptdw, sizeof(sptdw),
                              &dummy, NULL);
    if (! success) {
        if (verbose) {
            err = GetLastError();
            fprintf(stderr, "fetchInquiry: DeviceIoControl for INQUIRY, "
                    "err=%lu\n\t%s", err, get_err_str(err, sizeof(b), b));
        }
        return success;
    }
    if (afterCall)
        memcpy(afterCall, &sptdw, sizeof(SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER));
    if (resp) {
        len = (SCSI2_INQ_RESP_LEN > max_resp_len) ?
              max_resp_len : SCSI2_INQ_RESP_LEN;
        memcpy(resp, inqResp, len);
    }
    return success;
}

static int sg_do_wscan(char letter, int verbose)
{
    int k, j, m, hole_count, index, matched;
    DWORD err;
    HANDLE fh;
    ULONG dummy;
    BOOL success;
    BYTE bus;
    PSCSI_ADAPTER_BUS_INFO  ai;
    SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER sptdw;
    unsigned char inqResp[SCSI2_INQ_RESP_LEN];
    char adapter_name[64];
    char inqDataBuff[2048];
    char b[256];
    struct w_scsi_elem * sep;

    memset(w_scsi_arr, 0, sizeof(w_scsi_arr));
    hole_count = 0;
    for (k = 0; k < MAX_ADAPTER_NUM; ++k) {
        snprintf(adapter_name, sizeof (adapter_name), "\\\\.\\SCSI%d:", k);
        fh = CreateFile(adapter_name, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (fh != INVALID_HANDLE_VALUE) {
            hole_count = 0;
            success = DeviceIoControl(fh, IOCTL_SCSI_GET_INQUIRY_DATA,
                                      NULL, 0, inqDataBuff, sizeof(inqDataBuff),
                                      &dummy, FALSE);
            if (success) {
                PSCSI_BUS_DATA pbd;
                PSCSI_INQUIRY_DATA pid;
                int num_lus, off, len;

                ai = (PSCSI_ADAPTER_BUS_INFO)inqDataBuff;
                for (bus = 0; bus < ai->NumberOfBusses; bus++) {
                    pbd = ai->BusData + bus;
                    num_lus = pbd->NumberOfLogicalUnits;
                    off = pbd->InquiryDataOffset;
                    for (j = 0; j < num_lus; ++j) {
                        if ((off < (int)sizeof(SCSI_ADAPTER_BUS_INFO)) ||
                            (off > ((int)sizeof(inqDataBuff) -
                                    (int)sizeof(SCSI_INQUIRY_DATA))))
                            break;
                        pid = (PSCSI_INQUIRY_DATA)(inqDataBuff + off);
                        m = next_unused_scsi_elem++;
                        if (next_unused_scsi_elem > MAX_SCSI_ELEMS) {
                            fprintf(stderr, "Too many scsi devices (more "
                                    "than %d)\n", MAX_SCSI_ELEMS);
                            return SG_LIB_CAT_OTHER;
                        }
                        next_elem_after_scsi_adapter_valid =
                                        next_unused_scsi_elem;
                        sep = w_scsi_arr + m;
                        sep->in_use = 1;
                        sep->scsi_adapter_valid = 1;
                        sep->port_num = k;
                        sep->bus = pid->PathId;
                        sep->target = pid->TargetId;
                        sep->lun = pid->Lun;
                        sep->device_claimed = pid->DeviceClaimed;
                        len = pid->InquiryDataLength;
                        len = (len > SCSI2_INQ_RESP_LEN) ?
                              SCSI2_INQ_RESP_LEN : len;
                        memcpy(sep->inq_resp, pid->InquiryData, len);
                        sep->pdt = sep->inq_resp[0] & 0x3f;
                        if (0 == sep->inq_resp[4])
                            sep->dubious_scsi = 1;

                        if (verbose > 1) {
                            fprintf(stderr, "%s: PathId=%d TargetId=%d "
                                    "Lun=%d ", adapter_name, pid->PathId,
                                    pid->TargetId, pid->Lun);
                            fprintf(stderr, "  DeviceClaimed=%d\n",
                                    pid->DeviceClaimed);
                            dStrHex((const char *)(pid->InquiryData),
                                    pid->InquiryDataLength, 0);
                        }
                        off = pid->NextInquiryDataOffset;
                    }
                }
            } else {
                err = GetLastError();
                fprintf(stderr, "%s: IOCTL_SCSI_GET_INQUIRY_DATA failed "
                        "err=%lu\n\t%s",
                        adapter_name, err, get_err_str(err, sizeof(b), b));
            }
            CloseHandle(fh);
        } else {
            if (verbose > 2) {
                err = GetLastError();
                fprintf(stderr, "%s: CreateFile failed err=%lu\n\t%s",
                        adapter_name, err, get_err_str(err, sizeof(b), b));
            }
            if (++hole_count >= MAX_HOLE_COUNT)
                break;
        }
    }

    for (k = 0; k < 24; ++k) {
        matched = 0;
        sep = NULL;
        snprintf(adapter_name, sizeof (adapter_name), "\\\\.\\%c:", 'C' + k);
        fh = CreateFile(adapter_name, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (fh != INVALID_HANDLE_VALUE) {
            success  = DeviceIoControl(fh, IOCTL_SCSI_GET_ADDRESS,
                                       NULL, 0, inqDataBuff,
                                       sizeof(inqDataBuff), &dummy, FALSE);
            if (success) {
                PSCSI_ADDRESS pa;

                pa = (PSCSI_ADDRESS)inqDataBuff;
                index = findElemIndex(pa->PortNumber, pa->PathId,
                                      pa->TargetId, pa->Lun);
                if (index >= 0) {
                    sep = w_scsi_arr + index;
                    matched = 1;
                } else {
                    m = next_unused_scsi_elem++;
                    if (next_unused_scsi_elem > MAX_SCSI_ELEMS) {
                        fprintf(stderr, "Too many scsi devices (more "
                                "than %d)\n", MAX_SCSI_ELEMS);
                        return SG_LIB_CAT_OTHER;
                    }
                    sep = w_scsi_arr + m;
                    sep->in_use = 1;
                    sep->port_num = pa->PortNumber;
                    sep->bus = pa->PathId;
                    sep->target = pa->TargetId;
                    sep->lun = pa->Lun;
                    sep->device_claimed = 1;
                }
                if (sep->volume_valid) {
                    sep->volume_multiple = 1;
                    if (('C' + k) == letter)
                        sep->volume_letter = letter;
                } else {
                    sep->volume_valid = 1;
                    sep->volume_letter = 'C' + k;
                }
                if (verbose > 1)
                    fprintf(stderr, "%c: PortNum=%d PathId=%d TargetId=%d "
                            "Lun=%d  index=%d\n", 'C' + k, pa->PortNumber,
                            pa->PathId, pa->TargetId, pa->Lun, index);
                if (matched) {
                    CloseHandle(fh);
                    continue;
                }
            } else {
                if (verbose > 1) {
                    err = GetLastError();
                    fprintf(stderr, "%c: IOCTL_SCSI_GET_ADDRESS err=%lu\n\t"
                            "%s", 'C' + k, err,
                            get_err_str(err, sizeof(b), b));
                }
            }
            if (fetchInquiry(fh, inqResp, sizeof(inqResp), &sptdw,
                             verbose)) {
                if (sptdw.spt.ScsiStatus) {
                    if (verbose) {
                        fprintf(stderr, "%c: INQUIRY failed:  ", 'C' + k);
                        sg_print_scsi_status(sptdw.spt.ScsiStatus);
                        sg_print_sense("    ", sptdw.ucSenseBuf,
                                       sizeof(sptdw.ucSenseBuf), 0);
                    }
                    CloseHandle(fh);
                    continue;
                }
                if (NULL == sep) {
                    m = next_unused_scsi_elem++;
                    if (next_unused_scsi_elem > MAX_SCSI_ELEMS) {
                        fprintf(stderr, "Too many scsi devices (more "
                                "than %d)\n", MAX_SCSI_ELEMS);
                        return SG_LIB_CAT_OTHER;
                    }
                    sep = w_scsi_arr + m;
                    sep->in_use = 1;
                    sep->device_claimed = 1;
                    sep->volume_valid = 1;
                    sep->volume_letter = 'C' + k;
                }
                memcpy(sep->inq_resp, inqResp, sizeof(sep->inq_resp));
                sep->pdt = sep->inq_resp[0] & 0x3f;
                if (0 == sep->inq_resp[4])
                    sep->dubious_scsi = 1;
            }
            CloseHandle(fh);
        }
    }

    hole_count = 0;
    for (k = 0; k < MAX_PHYSICALDRIVE_NUM; ++k) {
        matched = 0;
        sep = NULL;
        snprintf(adapter_name, sizeof (adapter_name),
                 "\\\\.\\PhysicalDrive%d", k);
        fh = CreateFile(adapter_name, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (fh != INVALID_HANDLE_VALUE) {
            hole_count = 0;
            success  = DeviceIoControl(fh, IOCTL_SCSI_GET_ADDRESS,
                                       NULL, 0, inqDataBuff,
                                       sizeof(inqDataBuff), &dummy, FALSE);
            if (success) {
                PSCSI_ADDRESS pa;

                pa = (PSCSI_ADDRESS)inqDataBuff;
                index = findElemIndex(pa->PortNumber, pa->PathId,
                                      pa->TargetId, pa->Lun);
                if (index >= 0) {
                    sep = w_scsi_arr + index;
                    matched = 1;
                } else {
                    m = next_unused_scsi_elem++;
                    if (next_unused_scsi_elem > MAX_SCSI_ELEMS) {
                        fprintf(stderr, "Too many scsi devices (more "
                                "than %d)\n", MAX_SCSI_ELEMS);
                        return SG_LIB_CAT_OTHER;
                    }
                    sep = w_scsi_arr + m;
                    sep->in_use = 1;
                    sep->port_num = pa->PortNumber;
                    sep->bus = pa->PathId;
                    sep->target = pa->TargetId;
                    sep->lun = pa->Lun;
                    sep->device_claimed = 1;
                }
                sep->physicaldrive_valid = 1;
                sep->physicaldrive_num = k;
                if (verbose > 1)
                    fprintf(stderr, "PD%d: PortNum=%d PathId=%d TargetId=%d "
                            "Lun=%d  index=%d\n", k, pa->PortNumber,
                            pa->PathId, pa->TargetId, pa->Lun, index);
                if (matched) {
                    CloseHandle(fh);
                    continue;
                }
            } else {
                if (verbose > 1) {
                    err = GetLastError();
                    fprintf(stderr, "PD%d: IOCTL_SCSI_GET_ADDRESS err=%lu\n\t"
                            "%s", k, err, get_err_str(err, sizeof(b), b));
                }
            }
            if (fetchInquiry(fh, inqResp, sizeof(inqResp), &sptdw,
                             verbose)) {
                if (sptdw.spt.ScsiStatus) {
                    if (verbose) {
                        fprintf(stderr, "PD%d: INQUIRY failed:  ", k);
                        sg_print_scsi_status(sptdw.spt.ScsiStatus);
                        sg_print_sense("    ", sptdw.ucSenseBuf,
                                       sizeof(sptdw.ucSenseBuf), 0);
                    }
                    CloseHandle(fh);
                    continue;
                }
                if (NULL == sep) {
                    m = next_unused_scsi_elem++;
                    if (next_unused_scsi_elem > MAX_SCSI_ELEMS) {
                        fprintf(stderr, "Too many scsi devices (more "
                                "than %d)\n", MAX_SCSI_ELEMS);
                        return SG_LIB_CAT_OTHER;
                    }
                    sep = w_scsi_arr + m;
                    sep->in_use = 1;
                    sep->device_claimed = 1;
                    sep->physicaldrive_valid = 1;
                    sep->physicaldrive_num = k;
                }
                memcpy(sep->inq_resp, inqResp, sizeof(sep->inq_resp));
                sep->pdt = sep->inq_resp[0] & 0x3f;
                if (0 == sep->inq_resp[4])
                    sep->dubious_scsi = 1;
            }
            CloseHandle(fh);
        } else {
            if (verbose > 2) {
                err = GetLastError();
                fprintf(stderr, "%s: CreateFile failed err=%lu\n\t%s",
                        adapter_name, err, get_err_str(err, sizeof(b), b));
            }
            if (++hole_count >= MAX_HOLE_COUNT)
                break;
        }
    }

    hole_count = 0;
    for (k = 0; k < MAX_CDROM_NUM; ++k) {
        matched = 0;
        sep = NULL;
        snprintf(adapter_name, sizeof (adapter_name), "\\\\.\\CDROM%d", k);
        fh = CreateFile(adapter_name, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (fh != INVALID_HANDLE_VALUE) {
            hole_count = 0;
            success  = DeviceIoControl(fh, IOCTL_SCSI_GET_ADDRESS,
                                       NULL, 0, inqDataBuff,
                                       sizeof(inqDataBuff), &dummy, FALSE);
            if (success) {
                PSCSI_ADDRESS pa;

                pa = (PSCSI_ADDRESS)inqDataBuff;
                index = findElemIndex(pa->PortNumber, pa->PathId,
                                      pa->TargetId, pa->Lun);
                if (index >= 0) {
                    sep = w_scsi_arr + index;
                    matched = 1;
                } else {
                    m = next_unused_scsi_elem++;
                    if (next_unused_scsi_elem > MAX_SCSI_ELEMS) {
                        fprintf(stderr, "Too many scsi devices (more "
                                "than %d)\n", MAX_SCSI_ELEMS);
                        return SG_LIB_CAT_OTHER;
                    }
                    sep = w_scsi_arr + m;
                    sep->in_use = 1;
                    sep->port_num = pa->PortNumber;
                    sep->bus = pa->PathId;
                    sep->target = pa->TargetId;
                    sep->lun = pa->Lun;
                    sep->device_claimed = 1;
                }
                sep->cdrom_valid = 1;
                sep->cdrom_num = k;
                if (verbose > 1)
                    fprintf(stderr, "CDROM%d: PortNum=%d PathId=%d TargetId=%d "
                            "Lun=%d  index=%d\n", k, pa->PortNumber,
                            pa->PathId, pa->TargetId, pa->Lun, index);
                if (matched) {
                    CloseHandle(fh);
                    continue;
                }
            } else {
                if (verbose > 1) {
                    err = GetLastError();
                    fprintf(stderr, "CDROM%d: IOCTL_SCSI_GET_ADDRESS "
                            "err=%lu\n\t%s", k, err,
                            get_err_str(err, sizeof(b), b));
                }
            }
            if (fetchInquiry(fh, inqResp, sizeof(inqResp), &sptdw,
                             verbose)) {
                if (sptdw.spt.ScsiStatus) {
                    if (verbose) {
                        fprintf(stderr, "CDROM%d: INQUIRY failed:  ", k);
                        sg_print_scsi_status(sptdw.spt.ScsiStatus);
                        sg_print_sense("    ", sptdw.ucSenseBuf,
                                       sizeof(sptdw.ucSenseBuf), 0);
                    }
                    CloseHandle(fh);
                    continue;
                }
                if (NULL == sep) {
                    m = next_unused_scsi_elem++;
                    if (next_unused_scsi_elem > MAX_SCSI_ELEMS) {
                        fprintf(stderr, "Too many scsi devices (more "
                                "than %d)\n", MAX_SCSI_ELEMS);
                        return SG_LIB_CAT_OTHER;
                    }
                    sep = w_scsi_arr + m;
                    sep->in_use = 1;
                    sep->device_claimed = 1;
                    sep->cdrom_valid = 1;
                    sep->cdrom_num = k;
                }
                memcpy(sep->inq_resp, inqResp, sizeof(sep->inq_resp));
                sep->pdt = sep->inq_resp[0] & 0x3f;
                if (0 == sep->inq_resp[4])
                    sep->dubious_scsi = 1;
            }
            CloseHandle(fh);
        } else {
            if (verbose > 3) {
                err = GetLastError();
                fprintf(stderr, "%s: CreateFile failed err=%lu\n\t%s",
                        adapter_name, err, get_err_str(err, sizeof(b), b));
            }
            if (++hole_count >= MAX_HOLE_COUNT)
                break;
        }
    }

    hole_count = 0;
    for (k = 0; k < MAX_TAPE_NUM; ++k) {
        matched = 0;
        sep = NULL;
        snprintf(adapter_name, sizeof (adapter_name), "\\\\.\\TAPE%d", k);
        fh = CreateFile(adapter_name, GENERIC_READ | GENERIC_WRITE,
                        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                        OPEN_EXISTING, 0, NULL);
        if (fh != INVALID_HANDLE_VALUE) {
            hole_count = 0;
            success  = DeviceIoControl(fh, IOCTL_SCSI_GET_ADDRESS,
                                       NULL, 0, inqDataBuff,
                                       sizeof(inqDataBuff), &dummy, FALSE);
            if (success) {
                PSCSI_ADDRESS pa;

                pa = (PSCSI_ADDRESS)inqDataBuff;
                index = findElemIndex(pa->PortNumber, pa->PathId,
                                      pa->TargetId, pa->Lun);
                if (index >= 0) {
                    sep = w_scsi_arr + index;
                    matched = 1;
                } else {
                    m = next_unused_scsi_elem++;
                    if (next_unused_scsi_elem > MAX_SCSI_ELEMS) {
                        fprintf(stderr, "Too many scsi devices (more "
                                "than %d)\n", MAX_SCSI_ELEMS);
                        return SG_LIB_CAT_OTHER;
                    }
                    sep = w_scsi_arr + m;
                    sep->in_use = 1;
                    sep->port_num = pa->PortNumber;
                    sep->bus = pa->PathId;
                    sep->target = pa->TargetId;
                    sep->lun = pa->Lun;
                    sep->device_claimed = 1;
                }
                sep->tape_valid = 1;
                sep->tape_num = k;
                if (verbose > 1)
                    fprintf(stderr, "TAPE%d: PortNum=%d PathId=%d TargetId=%d "
                            "Lun=%d  index=%d\n", k, pa->PortNumber,
                            pa->PathId, pa->TargetId, pa->Lun, index);
                if (matched) {
                    CloseHandle(fh);
                    continue;
                }
            } else {
                if (verbose > 1) {
                    err = GetLastError();
                    fprintf(stderr, "TAPE%d: IOCTL_SCSI_GET_ADDRESS "
                            "err=%lu\n\t%s", k, err,
                            get_err_str(err, sizeof(b), b));
                }
            }
            if (fetchInquiry(fh, inqResp, sizeof(inqResp), &sptdw,
                             verbose)) {
                if (sptdw.spt.ScsiStatus) {
                    if (verbose) {
                        fprintf(stderr, "TAPE%d: INQUIRY failed:  ", k);
                        sg_print_scsi_status(sptdw.spt.ScsiStatus);
                        sg_print_sense("    ", sptdw.ucSenseBuf,
                                       sizeof(sptdw.ucSenseBuf), 0);
                    }
                    CloseHandle(fh);
                    continue;
                }
                if (NULL == sep) {
                    m = next_unused_scsi_elem++;
                    if (next_unused_scsi_elem > MAX_SCSI_ELEMS) {
                        fprintf(stderr, "Too many scsi devices (more "
                                "than %d)\n", MAX_SCSI_ELEMS);
                        return SG_LIB_CAT_OTHER;
                    }
                    sep = w_scsi_arr + m;
                    sep->in_use = 1;
                    sep->device_claimed = 1;
                    sep->tape_valid = 1;
                    sep->tape_num = k;
                }
                memcpy(sep->inq_resp, inqResp, sizeof(sep->inq_resp));
                sep->pdt = sep->inq_resp[0] & 0x3f;
                if (0 == sep->inq_resp[4])
                    sep->dubious_scsi = 1;
            }
            CloseHandle(fh);
        } else {
            if (verbose > 4) {
                err = GetLastError();
                fprintf(stderr, "%s: CreateFile failed err=%lu\n\t%s",
                        adapter_name, err, get_err_str(err, sizeof(b), b));
            }
            if (++hole_count >= MAX_HOLE_COUNT)
                break;
        }
    }

    for (k = 0; k < MAX_SCSI_ELEMS; ++k) {
        sep = w_scsi_arr + k;
        if (0 == sep->in_use)
            break;
        if (sep->scsi_adapter_valid) {
            snprintf(b, sizeof(b), "SCSI%d:%d,%d,%d ", sep->port_num,
                     sep->bus, sep->target, sep->lun);
            printf("%-18s", b);
        } else
            printf("                  ");
        if (sep->volume_valid)
            printf("%c: %c  ", sep->volume_letter,
                   (sep->volume_multiple ? '+' : ' '));
        else
            printf("      ");
        if (sep->physicaldrive_valid) {
            snprintf(b, sizeof(b), "PD%d ", sep->physicaldrive_num);
            printf("%-9s", b);
        } else if (sep->cdrom_valid) {
            snprintf(b, sizeof(b), "CDROM%d ", sep->cdrom_num);
            printf("%-9s", b);
        } else if (sep->tape_valid) {
            snprintf(b, sizeof(b), "TAPE%d ", sep->tape_num);
            printf("%-9s", b);
        } else
            printf("         ");

        memcpy(b, sep->inq_resp + 8, SCSI2_INQ_RESP_LEN);
        for (j = 0; j < 28; ++j) {
            if ((b[j] < 0x20) || (b[j] > 0x7e))
                b[j] = ' ';
        }
        b[28] = '\0';
        printf("%-30s", b);
        if (sep->dubious_scsi)
            printf("*     ");
        else if ((! sep->physicaldrive_valid) && (! sep->cdrom_valid) &&
                 (! sep->tape_valid))
            printf("pdt=%-2d", sep->pdt);
        else
            printf("      ");

        printf("\n");
    }
    return 0;
}


int main(int argc, char * argv[])
{
    int c, ret;
    int verbose = 0;
    int vol_letter = 0;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHl:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            vol_letter = toupper(optarg[0]);
            if ((vol_letter < 'C') || (vol_letter > 'Z')) {
                fprintf(stderr, "'--letter=' expects a letter in the "
                        "'C' to 'Z' range\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised option code 0x%x ??\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    w_scsi_arr = malloc(sizeof(struct w_scsi_elem) * MAX_SCSI_ELEMS);

    ret = sg_do_wscan(vol_letter, verbose);

    free(w_scsi_arr);
    return ret;
}

#endif

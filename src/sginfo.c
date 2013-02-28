/* * This program reads various mode pages and bits of other
 * information from a scsi device and interprets the raw data for you
 * with a report written to stdout.  Usage:
 *
 * ./sginfo [options] /dev/sg2 [replace parameters]
 *
 * Options are:
 * -6    do 6 byte mode sense + select (deafult: 10 byte)
 * -a    display all mode pages reported by the device: equivalent to '-t 63'.
 * -A    display all mode pages and subpages reported by the device: equivalent
 *       to '-t 63,255'.
 * -c    access Cache control page.
 * -C    access Control Page.
 * -d    display defect lists (default format: index).
 * -D    access disconnect-reconnect page.
 * -e    access Read-Write error recovery page.
 * -E    access Control Extension page.
 * -f    access Format Device Page.
 * -Farg defect list format (-Flogical, -flba64, -Fphysical, -Findex, -Fhead)
 * -g    access rigid disk geometry page.
 * -G    display only "grown" defect list (default format: index)
 * -i    display information from Inquiry command.
 * -I    access Informational Exceptions page.
 * -l    list known scsi devices on the system
 * -n    access notch parameters page.
 * -N    Negate (stop) storing to saved page (active with -R)
 * -P    access Power Condition Page.
 * -r    list known raw scsi devices on the system
 * -s    display serial number (from INQUIRY VPD page)
 * -t <n[,spn]> access page number <n> [and subpage <spn>], try to decode
 * -u <n[,spn]> access page number <n> [and subpage <spn>], output in hex
 * -v    show this program's version number
 * -V    access Verify Error Recovery Page.
 * -T    trace commands (for debugging, double for more debug)
 * -z    do a single fetch for mode pages (rather than double fetch)
 *
 * Only one of the following three options can be specified.
 * None of these three implies the current values are returned.
 * -m    Display modifiable fields instead of current values
 * -M    Display manufacturer defaults instead of current values
 * -S    Display saved defaults instead of current values
 *
 * -X    Display output values in a list.
 * -R    Replace parameters - best used with -X
 *
 * Eric Youngdale - 11/1/93.  Version 1.0.
 *
 * Version 1.1: Ability to change parameters on cache page, support for
 *  X front end.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2, or (at your option)
 *   any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Michael Weller (eowmob at exp-math dot uni-essen dot de)
 *      11/23/94 massive extensions from 1.4a
 *      08/23/97 fix problems with defect lists
 *
 * Douglas Gilbert (dgilbert at interlog dot com)
 *      990628   port to sg .... (version 1.81)
 *               up 4KB limit on defect list to 32KB
 *               'sginfo -l' also shows sg devices and mapping to other
 *                    scsi devices
 *               'sginfo' commands can take either an sd, sr (scd), st
 *                    or an sg device (all non-sg devices converted to a
 *                    sg device)
 *
 *      001208   Add Kurt Garloff's "-uno" flag for displaying info
 *               from a page number. <garloff at suse dot de> [version 1.90]
 *
 * Kurt Garloff <garloff at suse dot de>
 *    20000715  allow displaying and modification of vendor specific pages
 *                      (unformatted - @ hexdatafield)
 *              accept vendor lengths for those pages
 *              enabled page saving
 *              cleaned parameter parsing a bit (it's still a terrible mess!)
 *              Use sr (instead of scd) and sg%d (instead of sga,b,...) in -l
 *                      and support much more devs in -l (incl. nosst)
 *              Fix segfault in defect list (len=0xffff) and adapt formatting
 *                      to large disks. Support up to 256kB defect lists with
 *                      0xB7 (12byte) command if necessary and fallback to 0x37
 *                      (10byte) in case of failure. Report truncation.
 *              sizeof(buffer) (which is sizeof(char*) == 4 or 32 bit archs)
 *                      was used incorrectly all over the place. Fixed.
 *                                      [version 1.95]
 * Douglas Gilbert (dgilbert at interlog dot com)
 *    20020113  snprintf() type cleanup [version 1.96]
 *    20021211  correct sginfo MODE_SELECT, protect against block devices
 *              that answer sg's ioctls. [version 1.97]
 *    20021228  scan for some "scd<n>" as well as "sr<n>" device names [1.98]
 *    20021020  Update control page [1.99]
 *
 * Thomas Steudten (thomas at steudten dot com)
 *    20040521  add -Fhead feature [version 2.04]
 *
 * Tim Hunt (tim at timhunt dot net)
 *    20050427  increase number of mapped SCSI disks devices
 *
 * Dave Johnson (djj at ccv dot brown dot edu)
 *    20051218  improve disk defect list handling
 */


/*
 * N.B. This utility is in maintenance mode only. This means that serious
 * bugs will be fixed but no new features or mode page changes will be
 * added. Please use the sdparm utility.     D. Gilbert 20090316
 */

#define _XOPEN_SOURCE 500
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

static const char * version_str = "2.32 [20130228]";

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <ctype.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_io_linux.h"


static int glob_fd;
static char *device_name;

#define MAX_SG_DEVS 8192
#define MAX_RESP6_SIZE 252
#define MAX_RESP10_SIZE (4*1024)
#define MAX_BUFFER_SIZE MAX_RESP10_SIZE

#define INQUIRY_RESP_INITIAL_LEN 36

#define MAX_HEADS 127
#define HEAD_SORT_TOKEN 0x55

#define SIZEOF_BUFFER (16*1024)
#define SIZEOF_BUFFER1 (16*1024)
static unsigned char cbuffer[SIZEOF_BUFFER];
static unsigned char cbuffer1[SIZEOF_BUFFER1];
static unsigned char cbuffer2[SIZEOF_BUFFER1];

static char defect = 0;
static char defectformat = 0x4;
static char grown_defect = 0;
static char negate_sp_bit = 0;
static char replace = 0;
static char serial_number = 0;
static char x_interface = 0;
static char single_fetch = 0;

static char mode6byte = 0;      /* defaults to 10 byte mode sense + select */
static char trace_cmd = 0;

struct mpage_info {
    int page;
    int subpage;
    int page_control;
    int peri_type;
    int inq_byte6;      /* EncServ and MChngr bits of interest */
    int resp_len;
};

/* declarations of functions decoding known mode pages */
static int common_disconnect_reconnect(struct mpage_info * mpi,
                                       const char * prefix);
static int common_control(struct mpage_info * mpi, const char * prefix);
static int common_control_extension(struct mpage_info * mpi,
                                    const char * prefix);
static int common_proto_spec_lu(struct mpage_info * mpi, const char * prefix);
static int common_proto_spec_port(struct mpage_info * mpi,
                                  const char * prefix);
static int common_proto_spec_port_sp1(struct mpage_info * mpi,
                                      const char * prefix);
static int common_proto_spec_port_sp2(struct mpage_info * mpi,
                                      const char * prefix);
static int common_power_condition(struct mpage_info * mpi,
                                  const char * prefix);
static int common_informational(struct mpage_info * mpi, const char * prefix);
static int disk_error_recovery(struct mpage_info * mpi, const char * prefix);
static int disk_format(struct mpage_info * mpi, const char * prefix);
static int disk_verify_error_recovery(struct mpage_info * mpi,
                                      const char * prefix);
static int disk_geometry(struct mpage_info * mpi, const char * prefix);
static int disk_notch_parameters(struct mpage_info * mpi, const char * prefix);
static int disk_cache(struct mpage_info * mpi, const char * prefix);
static int disk_xor_control(struct mpage_info * mpi, const char * prefix);
static int disk_background(struct mpage_info * mpi, const char * prefix);
static int optical_memory(struct mpage_info * mpi, const char * prefix);
static int cdvd_error_recovery(struct mpage_info * mpi, const char * prefix);
static int cdvd_mrw(struct mpage_info * mpi, const char * prefix);
static int cdvd_write_param(struct mpage_info * mpi, const char * prefix);
static int cdvd_audio_control(struct mpage_info * mpi, const char * prefix);
static int cdvd_timeout(struct mpage_info * mpi, const char * prefix);
static int cdvd_device_param(struct mpage_info * mpi, const char * prefix);
static int cdvd_cache(struct mpage_info * mpi, const char * prefix);
static int cdvd_mm_capab(struct mpage_info * mpi, const char * prefix);
static int cdvd_feature(struct mpage_info * mpi, const char * prefix);
static int tape_data_compression(struct mpage_info * mpi, const char * prefix);
static int tape_dev_config(struct mpage_info * mpi, const char * prefix);
static int tape_medium_part1(struct mpage_info * mpi, const char * prefix);
static int tape_medium_part2_4(struct mpage_info * mpi, const char * prefix);
static int ses_services_manag(struct mpage_info * mpi, const char * prefix);
static int spi4_training_config(struct mpage_info * mpi, const char * prefix);
static int spi4_negotiated(struct mpage_info * mpi, const char * prefix);
static int spi4_report_xfer(struct mpage_info * mpi, const char * prefix);

enum page_class {PC_COMMON, PC_DISK, PC_TAPE, PC_CDVD, PC_SES, PC_SMC};

struct mpage_name_func {
    int page;
    int subpage;
    enum page_class pg_class;
    char * name;
    int (*func)(struct mpage_info *, const char *);
};

#define MP_LIST_PAGES 0x3f
#define MP_LIST_SUBPAGES 0xff

static struct mpage_name_func mpage_common[] =
{
    { 0, 0, PC_COMMON, "Vendor (non-page format)", NULL},
    { 2, 0, PC_COMMON, "Disconnect-Reconnect", common_disconnect_reconnect},
    { 9, 0, PC_COMMON, "Peripheral device (obsolete)", NULL},
    { 0xa, 0, PC_COMMON, "Control", common_control},
    { 0xa, 1, PC_COMMON, "Control Extension", common_control_extension},
    { 0x15, 0, PC_COMMON, "Extended", NULL},
    { 0x16, 0, PC_COMMON, "Extended, device-type specific", NULL},
    { 0x18, 0, PC_COMMON, "Protocol specific lu", common_proto_spec_lu},
    { 0x19, 0, PC_COMMON, "Protocol specific port", common_proto_spec_port},
    { 0x19, 1, PC_COMMON, "Protocol specific port, subpage 1 overload",
      common_proto_spec_port_sp1},
    { 0x19, 2, PC_COMMON, "Protocol specific port, subpage 2 overload",
      common_proto_spec_port_sp2},
/*    { 0x19, 2, PC_COMMON, "SPI-4 Saved Training configuration",
        spi4_training_config}, */
    { 0x19, 3, PC_COMMON, "SPI-4 Negotiated Settings", spi4_negotiated},
    { 0x19, 4, PC_COMMON, "SPI-4 Report transfer capabilities",
      spi4_report_xfer},
    { 0x1a, 0, PC_COMMON, "Power Condition", common_power_condition},
    { 0x1c, 0, PC_COMMON, "Informational Exceptions", common_informational},
    { MP_LIST_PAGES, 0, PC_COMMON, "Return all pages", NULL},
};
static const int mpage_common_len = sizeof(mpage_common) /
                                    sizeof(mpage_common[0]);

static struct mpage_name_func mpage_disk[] =
{
    { 1, 0, PC_DISK, "Read-Write Error Recovery", disk_error_recovery},
    { 3, 0, PC_DISK, "Format Device", disk_format},
    { 4, 0, PC_DISK, "Rigid Disk Geometry", disk_geometry},
    { 5, 0, PC_DISK, "Flexible Disk", NULL},
    { 6, 0, PC_DISK, "Optical memory", optical_memory},
    { 7, 0, PC_DISK, "Verify Error Recovery", disk_verify_error_recovery},
    { 8, 0, PC_DISK, "Caching", disk_cache},
    { 0xa, 0xf1, PC_DISK, "Parallel ATA control (SAT)", NULL},
    { 0xb, 0, PC_DISK, "Medium Types Supported", NULL},
    { 0xc, 0, PC_DISK, "Notch and Partition", disk_notch_parameters},
    { 0x10, 0, PC_DISK, "XOR control", disk_xor_control},
    { 0x1c, 1, PC_DISK, "Background control", disk_background},
};
static const int mpage_disk_len = sizeof(mpage_disk) / sizeof(mpage_disk[0]);

static struct mpage_name_func mpage_cdvd[] =
{
    { 1, 0, PC_CDVD, "Read-Write Error Recovery (cdvd)",
      cdvd_error_recovery},
    { 3, 0, PC_CDVD, "MRW", cdvd_mrw},
    { 5, 0, PC_CDVD, "Write parameters", cdvd_write_param},
    { 8, 0, PC_CDVD, "Caching", cdvd_cache},
    { 0xd, 0, PC_CDVD, "CD device parameters", cdvd_device_param},
    { 0xe, 0, PC_CDVD, "CD audio control", cdvd_audio_control},
    { 0x18, 0, PC_CDVD, "Feature set support & version", cdvd_feature},
    { 0x1a, 0, PC_CDVD, "Power Condition", common_power_condition},
    { 0x1c, 0, PC_CDVD, "Fault/failure reporting control",
      common_informational},
    { 0x1d, 0, PC_CDVD, "Time-out & protect", cdvd_timeout},
    { 0x2a, 0, PC_CDVD, "MM capabilities & mechanical status", cdvd_mm_capab},
};
static const int mpage_cdvd_len = sizeof(mpage_cdvd) / sizeof(mpage_cdvd[0]);

static struct mpage_name_func mpage_tape[] =
{
    { 1, 0, PC_TAPE, "Read-Write Error Recovery", disk_error_recovery},
    { 0xf, 0, PC_TAPE, "Data compression", tape_data_compression},
    { 0x10, 0, PC_TAPE, "Device configuration", tape_dev_config},
    { 0x10, 1, PC_TAPE, "Device configuration extension", NULL},
    { 0x11, 0, PC_TAPE, "Medium partition(1)", tape_medium_part1},
    { 0x12, 0, PC_TAPE, "Medium partition(2)", tape_medium_part2_4},
    { 0x13, 0, PC_TAPE, "Medium partition(3)", tape_medium_part2_4},
    { 0x14, 0, PC_TAPE, "Medium partition(4)", tape_medium_part2_4},
    { 0x1c, 0, PC_TAPE, "Informational Exceptions", common_informational},
    { 0x1d, 0, PC_TAPE, "Medium configuration", NULL},
};
static const int mpage_tape_len = sizeof(mpage_tape) / sizeof(mpage_tape[0]);

static struct mpage_name_func mpage_ses[] =
{
    { 0x14, 0, PC_SES, "Enclosure services management", ses_services_manag},
};
static const int mpage_ses_len = sizeof(mpage_ses) / sizeof(mpage_ses[0]);

static struct mpage_name_func mpage_smc[] =
{
    { 0x1d, 0, PC_SMC, "Element address assignment", NULL},
    { 0x1e, 0, PC_SMC, "Transport geometry parameters", NULL},
    { 0x1f, 0, PC_SMC, "Device capabilities", NULL},
    { 0x1f, 1, PC_SMC, "Extended device capabilities", NULL},
};
static const int mpage_smc_len = sizeof(mpage_smc) / sizeof(mpage_smc[0]);


#define MAXPARM 64

static int next_parameter;
static int n_replacement_values;
static uint64_t replacement_values[MAXPARM];
static char is_hex[MAXPARM];

#define SMODE_SENSE 0x1a
#define SMODE_SENSE_10 0x5a
#define SMODE_SELECT 0x15
#define SMODE_SELECT_10 0x55

#define MPHEADER6_LEN 4
#define MPHEADER10_LEN 8


/* forward declarations */
static void usage(char *);
static void dump(void *buffer, unsigned int length);

#define DXFER_NONE        0
#define DXFER_FROM_DEVICE 1
#define DXFER_TO_DEVICE   2


struct scsi_cmnd_io
{
    unsigned char * cmnd;       /* ptr to SCSI command block (cdb) */
    size_t  cmnd_len;           /* number of bytes in SCSI command */
    int dxfer_dir;              /* DXFER_NONE, DXFER_FROM_DEVICE, or
                                   DXFER_TO_DEVICE */
    unsigned char * dxferp;     /* ptr to outgoing/incoming data */
    size_t dxfer_len;           /* bytes to be transferred to/from dxferp */
};

#define SENSE_BUFF_LEN   32
#define CMD_TIMEOUT   60000 /* 60,000 milliseconds (60 seconds) */
#define EBUFF_SZ   256


#define GENERAL_ERROR           1
#define UNKNOWN_OPCODE          2
#define BAD_CDB_FIELD           3
#define UNSUPPORTED_PARAM       4
#define DEVICE_ATTENTION        5
#define DEVICE_NOT_READY        6

#define DECODE_FAILED_TRY_HEX   9999

/* Returns 0 -> ok, 1 -> general error, 2 -> unknown opcode,
   3 -> unsupported field in cdb, 4 -> unsupported param in data-in */
static int
do_scsi_io(struct scsi_cmnd_io * sio)
{
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    struct sg_scsi_sense_hdr ssh;
    int res;

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sio->cmnd_len;
    io_hdr.mx_sb_len = sizeof(sense_b);
    if (DXFER_NONE == sio->dxfer_dir)
        io_hdr.dxfer_direction = SG_DXFER_NONE;
    else
        io_hdr.dxfer_direction = (DXFER_TO_DEVICE == sio->dxfer_dir) ?
                                SG_DXFER_TO_DEV : SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = sio->dxfer_len;
    io_hdr.dxferp = sio->dxferp;
    io_hdr.cmdp = sio->cmnd;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = CMD_TIMEOUT;

    if (trace_cmd) {
        printf("  cdb:");
        dump(sio->cmnd, sio->cmnd_len);
    }
    if ((trace_cmd > 1) && (DXFER_TO_DEVICE == sio->dxfer_dir)) {
        printf("  additional data:\n");
        dump(sio->dxferp, sio->dxfer_len);
    }

    if (ioctl(glob_fd, SG_IO, &io_hdr) < 0) {
        perror("do_scsi_cmd: SG_IO error");
        return GENERAL_ERROR;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("do_scsi_cmd, continuing", &io_hdr, 1);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        return 0;
    default:
        if (trace_cmd) {
            char ebuff[EBUFF_SZ];

            snprintf(ebuff, EBUFF_SZ, "do_scsi_io: opcode=0x%x", sio->cmnd[0]);
            sg_chk_n_print3(ebuff, &io_hdr, 1);
        }
        if (sg_normalize_sense(&io_hdr, &ssh)) {
            if (ILLEGAL_REQUEST == ssh.sense_key) {
                if (0x20 == ssh.asc)
                    return UNKNOWN_OPCODE;
                else if (0x24 == ssh.asc)
                    return BAD_CDB_FIELD;
                else if (0x26 == ssh.asc)
                    return UNSUPPORTED_PARAM;
            } else if (UNIT_ATTENTION == ssh.sense_key)
                return DEVICE_ATTENTION;
            else if (NOT_READY == ssh.sense_key)
                return DEVICE_NOT_READY;
        }
        return GENERAL_ERROR;
    }
}

struct mpage_name_func * get_mpage_info(int page_no, int subpage_no,
                                    struct mpage_name_func * mpp, int elems)
{
    int k;

    for (k = 0; k < elems; ++k, ++mpp) {
        if ((mpp->page == page_no) && (mpp->subpage == subpage_no))
            return mpp;
        if (mpp->page > page_no)
            break;
    }
    return NULL;
}

enum page_class get_page_class(struct mpage_info * mpi)
{
    switch (mpi->peri_type)
    {
    case 0:
    case 4:
    case 7:
    case 0xe:   /* should be RBC */
        return PC_DISK;
    case 1:
    case 2:
        return PC_TAPE;
    case 8:
        return PC_SMC;
    case 5:
        return PC_CDVD;
    case 0xd:
        return PC_SES;
    default:
        return PC_COMMON;
    }
}

struct mpage_name_func * get_mpage_name_func(struct mpage_info * mpi)
{
    struct mpage_name_func * mpf = NULL;

    switch (get_page_class(mpi))
    {
    case PC_DISK:
        mpf = get_mpage_info(mpi->page, mpi->subpage, mpage_disk,
                             mpage_disk_len);
        break;
    case PC_CDVD:
        mpf = get_mpage_info(mpi->page, mpi->subpage, mpage_cdvd,
                             mpage_cdvd_len);
        break;
    case PC_TAPE:
        mpf = get_mpage_info(mpi->page, mpi->subpage, mpage_tape,
                             mpage_tape_len);
        break;
    case PC_SES:
        mpf = get_mpage_info(mpi->page, mpi->subpage, mpage_ses,
                             mpage_ses_len);
        break;
    case PC_SMC:
        mpf = get_mpage_info(mpi->page, mpi->subpage, mpage_smc,
                             mpage_smc_len);
        break;
    case PC_COMMON:
        /* picked up it catch all next */
        break;
    }
    if (NULL == mpf) {
        if ((PC_SES != get_page_class(mpi)) && (mpi->inq_byte6 & 0x40)) {
            /* check for attached enclosure services processor */
            mpf = get_mpage_info(mpi->page, mpi->subpage, mpage_ses,
                                 mpage_ses_len);
        }
        if ((PC_SMC != get_page_class(mpi)) && (mpi->inq_byte6 & 0x8)) {
            /* check for attached medium changer device */
            mpf = get_mpage_info(mpi->page, mpi->subpage, mpage_smc,
                                 mpage_smc_len);
        }
    }
    if (NULL == mpf)
        mpf = get_mpage_info(mpi->page, mpi->subpage, mpage_common,
                             mpage_common_len);
    return mpf;
}


static char unkn_page_str[64];

static char *
get_page_name(struct mpage_info * mpi)
{
    struct mpage_name_func * mpf;

    if (MP_LIST_PAGES == mpi->page) {
        if (MP_LIST_SUBPAGES == mpi->subpage)
            return "List supported pages and subpages";
        else
            return "List supported pages";
    }
    mpf = get_mpage_name_func(mpi);
    if ((NULL == mpf) || (NULL == mpf->name)) {
        if (mpi->subpage)
            snprintf(unkn_page_str, sizeof(unkn_page_str),
                     "page number=0x%x, subpage number=0x%x",
                     mpi->page, mpi->subpage);
        else
            snprintf(unkn_page_str, sizeof(unkn_page_str),
                     "page number=0x%x", mpi->page);
        return unkn_page_str;
    }
    return mpf->name;
}

static void
dump(void *buffer, unsigned int length)
{
    unsigned int i;

    printf("    ");
    for (i = 0; i < length; i++) {
#if 0
        if (((unsigned char *) buffer)[i] > 0x20)
            printf(" %c ", (unsigned int) ((unsigned char *) buffer)[i]);
        else
#endif
            printf("%02x ", (unsigned int) ((unsigned char *) buffer)[i]);
        if ((i % 16 == 15) && (i < (length - 1))) {
            printf("\n    ");
        }
    }
    printf("\n");

}

static int
getnbyte(const unsigned char *pnt, int nbyte)
{
    unsigned int result;
    int i;

    if (nbyte > 4)
        fprintf(stderr, "getnbyte() limited to 32 bits, nbyte=%d\n", nbyte);
    result = 0;
    for (i = 0; i < nbyte; i++)
        result = (result << 8) | (pnt[i] & 0xff);
    return result;
}

static int64_t
getnbyte_ll(const unsigned char *pnt, int nbyte)
{
    int64_t result;
    int i;

    if (nbyte > 8)
        fprintf(stderr, "getnbyte_ll() limited to 64 bits, nbyte=%d\n",
                nbyte);
    result = 0;
    for (i = 0; i < nbyte; i++)
        result = (result << 8) + (pnt[i] & 0xff);
    return result;
}

static int
putnbyte(unsigned char *pnt, unsigned int value,
                    unsigned int nbyte)
{
    int i;

    for (i = nbyte - 1; i >= 0; i--) {
        pnt[i] = value & 0xff;
        value = value >> 8;
    }
    return 0;
}

#define REASON_SZ 128

static void
check_parm_type(int i)
{
    char reason[REASON_SZ];

    if (i == 1 && is_hex[next_parameter] != 1) {
        snprintf(reason, REASON_SZ,
                 "simple number (pos %i) instead of @ hexdatafield: %"PRIu64,
                 next_parameter, replacement_values[next_parameter]);
        usage (reason);
    }
    if (i != 1 && is_hex[next_parameter]) {
        snprintf(reason, REASON_SZ,
                 "@ hexdatafield (pos %i) instead of a simple number: %"PRIu64,
                 next_parameter, replacement_values[next_parameter]);
        usage (reason);
    }
}

static void
bitfield(unsigned char *pageaddr, char * text, int mask, int shift)
{
    if (x_interface && replace) {
        check_parm_type(0);
        *pageaddr = (*pageaddr & ~(mask << shift)) |
            ((replacement_values[next_parameter++] & mask) << shift);
    } else if (x_interface)
        printf("%d ", (*pageaddr >> shift) & mask);
    else
        printf("%-35s%d\n", text, (*pageaddr >> shift) & mask);
}

#if 0
static void
notbitfield(unsigned char *pageaddr, char * text, int mask,
                        int shift)
{
    if (modifiable) {
        bitfield(pageaddr, text, mask, shift);
        return;
    }
    if (x_interface && replace) {
        check_parm_type(0);
        *pageaddr = (*pageaddr & ~(mask << shift)) |
            (((!replacement_values[next_parameter++]) & mask) << shift);
    } else if (x_interface)
        printf("%d ", !((*pageaddr >> shift) & mask));
    else
        printf("%-35s%d\n", text, !((*pageaddr >> shift) & mask));
}
#endif

static void
intfield(unsigned char * pageaddr, int nbytes, char * text)
{
    if (x_interface && replace) {
        check_parm_type(0);
        putnbyte(pageaddr, replacement_values[next_parameter++], nbytes);
    } else if (x_interface)
        printf("%d ", getnbyte(pageaddr, nbytes));
    else
        printf("%-35s%d\n", text, getnbyte(pageaddr, nbytes));
}

static void
hexfield(unsigned char * pageaddr, int nbytes, char * text)
{
    if (x_interface && replace) {
        check_parm_type(0);
        putnbyte(pageaddr, replacement_values[next_parameter++], nbytes);
    } else if (x_interface)
        printf("%d ", getnbyte(pageaddr, nbytes));
    else
        printf("%-35s0x%x\n", text, getnbyte(pageaddr, nbytes));
}

static void
hexdatafield(unsigned char * pageaddr, int nbytes, char * text)
{
    if (x_interface && replace) {
        unsigned char *ptr;
        unsigned tmp;

        /* Though in main we ensured that a @string has the right format,
           we have to check that we are working on a @ hexdata field */

        check_parm_type(1);

        ptr = (unsigned char *) (unsigned long)
              (replacement_values[next_parameter++]);
        ptr++;                  /* Skip @ */

        while (*ptr) {
            if (!nbytes)
                goto illegal;
            tmp = (*ptr >= 'a') ? (*ptr - 'a' + 'A') : *ptr;
            tmp -= (tmp >= 'A') ? 'A' - 10 : '0';

            *pageaddr = tmp << 4;
            ptr++;

            tmp = (*ptr >= 'a') ? (*ptr - 'a' + 'A') : *ptr;
            tmp -= (tmp >= 'A') ? 'A' - 10 : '0';

            *pageaddr++ += tmp;
            ptr++;
            nbytes--;
        }

        if (nbytes) {
          illegal:
            fputs("sginfo: incorrect number of bytes in @hexdatafield.\n",
                  stdout);
            exit(2);
        }
    } else if (x_interface) {
        putchar('@');
        while (nbytes-- > 0)
            printf("%02x", *pageaddr++);
        putchar(' ');
    } else {
        printf("%-35s0x", text);
        while (nbytes-- > 0)
            printf("%02x", *pageaddr++);
        putchar('\n');
    }
}


/* Offset into mode sense (6 or 10 byte) response that actual mode page
 * starts at (relative to resp[0]). Returns -1 if problem */
static int
modePageOffset(const unsigned char * resp, int len, int modese_6)
{
    int bd_len;
    int resp_len = 0;
    int offset = -1;

    if (resp) {
        if (modese_6) {
            resp_len = resp[0] + 1;
            bd_len = resp[3];
            offset = bd_len + MPHEADER6_LEN;
        } else {
            resp_len = (resp[0] << 8) + resp[1] + 2;
            bd_len = (resp[6] << 8) + resp[7];
            /* LongLBA doesn't change this calculation */
            offset = bd_len + MPHEADER10_LEN;
        }
        if ((offset + 2) > len) {
            printf("modePageOffset: raw_curr too small, offset=%d "
                   "resp_len=%d bd_len=%d\n", offset, resp_len, bd_len);
            offset = -1;
        } else if ((offset + 2) > resp_len) {
            printf("modePageOffset: response length too short, resp_len=%d"
                   " offset=%d bd_len=%d\n", resp_len, offset, bd_len);
            offset = -1;
        }
    }
    return offset;
}

/* Reads mode (sub-)page via 6 byte MODE SENSE, returns 0 if ok */
static int
get_mode_page6(struct mpage_info * mpi, int dbd, unsigned char * resp,
               int sngl_fetch)
{
    int status, off;
    unsigned char cmd[6];
    struct scsi_cmnd_io sci;
    int initial_len = (sngl_fetch ? MAX_RESP6_SIZE : 4);

    memset(resp, 0, 4);
    cmd[0] = SMODE_SENSE;       /* MODE SENSE (6) */
    cmd[1] = 0x00 | (dbd ? 0x8 : 0); /* disable block descriptors bit */
    cmd[2] = (mpi->page_control << 6) | mpi->page;
    cmd[3] = mpi->subpage;      /* subpage code */
    cmd[4] = initial_len;
    cmd[5] = 0x00;              /* control */

    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_FROM_DEVICE;
    sci.dxfer_len = initial_len;
    sci.dxferp = resp;
    status = do_scsi_io(&sci);
    if (status) {
        if (mpi->subpage)
            fprintf(stdout, ">>> Unable to read %s mode page 0x%x, subpage "
                    "0x%x [mode_sense_6]\n", get_page_name(mpi), mpi->page,
                    mpi->subpage);
        else
            fprintf(stdout, ">>> Unable to read %s mode page (0x%x) "
                    "[mode_sense_6]\n", get_page_name(mpi), mpi->page);
        return status;
    }
    mpi->resp_len = resp[0] + 1;
    if (sngl_fetch) {
        if (trace_cmd > 1) {
            off = modePageOffset(resp, mpi->resp_len, 1);
            if (off >= 0) {
                printf("  cdb response:\n");
                dump(resp, mpi->resp_len);
            }
        }
        return status;
    }

    cmd[4] = mpi->resp_len;
    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_FROM_DEVICE;
    sci.dxfer_len = mpi->resp_len;
    sci.dxferp = resp;
    status = do_scsi_io(&sci);
    if (status) {
        if (mpi->subpage)
            fprintf(stdout, ">>> Unable to read %s mode page 0x%x, subpage "
                    "0x%x [mode_sense_6]\n", get_page_name(mpi), mpi->page,
                    mpi->subpage);
        else
            fprintf(stdout, ">>> Unable to read %s mode page (0x%x) "
                    "[mode_sense_6]\n", get_page_name(mpi), mpi->page);
    } else if (trace_cmd > 1) {
        off = modePageOffset(resp, mpi->resp_len, 1);
        if (off >= 0) {
            printf("  cdb response:\n");
            dump(resp, mpi->resp_len);
        }
    }
    return status;
}

/* Reads mode (sub-)page via 10 byte MODE SENSE, returns 0 if ok */
static int
get_mode_page10(struct mpage_info * mpi, int llbaa, int dbd,
                unsigned char * resp, int sngl_fetch)
{
    int status, off;
    unsigned char cmd[10];
    struct scsi_cmnd_io sci;
    int initial_len = (sngl_fetch ? MAX_RESP10_SIZE : 4);

    memset(resp, 0, 4);
    cmd[0] = SMODE_SENSE_10;     /* MODE SENSE (10) */
    cmd[1] = 0x00 | (llbaa ? 0x10 : 0) | (dbd ? 0x8 : 0);
    cmd[2] = (mpi->page_control << 6) | mpi->page;
    cmd[3] = mpi->subpage;
    cmd[4] = 0x00;              /* (reserved) */
    cmd[5] = 0x00;              /* (reserved) */
    cmd[6] = 0x00;              /* (reserved) */
    cmd[7] = (initial_len >> 8) & 0xff;
    cmd[8] = initial_len & 0xff;
    cmd[9] = 0x00;              /* control */

    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_FROM_DEVICE;
    sci.dxfer_len = initial_len;
    sci.dxferp = resp;
    status = do_scsi_io(&sci);
    if (status) {
        if (mpi->subpage)
            fprintf(stdout, ">>> Unable to read %s mode page 0x%x, subpage "
                    "0x%x [mode_sense_10]\n", get_page_name(mpi), mpi->page,
                    mpi->subpage);
        else
            fprintf(stdout, ">>> Unable to read %s mode page (0x%x) "
                    "[mode_sense_10]\n", get_page_name(mpi), mpi->page);
            return status;
    }
    mpi->resp_len = (resp[0] << 8) + resp[1] + 2;
    if (sngl_fetch) {
        if (trace_cmd > 1) {
            off = modePageOffset(resp, mpi->resp_len, 0);
            if (off >= 0) {
                printf("  cdb response:\n");
                dump(resp, mpi->resp_len);
            }
        }
        return status;
    }

    cmd[7] = (mpi->resp_len >> 8) & 0xff;
    cmd[8] = (mpi->resp_len & 0xff);
    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_FROM_DEVICE;
    sci.dxfer_len = mpi->resp_len;
    sci.dxferp = resp;
    status = do_scsi_io(&sci);
    if (status) {
        if (mpi->subpage)
            fprintf(stdout, ">>> Unable to read %s mode page 0x%x, subpage "
                    "0x%x [mode_sense_10]\n", get_page_name(mpi), mpi->page,
                    mpi->subpage);
        else
            fprintf(stdout, ">>> Unable to read %s mode page (0x%x) "
                    "[mode_sense_10]\n", get_page_name(mpi), mpi->page);
    } else if (trace_cmd > 1) {
        off = modePageOffset(resp, mpi->resp_len, 0);
        if (off >= 0) {
            printf("  cdb response:\n");
            dump(resp, mpi->resp_len);
        }
    }
    return status;
}

static int
get_mode_page(struct mpage_info * mpi, int dbd, unsigned char * resp)
{
    int res;

    if (mode6byte)
        res = get_mode_page6(mpi, dbd, resp, single_fetch);
    else
        res = get_mode_page10(mpi, 0, dbd, resp, single_fetch);
    if (UNKNOWN_OPCODE == res)
        fprintf(stdout, ">>>>> Try command again with%s '-6' "
                "argument\n", (mode6byte ? "out the" : " a"));
    else if (mpi->subpage && (BAD_CDB_FIELD == res))
        fprintf(stdout, ">>>>> device doesn't seem to support "
                "subpages\n");
    else if (DEVICE_ATTENTION == res)
        fprintf(stdout, ">>>>> device reports UNIT ATTENTION, check it or"
                " just try again\n");
    else if (DEVICE_NOT_READY == res)
        fprintf(stdout, ">>>>> device NOT READY, does it need media?\n");
    return res;
}

/* Contents should point to the mode parameter header that we obtained
   in a prior read operation.  This way we do not have to work out the
   format of the beast. Assume 0 or 1 block descriptors. */
static int
put_mode_page6(struct mpage_info * mpi, const unsigned char * msense6_resp,
               int sp_bit)
{
    int status;
    int bdlen, resplen;
    unsigned char cmd[6];
    struct scsi_cmnd_io sci;

    bdlen = msense6_resp[3];
    resplen = msense6_resp[0] + 1;

    cmd[0] = SMODE_SELECT;
    cmd[1] = 0x10 | (sp_bit ? 1 : 0); /* always set PF bit */
    cmd[2] = 0x00;
    cmd[3] = 0x00;              /* (reserved) */
    cmd[4] = resplen;           /* parameter list length */
    cmd[5] = 0x00;              /* (reserved) */

    memcpy(cbuffer1, msense6_resp, resplen);
    cbuffer1[0] = 0;            /* Mask off the mode data length
                                   - reserved field */
    cbuffer1[2] = 0;            /* device-specific parameter is not defined
                                   and/or reserved for mode select */

#if 0   /* leave block descriptor alone */
    if (bdlen > 0) {
        memset(cbuffer1 + MPHEADER6_LEN, 0, 4);  /* clear 'number of blocks'
                                                   for DAD device */
        cbuffer1[MPHEADER6_LEN + 4] = 0; /* clear DAD density code. Why? */
        /* leave DAD block length */
    }
#endif
    cbuffer1[MPHEADER6_LEN + bdlen] &= 0x7f;   /* Mask PS bit */

    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_TO_DEVICE;
    sci.dxfer_len = resplen;
    sci.dxferp = cbuffer1;
    status = do_scsi_io(&sci);
    if (status) {
        if (mpi->subpage)
            fprintf(stdout, ">>> Unable to store %s mode page 0x%x,"
                    " subpage 0x%x [msel_6]\n", get_page_name(mpi),
                    mpi->page, mpi->subpage);
        else
            fprintf(stdout, ">>> Unable to store %s mode page 0x%x [msel_6]\n",
                    get_page_name(mpi), mpi->page);
    }
    return status;
}

/* Contents should point to the mode parameter header that we obtained
   in a prior read operation.  This way we do not have to work out the
   format of the beast. Assume 0 or 1 block descriptors. */
static int
put_mode_page10(struct mpage_info * mpi, const unsigned char * msense10_resp,
                int sp_bit)
{
    int status;
    int bdlen, resplen;
    unsigned char cmd[10];
    struct scsi_cmnd_io sci;

    bdlen = (msense10_resp[6] << 8) + msense10_resp[7];
    resplen = (msense10_resp[0] << 8) + msense10_resp[1] + 2;

    cmd[0] = SMODE_SELECT_10;
    cmd[1] = 0x10 | (sp_bit ? 1 : 0); /* always set PF bit */
    cmd[2] = 0x00;              /* (reserved) */
    cmd[3] = 0x00;              /* (reserved) */
    cmd[4] = 0x00;              /* (reserved) */
    cmd[5] = 0x00;              /* (reserved) */
    cmd[6] = 0x00;              /* (reserved) */
    cmd[7] = (resplen >> 8) & 0xff;
    cmd[8] = resplen & 0xff;
    cmd[9] = 0x00;              /* (reserved) */

    memcpy(cbuffer1, msense10_resp, resplen);
    cbuffer1[0] = 0;            /* Mask off the mode data length */
    cbuffer1[1] = 0;            /* Mask off the mode data length */
    cbuffer1[3] = 0;            /* device-specific parameter is not defined
                                   and/or reserved for mode select */
#if 0   /* leave block descriptor alone */
    if (bdlen > 0) {
        memset(cbuffer1 + MPHEADER10_LEN, 0, 4);  /* clear 'number of blocks'
                                                    for DAD device */
        cbuffer1[MPHEADER10_LEN + 4] = 0; /* clear DAD density code. Why? */
        /* leave DAD block length */
    }
#endif
    cbuffer1[MPHEADER10_LEN + bdlen] &= 0x7f;   /* Mask PS bit */

    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_TO_DEVICE;
    sci.dxfer_len = resplen;
    sci.dxferp = cbuffer1;
    status = do_scsi_io(&sci);
    if (status) {
        if (mpi->subpage)
            fprintf(stdout, ">>> Unable to store %s mode page 0x%x,"
                    " subpage 0x%x [msel_10]\n", get_page_name(mpi),
                    mpi->page, mpi->subpage);
        else
            fprintf(stdout, ">>> Unable to store %s mode page 0x%x "
                    "[msel_10]\n", get_page_name(mpi), mpi->page);
    }
    return status;
}

static int
put_mode_page(struct mpage_info * mpi, const unsigned char * msense_resp)
{
    if (mode6byte)
        return put_mode_page6(mpi, msense_resp, ! negate_sp_bit);
    else
        return put_mode_page10(mpi, msense_resp, ! negate_sp_bit);
}

static int
setup_mode_page(struct mpage_info * mpi, int nparam, unsigned char * buff,
                unsigned char ** o_pagestart)
{
    int status, offset, rem_pglen;
    unsigned char * pgp;

    status = get_mode_page(mpi, 0, buff);
    if (status) {
        printf("\n");
        return status;
    }
    offset = modePageOffset(buff, mpi->resp_len, mode6byte);
    if (offset < 0) {
        fprintf(stdout, "mode page=0x%x has bad page format\n", mpi->page);
        fprintf(stdout, "   perhaps '-z' switch may help\n");
        return -1;
    }
    pgp = buff + offset;
    *o_pagestart = pgp;
    rem_pglen = (0x40 & pgp[0]) ? ((pgp[2] << 8) + pgp[3]) : pgp[1];

    if (x_interface && replace) {
        if ((nparam && (n_replacement_values != nparam)) ||
            ((! nparam) && (n_replacement_values != rem_pglen))) {
            fprintf(stdout, "Wrong number of replacement values (%i instead "
                    "of %i)\n", n_replacement_values,
                    nparam ? nparam : rem_pglen);
            return 1;
        }
        next_parameter = 1;
    }
    return 0;
}

static int
get_protocol_id(int port_not_lu, unsigned char * buff, int * proto_idp,
                int * offp)
{
    int status, off, proto_id, spf;
    struct mpage_info mp_i;
    char b[64];

    memset(&mp_i, 0, sizeof(mp_i));
    mp_i.page = (port_not_lu ? 0x19 : 0x18);
    /* N.B. getting port or lu specific mode page (not subpage) */
    status = get_mode_page(&mp_i, 0, buff);
    if (status)
        return status;
    off = modePageOffset(buff, mp_i.resp_len, mode6byte);
    if (off < 0)
        return off;
    spf = (buff[off] & 0x40) ? 1 : 0;  /* subpages won't happen here */
    proto_id = buff[off + (spf ? 5 : 2)] & 0xf;
    if (trace_cmd > 0)
        printf("Protocol specific %s, protocol_id=%s\n",
               (port_not_lu ? "port" : "lu"),
               sg_get_trans_proto_str(proto_id, sizeof(b), b));
    if (proto_idp)
        *proto_idp = proto_id;
    if (offp)
        *offp = off;
    return 0;
}

static int
disk_geometry(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 9, cbuffer, &pagestart);
    if (status)
        return status;
    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-----------------------------------\n");
    };
    intfield(pagestart + 2, 3, "Number of cylinders");
    intfield(pagestart + 5, 1, "Number of heads");
    intfield(pagestart + 6, 3, "Starting cyl. write precomp");
    intfield(pagestart + 9, 3, "Starting cyl. reduced current");
    intfield(pagestart + 12, 2, "Device step rate");
    intfield(pagestart + 14, 3, "Landing Zone Cylinder");
    bitfield(pagestart + 17, "RPL", 3, 0);
    intfield(pagestart + 18, 1, "Rotational Offset");
    intfield(pagestart + 20, 2, "Rotational Rate");
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
common_disconnect_reconnect(struct mpage_info * mpi,
                                       const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 11, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("------------------------------------\n");
    };
    intfield(pagestart + 2, 1, "Buffer full ratio");
    intfield(pagestart + 3, 1, "Buffer empty ratio");
    intfield(pagestart + 4, 2, "Bus Inactivity Limit (SAS: 100us)");
    intfield(pagestart + 6, 2, "Disconnect Time Limit");
    intfield(pagestart + 8, 2, "Connect Time Limit (SAS: 100us)");
    intfield(pagestart + 10, 2, "Maximum Burst Size");
    bitfield(pagestart + 12, "EMDP", 1, 7);
    bitfield(pagestart + 12, "Fair Arbitration (fcp:faa,fab,fac)", 0x7, 4);
    bitfield(pagestart + 12, "DIMM", 1, 3);
    bitfield(pagestart + 12, "DTDC", 0x7, 0);
    intfield(pagestart + 14, 2, "First Burst Size");
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;

}

static int
common_control(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 21, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-----------------------\n");
    }
    bitfield(pagestart + 2, "TST", 0x7, 5);
    bitfield(pagestart + 2, "TMF_ONLY", 1, 4);
    bitfield(pagestart + 2, "D_SENSE", 1, 2);
    bitfield(pagestart + 2, "GLTSD", 1, 1);
    bitfield(pagestart + 2, "RLEC", 1, 0);
    bitfield(pagestart + 3, "Queue Algorithm Modifier", 0xf, 4);
    bitfield(pagestart + 3, "QErr", 0x3, 1);
    bitfield(pagestart + 3, "DQue [obsolete]", 1, 0);
    bitfield(pagestart + 4, "TAS", 1, 7);
    bitfield(pagestart + 4, "RAC", 1, 6);
    bitfield(pagestart + 4, "UA_INTLCK_CTRL", 0x3, 4);
    bitfield(pagestart + 4, "SWP", 1, 3);
    bitfield(pagestart + 4, "RAERP [obs.]", 1, 2);
    bitfield(pagestart + 4, "UAAERP [obs.]", 1, 1);
    bitfield(pagestart + 4, "EAERP [obs.]", 1, 0);
    bitfield(pagestart + 5, "ATO", 1, 7);
    bitfield(pagestart + 5, "TAS", 1, 6);
    bitfield(pagestart + 5, "AUTOLOAD MODE", 0x7, 0);
    intfield(pagestart + 6, 2, "Ready AER Holdoff Period [obs.]");
    intfield(pagestart + 8, 2, "Busy Timeout Period");
    intfield(pagestart + 10, 2, "Extended self-test completion time");
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
common_control_extension(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 4, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode subpage (0x%x,0x%x)\n", get_page_name(mpi), mpi->page,
               mpi->subpage);
        printf("--------------------------------------------\n");
    }
    bitfield(pagestart + 4, "TCMOS", 1, 2);
    bitfield(pagestart + 4, "SCSIP", 1, 1);
    bitfield(pagestart + 4, "IALUAE", 1, 0);
    bitfield(pagestart + 5, "Initial Priority", 0xf, 0);

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
common_informational(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 10, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-----------------------------------------\n");
    }
    bitfield(pagestart + 2, "PERF", 1, 7);
    bitfield(pagestart + 2, "EBF", 1, 5);
    bitfield(pagestart + 2, "EWASC", 1, 4);
    bitfield(pagestart + 2, "DEXCPT", 1, 3);
    bitfield(pagestart + 2, "TEST", 1, 2);
    bitfield(pagestart + 2, "EBACKERR", 1, 1);
    bitfield(pagestart + 2, "LOGERR", 1, 0);
    bitfield(pagestart + 3, "MRIE", 0xf, 0);
    intfield(pagestart + 4, 4, "Interval Timer");
    intfield(pagestart + 8, 4, "Report Count");
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
disk_error_recovery(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 14, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-----------------------------------------\n");
    }
    bitfield(pagestart + 2, "AWRE", 1, 7);
    bitfield(pagestart + 2, "ARRE", 1, 6);
    bitfield(pagestart + 2, "TB", 1, 5);
    bitfield(pagestart + 2, "RC", 1, 4);
    bitfield(pagestart + 2, "EER", 1, 3);
    bitfield(pagestart + 2, "PER", 1, 2);
    bitfield(pagestart + 2, "DTE", 1, 1);
    bitfield(pagestart + 2, "DCR", 1, 0);
    intfield(pagestart + 3, 1, "Read Retry Count");
    intfield(pagestart + 4, 1, "Correction Span");
    intfield(pagestart + 5, 1, "Head Offset Count");
    intfield(pagestart + 6, 1, "Data Strobe Offset Count");
    intfield(pagestart + 8, 1, "Write Retry Count");
    intfield(pagestart + 10, 2, "Recovery Time Limit (ms)");
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
cdvd_error_recovery(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 10, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("------------------------------------------------\n");
    }
    bitfield(pagestart + 2, "AWRE", 1, 7);
    bitfield(pagestart + 2, "ARRE", 1, 6);
    bitfield(pagestart + 2, "TB", 1, 5);
    bitfield(pagestart + 2, "RC", 1, 4);
    bitfield(pagestart + 2, "PER", 1, 2);
    bitfield(pagestart + 2, "DTE", 1, 1);
    bitfield(pagestart + 2, "DCR", 1, 0);
    intfield(pagestart + 3, 1, "Read Retry Count");
    bitfield(pagestart + 7, "EMCDR", 3, 0);
    intfield(pagestart + 8, 1, "Write Retry Count");
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
cdvd_mrw(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 1, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("------------------------------------------------\n");
    }
    bitfield(pagestart + 3, "LBA space", 1, 0);
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
disk_notch_parameters(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 6, cbuffer, &pagestart);
    if (status) {
        fprintf(stdout, "Special case: only give 6 fields to '-XR' since"
                " 'Pages Notched' is unchangeable\n");
        return status;
    }

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-----------------------------------\n");
    };
    bitfield(pagestart + 2, "Notched Drive", 1, 7);
    bitfield(pagestart + 2, "Logical or Physical Notch", 1, 6);
    intfield(pagestart + 4, 2, "Max # of notches");
    intfield(pagestart + 6, 2, "Active Notch");
    if (pagestart[2] & 0x40) {
        intfield(pagestart + 8, 4, "Starting Boundary");
        intfield(pagestart + 12, 4, "Ending Boundary");
    } else {           /* Hex is more meaningful for physical notches */
        hexfield(pagestart + 8, 4, "Starting Boundary");
        hexfield(pagestart + 12, 4, "Ending Boundary");
    }

    if (x_interface && !replace) {
#if 1
        ;       /* do nothing, skip this field */
#else
        if (1 == mpi->page_control)     /* modifiable */
            printf("0");
        else
            printf("0x%8.8x%8.8x", getnbyte(pagestart + 16, 4),
                   getnbyte(pagestart + 20, 4));
#endif
    };
    if (!x_interface)
        printf("Pages Notched                      %8.8x %8.8x\n",
               getnbyte(pagestart + 16, 4), getnbyte(pagestart + 20, 4));
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static char *
formatname(int format)
{
    switch(format) {
        case 0x0: return "logical block addresses (32 bit)";
        case 0x3: return "logical block addresses (64 bit)";
        case 0x4: return "bytes from index [Cyl:Head:Off]\n"
                "Offset -1 marks whole track as bad.\n";
        case 0x5: return "physical blocks [Cyl:Head:Sect]\n"
                "Sector -1 marks whole track as bad.\n";
    }
    return "Weird, unknown format";
}

static int
read_defect_list(int grown_only)
{
    int i, len, reallen, table, k, defect_format;
    int status = 0;
    int header = 1;
    int sorthead = 0;
    unsigned char cmd[10];
    unsigned char cmd12[12];
    unsigned char *df = NULL;
    unsigned char *bp = NULL;
    unsigned char *heapp = NULL;
    unsigned int  *headsp = NULL;
    int trunc;
    struct scsi_cmnd_io sci;

    if (defectformat == HEAD_SORT_TOKEN) {
        defectformat = 0x04;
        sorthead = 1;
        headsp = (unsigned int *)malloc(sizeof(unsigned int) * MAX_HEADS);
        if (headsp == NULL) {
           perror("malloc failed");
           return status;
        }
        memset(headsp,0,sizeof(unsigned int) * MAX_HEADS);
    }
    for (table = grown_only; table < 2; table++) {
        if (heapp) {
            free(heapp);
            heapp = NULL;
        }
        bp = cbuffer;
        memset(bp, 0, 4);
        trunc = 0;
        reallen = -1;

        cmd[0] = 0x37;          /* READ DEFECT DATA (10) */
        cmd[1] = 0x00;
        cmd[2] = (table ? 0x08 : 0x10) | defectformat;  /*  List, Format */
        cmd[3] = 0x00;          /* (reserved) */
        cmd[4] = 0x00;          /* (reserved) */
        cmd[5] = 0x00;          /* (reserved) */
        cmd[6] = 0x00;          /* (reserved) */
        cmd[7] = 0x00;          /* Alloc len */
        cmd[8] = 0x04;          /* Alloc len (size finder) */
        cmd[9] = 0x00;          /* control */

        sci.cmnd = cmd;
        sci.cmnd_len = sizeof(cmd);
        sci.dxfer_dir = DXFER_FROM_DEVICE;
        sci.dxfer_len = 4;
        sci.dxferp = bp;
        i = do_scsi_io(&sci);
        if (i) {
            fprintf(stdout, ">>> Unable to read %s defect data.\n",
                    (table ? "grown (GLIST)" : "primary (PLIST)"));
            status |= i;
            continue;
        }
        if (trace_cmd > 1) {
            printf("  cdb response:\n");
            dump(bp, 4);
        }
        /*
         * Check validity of response:
         * bp[0] reserved, must be zero
         * bp[1] bits 7-5 reserved, must be zero
         * bp[1] bits 4-3 should match table requested
         */
        if (0 != bp[0] || (table ? 0x08 : 0x10) != (bp[1] & 0xf8)) {
            fprintf(stdout, ">>> Invalid header for %s defect list.\n",
                    (table ? "grown (GLIST)" : "primary (PLIST)"));
            status |= 1;
            continue;
        }
        if (header) {
            printf("Defect Lists\n"
                   "------------\n");
            header = 0;
        }
        len = (bp[2] << 8) + bp[3];
        if (len < 0xfff8)
            reallen = len;
        else {
            /*
             * List length is at or over capacity of READ DEFECT DATA (10)
             * Try to get actual length with READ DEFECT DATA (12)
             */
            bp = cbuffer;
            memset(bp, 0, 8);
            cmd12[0] = 0xB7;          /* READ DEFECT DATA (12) */
            cmd12[1] = (table ? 0x08 : 0x10) | defectformat;/*  List, Format */
            cmd12[2] = 0x00;          /* (reserved) */
            cmd12[3] = 0x00;          /* (reserved) */
            cmd12[4] = 0x00;          /* (reserved) */
            cmd12[5] = 0x00;          /* (reserved) */
            cmd12[6] = 0x00;          /* Alloc len */
            cmd12[7] = 0x00;          /* Alloc len */
            cmd12[8] = 0x00;          /* Alloc len */
            cmd12[9] = 0x08;          /* Alloc len (size finder) */
            cmd12[10] = 0x00;         /* reserved */
            cmd12[11] = 0x00;         /* control */

            sci.cmnd = cmd12;
            sci.cmnd_len = sizeof(cmd12);
            sci.dxfer_dir = DXFER_FROM_DEVICE;
            sci.dxfer_len = 8;
            sci.dxferp = bp;
            i = do_scsi_io(&sci);
            if (i) {
                if (trace_cmd) {
                    fprintf(stdout, ">>> No 12 byte command support, "
                            "but list is too long for 10 byte version.\n"
                            "List will be truncated at 8191 elements\n");
                }
                goto trytenbyte;
            }
            if (trace_cmd > 1) {
                printf("  cdb response:\n");
                dump(bp, 8);
            }
            /*
             * Check validity of response:
             *    bp[0], bp[2] and bp[3] reserved, must be zero
             *    bp[1] bits 7-5 reserved, must be zero
             *    bp[1] bits 4-3 should match table we requested
             */
            if (0 != bp[0] || 0 != bp[2] || 0 != bp[3] ||
                    ((table ? 0x08 : 0x10) != (bp[1] & 0xf8))) {
                if (trace_cmd)
                    fprintf(stdout,
                            ">>> Invalid header for %s defect list.\n",
                            (table ? "grown (GLIST)" : "primary (PLIST)"));
                goto trytenbyte;
            }
            len = (bp[4] << 24) + (bp[5] << 16) + (bp[6] << 8) + bp[7];
            reallen = len;
        }

        if (len > 0) {
            k = len + 8;              /* length of defect list + header */
            if (k > (int)sizeof(cbuffer)) {
                heapp = (unsigned char *)malloc(k);

                if (len > 0x80000 && NULL == heapp) {
                    len = 0x80000;      /* go large: 512 KB */
                    k = len + 8;
                    heapp = (unsigned char *)malloc(k);
                }
                if (heapp != NULL)
                    bp = heapp;
            }
            if (len > 0xfff0 && heapp != NULL) {
                cmd12[0] = 0xB7;          /* READ DEFECT DATA (12) */
                cmd12[1] = (table ? 0x08 : 0x10) | defectformat;
                                                /*  List, Format */
                cmd12[2] = 0x00;          /* (reserved) */
                cmd12[3] = 0x00;          /* (reserved) */
                cmd12[4] = 0x00;          /* (reserved) */
                cmd12[5] = 0x00;          /* (reserved) */
                cmd12[6] = 0x00;          /* Alloc len */
                cmd12[7] = (k >> 16) & 0xff;     /* Alloc len */
                cmd12[8] = (k >> 8) & 0xff;      /* Alloc len */
                cmd12[9] = (k & 0xff);    /* Alloc len */
                cmd12[10] = 0x00;         /* reserved */
                cmd12[11] = 0x00;         /* control */

                sci.cmnd = cmd12;
                sci.cmnd_len = sizeof(cmd12);
                sci.dxfer_dir = DXFER_FROM_DEVICE;
                sci.dxfer_len = k;
                sci.dxferp = bp;
                i = do_scsi_io(&sci);
                if (i)
                    goto trytenbyte;
                if (trace_cmd > 1) {
                    printf("  cdb response:\n");
                    dump(bp, 8);
                }
                reallen = (bp[4] << 24) + (bp[5] << 16) + (bp[6] << 8) +
                          bp[7];
                if (reallen > len) {
                    trunc = 1;
                }
                df = (unsigned char *) (bp + 8);
            }
            else {
trytenbyte:
                if (len > 0xfff8) {
                    len = 0xfff8;
                    trunc = 1;
                }
                k = len + 4;            /* length of defect list + header */
                if (k > (int)sizeof(cbuffer) && NULL == heapp) {
                    heapp = (unsigned char *)malloc(k);
                    if (heapp != NULL)
                        bp = heapp;
                }
                if (k > (int)sizeof(cbuffer) && NULL == heapp) {
                    bp = cbuffer;
                    k = sizeof(cbuffer);
                    len = k - 4;
                    trunc = 1;
                }
                cmd[0] = 0x37;          /* READ DEFECT DATA (10) */
                cmd[1] = 0x00;
                cmd[2] = (table ? 0x08 : 0x10) | defectformat;
                                        /*  List, Format */
                cmd[3] = 0x00;          /* (reserved) */
                cmd[4] = 0x00;          /* (reserved) */
                cmd[5] = 0x00;          /* (reserved) */
                cmd[6] = 0x00;          /* (reserved) */
                cmd[7] = (k >> 8);      /* Alloc len */
                cmd[8] = (k & 0xff);    /* Alloc len */
                cmd[9] = 0x00;          /* control */

                sci.cmnd = cmd;
                sci.cmnd_len = sizeof(cmd);
                sci.dxfer_dir = DXFER_FROM_DEVICE;
                sci.dxfer_len = k;
                sci.dxferp = bp;
                i = do_scsi_io(&sci);
                df = (unsigned char *) (bp + 4);
            }
        }
        if (i) {
            fprintf(stdout, ">>> Unable to read %s defect data.\n",
                    (table ? "grown (GLIST)" : "primary (PLIST)"));
            status |= i;
            continue;
        }
        else {
            if (table && !status && !sorthead)
                printf("\n");
            defect_format = (bp[1] & 0x7);
            if (-1 == reallen) {
                printf("at least ");
                reallen = len;
            }
            printf("%d entries (%d bytes) in %s table.\n",
                   reallen / ((0 == defect_format) ? 4 : 8), reallen,
                   table ? "grown (GLIST)" : "primary (PLIST)");
            if (!sorthead)
                printf("Format (%x) is: %s\n", defect_format,
                   formatname(defect_format));
            i = 0;
            switch (defect_format) {
            case 4:     /* bytes from index */
                while (len > 0) {
                    snprintf((char *)cbuffer1, 40, "%6d:%3u:%8d",
                             getnbyte(df, 3), df[3], getnbyte(df + 4, 4));
                    if (sorthead == 0)
                        printf("%19s", (char *)cbuffer1);
                    else
                        if (df[3] < MAX_HEADS) headsp[df[3]]++;
                    len -= 8;
                    df += 8;
                    i++;
                    if (i >= 4 && !sorthead) {
                        printf("\n");
                        i = 0;
                    }
                    else if (!sorthead) printf("|");
                }
            case 5:     /* physical sector */
                while (len > 0) {
                    snprintf((char *)cbuffer1, 40, "%6d:%2u:%5d",
                             getnbyte(df, 3),
                             df[3], getnbyte(df + 4, 4));
                    if (sorthead == 0)
                        printf("%15s", (char *)cbuffer1);
                    else
                        if (df[3] < MAX_HEADS) headsp[df[3]]++;
                    len -= 8;
                    df += 8;
                    i++;
                    if (i >= 5 && !sorthead) {
                        printf("\n");
                        i = 0;
                    }
                    else if (!sorthead) printf("|");
                }
            case 0:     /* lba (32 bit) */
                while (len > 0) {
                    printf("%10d", getnbyte(df, 4));
                    len -= 4;
                    df += 4;
                    i++;
                    if (i >= 7) {
                        printf("\n");
                        i = 0;
                    }
                    else
                        printf("|");
                }
            case 3:     /* lba (64 bit) */
                while (len > 0) {
                    printf("%15"PRId64, getnbyte_ll(df, 8));
                    len -= 8;
                    df += 8;
                    i++;
                    if (i >= 5) {
                        printf("\n");
                        i = 0;
                    }
                    else
                        printf("|");
                }
                break;
            default:
                printf("unknown defect list format: %d\n", defect_format);
                break;
            }
            if (i && !sorthead)
                printf("\n");
        }
        if (trunc)
                printf("[truncated]\n");
    }
    if (heapp) {
        free(heapp);
        heapp = NULL;
    }
    if (sorthead) {
        printf("Format is: [head:# entries for this head in list]\n\n");
        for (i=0; i<MAX_HEADS; i++) {
            if (headsp[i] > 0) {
               printf("%3d: %u\n", i, headsp[i]);
            }
        }
    }
    printf("\n");
    return status;
}

static int
disk_cache(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 21, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-----------------------\n");
    };
    bitfield(pagestart + 2, "Initiator Control", 1, 7);
    bitfield(pagestart + 2, "ABPF", 1, 6);
    bitfield(pagestart + 2, "CAP", 1, 5);
    bitfield(pagestart + 2, "DISC", 1, 4);
    bitfield(pagestart + 2, "SIZE", 1, 3);
    bitfield(pagestart + 2, "Write Cache Enabled", 1, 2);
    bitfield(pagestart + 2, "MF", 1, 1);
    bitfield(pagestart + 2, "Read Cache Disabled", 1, 0);
    bitfield(pagestart + 3, "Demand Read Retention Priority", 0xf, 4);
    bitfield(pagestart + 3, "Demand Write Retention Priority", 0xf, 0);
    intfield(pagestart + 4, 2, "Disable Pre-fetch Transfer Length");
    intfield(pagestart + 6, 2, "Minimum Pre-fetch");
    intfield(pagestart + 8, 2, "Maximum Pre-fetch");
    intfield(pagestart + 10, 2, "Maximum Pre-fetch Ceiling");
    bitfield(pagestart + 12, "FSW", 1, 7);
    bitfield(pagestart + 12, "LBCSS", 1, 6);
    bitfield(pagestart + 12, "DRA", 1, 5);
    bitfield(pagestart + 12, "NV_DIS", 1, 0);
    intfield(pagestart + 13, 1, "Number of Cache Segments");
    intfield(pagestart + 14, 2, "Cache Segment size");
    intfield(pagestart + 17, 3, "Non-Cache Segment size");
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
disk_format(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 13, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-----------------------------\n");
    };
    intfield(pagestart + 2, 2, "Tracks per Zone");
    intfield(pagestart + 4, 2, "Alternate sectors per zone");
    intfield(pagestart + 6, 2, "Alternate tracks per zone");
    intfield(pagestart + 8, 2, "Alternate tracks per lu");
    intfield(pagestart + 10, 2, "Sectors per track");
    intfield(pagestart + 12, 2, "Data bytes per physical sector");
    intfield(pagestart + 14, 2, "Interleave");
    intfield(pagestart + 16, 2, "Track skew factor");
    intfield(pagestart + 18, 2, "Cylinder skew factor");
    bitfield(pagestart + 20, "Supports Soft Sectoring", 1, 7);
    bitfield(pagestart + 20, "Supports Hard Sectoring", 1, 6);
    bitfield(pagestart + 20, "Removable Medium", 1, 5);
    bitfield(pagestart + 20, "Surface", 1, 4);
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;

}

static int
disk_verify_error_recovery(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 7, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-------------------------------------\n");
    }
    bitfield(pagestart + 2, "EER", 1, 3);
    bitfield(pagestart + 2, "PER", 1, 2);
    bitfield(pagestart + 2, "DTE", 1, 1);
    bitfield(pagestart + 2, "DCR", 1, 0);
    intfield(pagestart + 3, 1, "Verify Retry Count");
    intfield(pagestart + 4, 1, "Verify Correction Span (bits)");
    intfield(pagestart + 10, 2, "Verify Recovery Time Limit (ms)");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

#if 0
static int
peripheral_device_page(struct mpage_info * mpi, const char * prefix)
{
    static char *idents[] =
    {
        "X3.131: Small Computer System Interface",
        "X3.91M-1987: Storage Module Interface",
        "X3.170: Enhanced Small Device Interface",
        "X3.130-1986; X3T9.3/87-002: IPI-2",
        "X3.132-1987; X3.147-1988: IPI-3"
    };
    int status;
    unsigned ident;
    unsigned char *pagestart;
    char *name;

    status = setup_mode_page(mpi, 2, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("---------------------------------\n");
    };

#if 0
    dump(pagestart, 20);
    pagestart[1] += 2;          /*TEST */
    cbuffer[8] += 2;             /*TEST */
#endif

    ident = getnbyte(pagestart + 2, 2);
    if (ident < (sizeof(idents) / sizeof(char *)))
         name = idents[ident];
    else if (ident < 0x8000)
        name = "Reserved";
    else
        name = "Vendor Specific";

#ifdef DPG_CHECK_THIS_OUT
    bdlen = pagestart[1] - 6;
    if (bdlen < 0)
        bdlen = 0;
    else {
        status = setup_mode_page(mpi, 2, cbuffer, &bdlen,
                                 &pagestart);
        if (status)
            return status;
    }

    hexfield(pagestart + 2, 2, "Interface Identifier");
    if (!x_interface) {
        for (ident = 0; ident < 35; ident++)
            putchar(' ');
        puts(name);
    }
    hexdatafield(pagestart + 8, bdlen, "Vendor Specific Data");
#endif

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    if (x_interface)
        puts(name);
    return 0;
}
#endif

static int
common_power_condition(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 4, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("--------------------------------\n");
    }
    bitfield(pagestart + 3, "Idle", 1, 1);
    bitfield(pagestart + 3, "Standby", 1, 0);
    intfield(pagestart + 4, 4, "Idle Condition counter (100ms)");
    intfield(pagestart + 8, 4, "Standby Condition counter (100ms)");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
disk_xor_control(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 5, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("--------------------------------\n");
    }
    bitfield(pagestart + 2, "XORDS", 1, 1);
    intfield(pagestart + 4, 4, "Maximum XOR write size");
    intfield(pagestart + 12, 4, "Maximum regenerate size");
    intfield(pagestart + 16, 4, "Maximum rebuild transfer size");
    intfield(pagestart + 22, 2, "Rebuild delay");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
disk_background(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 4, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode subpage (0x%x,0x%x)\n", get_page_name(mpi), mpi->page,
               mpi->subpage);
        printf("--------------------------------------------\n");
    }
    bitfield(pagestart + 4, "Enable background medium scan", 1, 0);
    bitfield(pagestart + 5, "Enable pre-scan", 1, 0);
    intfield(pagestart + 6, 2, "BMS interval time (hour)");
    intfield(pagestart + 8, 2, "Pre-scan timeout value (hour)");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
optical_memory(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 1, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("--------------------------------\n");
    }
    bitfield(pagestart + 2, "RUBR", 1, 0);

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
cdvd_write_param(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 20, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("--------------------------------\n");
    }
    bitfield(pagestart + 2, "BUFE", 1, 6);
    bitfield(pagestart + 2, "LS_V", 1, 5);
    bitfield(pagestart + 2, "Test Write", 1, 4);
    bitfield(pagestart + 2, "Write Type", 0xf, 0);
    bitfield(pagestart + 3, "MultiSession", 3, 6);
    bitfield(pagestart + 3, "FP", 1, 5);
    bitfield(pagestart + 3, "Copy", 1, 4);
    bitfield(pagestart + 3, "Track Mode", 0xf, 0);
    bitfield(pagestart + 4, "Data Block type", 0xf, 0);
    intfield(pagestart + 5, 1, "Link size");
    bitfield(pagestart + 7, "Initiator app. code", 0x3f, 0);
    intfield(pagestart + 8, 1, "Session Format");
    intfield(pagestart + 10, 4, "Packet size");
    intfield(pagestart + 14, 2, "Audio Pause Length");
    hexdatafield(pagestart + 16, 16, "Media Catalog number");
    hexdatafield(pagestart + 32, 16, "Int. standard recording code");
    hexdatafield(pagestart + 48, 1, "Subheader byte 1");
    hexdatafield(pagestart + 49, 1, "Subheader byte 2");
    hexdatafield(pagestart + 50, 1, "Subheader byte 3");
    hexdatafield(pagestart + 51, 1, "Subheader byte 4");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
cdvd_audio_control(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 10, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("--------------------------------\n");
    }
    bitfield(pagestart + 2, "IMMED", 1, 2);
    bitfield(pagestart + 2, "SOTC", 1, 1);
    bitfield(pagestart + 8, "CDDA out port 0, channel select", 0xf, 0);
    intfield(pagestart + 9, 1, "Channel port 0 volume");
    bitfield(pagestart + 10, "CDDA out port 1, channel select", 0xf, 0);
    intfield(pagestart + 11, 1, "Channel port 1 volume");
    bitfield(pagestart + 12, "CDDA out port 2, channel select", 0xf, 0);
    intfield(pagestart + 13, 1, "Channel port 2 volume");
    bitfield(pagestart + 14, "CDDA out port 3, channel select", 0xf, 0);
    intfield(pagestart + 15, 1, "Channel port 3 volume");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
cdvd_timeout(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 6, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-----------------------------------\n");
    }
    bitfield(pagestart + 4, "G3Enable", 1, 3);
    bitfield(pagestart + 4, "TMOE", 1, 2);
    bitfield(pagestart + 4, "DISP", 1, 1);
    bitfield(pagestart + 4, "SWPP", 1, 0);
    intfield(pagestart + 6, 2, "Group 1 minimum time-out");
    intfield(pagestart + 8, 2, "Group 2 minimum time-out");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
cdvd_device_param(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 3, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("------------------------------------\n");
    }
    bitfield(pagestart + 3, "Inactivity timer multiplier", 0xf, 0);
    intfield(pagestart + 4, 2, "MSF-S units per MSF_M unit");
    intfield(pagestart + 6, 2, "MSF-F units per MSF_S unit");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

/* This is not a standard t10.org MMC mode page (it is now "protocol specific
   lu" mode page). This definition was found in Hitachi GF-2050/GF-2055
   DVD-RAM drive SCSI reference manual. */
static int
cdvd_feature(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 12, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("----------------------------------------------\n");
    }
    intfield(pagestart + 2, 2, "DVD feature set");
    intfield(pagestart + 4, 2, "CD audio");
    intfield(pagestart + 6, 2, "Embedded changer");
    intfield(pagestart + 8, 2, "Packet SMART");
    intfield(pagestart + 10, 2, "Persistent prevent(MESN)");
    intfield(pagestart + 12, 2, "Event status notification");
    intfield(pagestart + 14, 2, "Digital output");
    intfield(pagestart + 16, 2, "CD sequential recordable");
    intfield(pagestart + 18, 2, "DVD sequential recordable");
    intfield(pagestart + 20, 2, "Random recordable");
    intfield(pagestart + 22, 2, "Key management");
    intfield(pagestart + 24, 2, "Partial recorded CD media read");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
cdvd_mm_capab(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 49, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("----------------------------------------------------\n");
    }
    bitfield(pagestart + 2, "DVD-RAM read", 1, 5);
    bitfield(pagestart + 2, "DVD-R read", 1, 4);
    bitfield(pagestart + 2, "DVD-ROM read", 1, 3);
    bitfield(pagestart + 2, "Method 2", 1, 2);
    bitfield(pagestart + 2, "CD-RW read", 1, 1);
    bitfield(pagestart + 2, "CD-R read", 1, 0);
    bitfield(pagestart + 3, "DVD-RAM write", 1, 5);
    bitfield(pagestart + 3, "DVD-R write", 1, 4);
    bitfield(pagestart + 3, "DVD-ROM write", 1, 3);
    bitfield(pagestart + 3, "Test Write", 1, 2);
    bitfield(pagestart + 3, "CD-RW write", 1, 1);
    bitfield(pagestart + 3, "CD-R write", 1, 0);
    bitfield(pagestart + 4, "BUF", 1, 7);
    bitfield(pagestart + 4, "MultiSession", 1, 6);
    bitfield(pagestart + 4, "Mode 2 Form 2", 1, 5);
    bitfield(pagestart + 4, "Mode 2 Form 1", 1, 4);
    bitfield(pagestart + 4, "Digital port (2)", 1, 3);
    bitfield(pagestart + 4, "Digital port (1)", 1, 2);
    bitfield(pagestart + 4, "Composite", 1, 1);
    bitfield(pagestart + 4, "Audio play", 1, 0);
    bitfield(pagestart + 5, "Read bar code", 1, 7);
    bitfield(pagestart + 5, "UPC", 1, 6);
    bitfield(pagestart + 5, "ISRC", 1, 5);
    bitfield(pagestart + 5, "C2 pointers supported", 1, 4);
    bitfield(pagestart + 5, "R-W de-interleaved & corrected", 1, 3);
    bitfield(pagestart + 5, "R-W supported", 1, 2);
    bitfield(pagestart + 5, "CD-DA stream is accurate", 1, 1);
    bitfield(pagestart + 5, "CD-DA commands supported", 1, 0);
    bitfield(pagestart + 6, "Loading mechanism type", 7, 5);
    bitfield(pagestart + 6, "Eject (individual or magazine)", 1, 3);
    bitfield(pagestart + 6, "Prevent jumper", 1, 2);
    bitfield(pagestart + 6, "Lock state", 1, 1);
    bitfield(pagestart + 6, "Lock", 1, 0);
    bitfield(pagestart + 7, "R-W in lead-in", 1, 5);
    bitfield(pagestart + 7, "Side change capable", 1, 4);
    bitfield(pagestart + 7, "S/W slot selection", 1, 3);
    bitfield(pagestart + 7, "Changer supports disc present", 1, 2);
    bitfield(pagestart + 7, "Separate channel mute", 1, 1);
    bitfield(pagestart + 7, "Separate volume levels", 1, 0);
    intfield(pagestart + 10, 2, "number of volume level supported");
    intfield(pagestart + 12, 2, "Buffer size supported");
    bitfield(pagestart + 17, "Length", 3, 4);
    bitfield(pagestart + 17, "LSBF", 1, 3);
    bitfield(pagestart + 17, "RCK", 1, 2);
    bitfield(pagestart + 17, "BCKF", 1, 1);
    intfield(pagestart + 22, 2, "Copy management revision supported");
    bitfield(pagestart + 27, "Rotation control selected", 3, 0);
    intfield(pagestart + 28, 2, "Current write speed selected");
    intfield(pagestart + 30, 2, "# of lu speed performance tables");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
cdvd_cache(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 2, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("-----------------------\n");
    };
    bitfield(pagestart + 2, "Write Cache Enabled", 1, 2);
    bitfield(pagestart + 2, "Read Cache Disabled", 1, 0);
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
tape_data_compression(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 6, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("----------------------------------------------------\n");
    }
    bitfield(pagestart + 2, "DCE", 1, 7);
    bitfield(pagestart + 2, "DCC", 1, 6);
    bitfield(pagestart + 3, "DDE", 1, 7);
    bitfield(pagestart + 3, "RED", 3, 5);
    intfield(pagestart + 4, 4, "Compression algorithm");
    intfield(pagestart + 8, 4, "Decompression algorithm");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
tape_dev_config(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 25, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("----------------------------------------------------\n");
    }
    bitfield(pagestart + 2, "CAF", 1, 5);
    bitfield(pagestart + 2, "Active format", 0x1f, 0);
    intfield(pagestart + 3, 1, "Active partition");
    intfield(pagestart + 4, 1, "Write object cbuffer full ratio");
    intfield(pagestart + 5, 1, "Read object cbuffer full ratio");
    intfield(pagestart + 6, 2, "Wire delay time");
    bitfield(pagestart + 8, "OBR", 1, 7);
    bitfield(pagestart + 8, "LOIS", 1, 6);
    bitfield(pagestart + 8, "RSMK", 1, 5);
    bitfield(pagestart + 8, "AVC", 1, 4);
    bitfield(pagestart + 8, "SOCF", 3, 2);
    bitfield(pagestart + 8, "ROBO", 1, 1);
    bitfield(pagestart + 8, "REW", 1, 0);
    intfield(pagestart + 9, 1, "Gap size");
    bitfield(pagestart + 10, "EOD defined", 7, 5);
    bitfield(pagestart + 10, "EEG", 1, 4);
    bitfield(pagestart + 10, "SEW", 1, 3);
    bitfield(pagestart + 10, "SWP", 1, 2);
    bitfield(pagestart + 10, "BAML", 1, 1);
    bitfield(pagestart + 10, "BAM", 1, 0);
    intfield(pagestart + 11, 3, "Object cbuffer size at early warning");
    intfield(pagestart + 14, 1, "Select data compression algorithm");
    bitfield(pagestart + 15, "ASOCWP", 1, 2);
    bitfield(pagestart + 15, "PERSWO", 1, 1);
    bitfield(pagestart + 15, "PRMWP", 1, 0);

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
tape_medium_part1(struct mpage_info * mpi, const char * prefix)
{
    int status, off, len;
    unsigned char *pagestart;

    /* variable length mode page, need to know its response length */
    status = get_mode_page(mpi, 0, cbuffer);
    if (status)
        return status;
    off = modePageOffset(cbuffer, mpi->resp_len, mode6byte);
    if (off < 0)
        return off;
    len = mpi->resp_len - off;

    status = setup_mode_page(mpi, 12 + ((len - 10) / 2), cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("----------------------------------------------------\n");
    }
    intfield(pagestart + 2, 1, "Maximum additional partitions");
    intfield(pagestart + 3, 1, "Additional partitions defined");
    bitfield(pagestart + 4, "FDP", 1, 7);
    bitfield(pagestart + 4, "SDP", 1, 6);
    bitfield(pagestart + 4, "IDP", 1, 5);
    bitfield(pagestart + 4, "PSUM", 3, 3);
    bitfield(pagestart + 4, "POFM", 1, 2);
    bitfield(pagestart + 4, "CLEAR", 1, 1);
    bitfield(pagestart + 4, "ADDP", 1, 0);
    intfield(pagestart + 5, 1, "Medium format recognition");
    bitfield(pagestart + 6, "Partition units", 0xf, 0);
    intfield(pagestart + 8, 2, "Partition size");

    for (off = 10; off < len; off += 2)
        intfield(pagestart + off, 2, "Partition size");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
tape_medium_part2_4(struct mpage_info * mpi, const char * prefix)
{
    int status, off, len;
    unsigned char *pagestart;

    /* variable length mode page, need to know its response length */
    status = get_mode_page(mpi, 0, cbuffer);
    if (status)
        return status;
    off = modePageOffset(cbuffer, mpi->resp_len, mode6byte);
    if (off < 0)
        return off;
    len = mpi->resp_len - off;

    status = setup_mode_page(mpi, 1 + ((len - 4) / 2), cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("----------------------------------------------------\n");
    }
    intfield(pagestart + 2, 2, "Partition size");

    for (off = 4; off < len; off += 2)
        intfield(pagestart + off, 2, "Partition size");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
ses_services_manag(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 2, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", get_page_name(mpi), mpi->page);
        printf("----------------------------------------------------\n");
    }
    bitfield(pagestart + 5, "ENBLTC", 1, 0);
    intfield(pagestart + 6, 2, "Maximum time to completion (100 ms units)");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
fcp_proto_spec_lu(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 1, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", "Fibre Channel logical unit",
               mpi->page);
        printf("----------------------------------------------------\n");
    }
    bitfield(pagestart + 3, "EPDC", 1, 0);

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
sas_proto_spec_lu(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 1, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", "SAS logical unit", mpi->page);
        printf("----------------------------------------------------\n");
    }
    bitfield(pagestart + 2, "Transport Layer Retries", 1, 4);

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
common_proto_spec_lu(struct mpage_info * mpi, const char * prefix)
{
    int status, proto_id;

    status = get_protocol_id(0, cbuffer, &proto_id, NULL);
    if (status)
        return status;
    if (0 == proto_id)
        return fcp_proto_spec_lu(mpi, prefix);
    else if (6 == proto_id)
        return sas_proto_spec_lu(mpi, prefix);
    else
        return DECODE_FAILED_TRY_HEX;
}

static int
fcp_proto_spec_port(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 10, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", "Fibre Channel port control",
               mpi->page);
        printf("----------------------------------------------------\n");
    }
    bitfield(pagestart + 3, "DTFD", 1, 7);
    bitfield(pagestart + 3, "PLPB", 1, 6);
    bitfield(pagestart + 3, "DDIS", 1, 5);
    bitfield(pagestart + 3, "DLM", 1, 4);
    bitfield(pagestart + 3, "RHA", 1, 3);
    bitfield(pagestart + 3, "ALWI", 1, 2);
    bitfield(pagestart + 3, "DTIPE", 1, 1);
    bitfield(pagestart + 3, "DTOLI", 1, 0);
    bitfield(pagestart + 6, "RR_TOV units", 7, 0);
    intfield(pagestart + 7, 1, "Resource recovery time-out");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
spi4_proto_spec_port(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 1, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", "SPI-4 port control", mpi->page);
        printf("-----------------------------------\n");
    }
    intfield(pagestart + 4, 2, "Synchronous transfer time-out");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

/* Protocol specific mode page for SAS, short format (subpage 0) */
static int
sas_proto_spec_port(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 3, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode page (0x%x)\n", "SAS SSP port control", mpi->page);
        printf("-------------------------------------\n");
    }
    bitfield(pagestart + 2, "Ready LED meaning", 0x1, 4);
    intfield(pagestart + 4, 2, "I_T Nexus Loss time");
    intfield(pagestart + 6, 2, "Initiator response time-out");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
common_proto_spec_port(struct mpage_info * mpi, const char * prefix)
{
    int status, proto_id;

    status = get_protocol_id(1, cbuffer, &proto_id, NULL);
    if (status)
        return status;
    if (0 == proto_id)
        return fcp_proto_spec_port(mpi, prefix);
    else if (1 == proto_id)
        return spi4_proto_spec_port(mpi, prefix);
    else if (6 == proto_id)
        return sas_proto_spec_port(mpi, prefix);
    else
        return DECODE_FAILED_TRY_HEX;
}

static int
spi4_margin_control(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 5, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode subpage (0x%x,0x%x)\n", "SPI-4 Margin control",
               mpi->page, mpi->subpage);
        printf("--------------------------------------------\n");
    }
    bitfield(pagestart + 5, "Protocol identifier", 0xf, 0);
    bitfield(pagestart + 7, "Driver Strength", 0xf, 4);
    bitfield(pagestart + 8, "Driver Asymmetry", 0xf, 4);
    bitfield(pagestart + 8, "Driver Precompensation", 0xf, 0);
    bitfield(pagestart + 9, "Driver Slew rate", 0xf, 4);

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

/* Protocol specific mode page for SAS, phy control + discover (subpage 1) */
static int
sas_phy_control_discover(struct mpage_info * mpi, const char * prefix)
{
    int status, off, num_phys, k;
    unsigned char *pagestart;
    unsigned char *p;

   /* variable length mode page, need to know its response length */
    status = get_mode_page(mpi, 0, cbuffer);
    if (status)
        return status;
    off = modePageOffset(cbuffer, mpi->resp_len, mode6byte);
    if (off < 0)
        return off;
    num_phys = cbuffer[off + 7];

    status = setup_mode_page(mpi,  1 + (16 * num_phys), cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode subpage (0x%x,0x%x)\n", "SAS Phy Control and "
               "Discover", mpi->page, mpi->subpage);
        printf("--------------------------------------------\n");
    }
    intfield(pagestart + 7, 1, "Number of phys");
    for (k = 0, p = pagestart + 8; k < num_phys; ++k, p += 48) {
        intfield(p + 1, 1, "Phy Identifier");
        bitfield(p + 4, "Attached Device type", 0x7, 4);
        bitfield(p + 5, "Negotiated Logical Link rate", 0xf, 0);
        bitfield(p + 6, "Attached SSP Initiator port", 0x1, 3);
        bitfield(p + 6, "Attached STP Initiator port", 0x1, 2);
        bitfield(p + 6, "Attached SMP Initiator port", 0x1, 1);
        bitfield(p + 7, "Attached SSP Target port", 0x1, 3);
        bitfield(p + 7, "Attached STP Target port", 0x1, 2);
        bitfield(p + 7, "Attached SMP Target port", 0x1, 1);
        hexdatafield(p + 8, 8, "SAS address");
        hexdatafield(p + 16, 8, "Attached SAS address");
        intfield(p + 24, 1, "Attached Phy identifier");
        bitfield(p + 32, "Programmed Min Physical Link rate", 0xf, 4);
        bitfield(p + 32, "Hardware Min Physical Link rate", 0xf, 0);
        bitfield(p + 33, "Programmed Max Physical Link rate", 0xf, 4);
        bitfield(p + 33, "Hardware Max Physical Link rate", 0xf, 0);
    }
    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}


static int
common_proto_spec_port_sp1(struct mpage_info * mpi, const char * prefix)
{
    int status, proto_id;

    status = get_protocol_id(1, cbuffer, &proto_id, NULL);
    if (status)
        return status;
    if (1 == proto_id)
        return spi4_margin_control(mpi, prefix);
    else if (6 == proto_id)
        return sas_phy_control_discover(mpi, prefix);
    else
        return DECODE_FAILED_TRY_HEX;
}

static int
spi4_training_config(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 27, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode subpage (0x%x,0x%x)\n", "training configuration",
               mpi->page, mpi->subpage);
        printf("----------------------------------------------------------\n");
    }
    hexdatafield(pagestart + 10, 4, "DB(0) value");
    hexdatafield(pagestart + 14, 4, "DB(1) value");
    hexdatafield(pagestart + 18, 4, "DB(2) value");
    hexdatafield(pagestart + 22, 4, "DB(3) value");
    hexdatafield(pagestart + 26, 4, "DB(4) value");
    hexdatafield(pagestart + 30, 4, "DB(5) value");
    hexdatafield(pagestart + 34, 4, "DB(6) value");
    hexdatafield(pagestart + 38, 4, "DB(7) value");
    hexdatafield(pagestart + 42, 4, "DB(8) value");
    hexdatafield(pagestart + 46, 4, "DB(9) value");
    hexdatafield(pagestart + 50, 4, "DB(10) value");
    hexdatafield(pagestart + 54, 4, "DB(11) value");
    hexdatafield(pagestart + 58, 4, "DB(12) value");
    hexdatafield(pagestart + 62, 4, "DB(13) value");
    hexdatafield(pagestart + 66, 4, "DB(14) value");
    hexdatafield(pagestart + 70, 4, "DB(15) value");
    hexdatafield(pagestart + 74, 4, "P_CRCA value");
    hexdatafield(pagestart + 78, 4, "P1 value");
    hexdatafield(pagestart + 82, 4, "BSY value");
    hexdatafield(pagestart + 86, 4, "SEL value");
    hexdatafield(pagestart + 90, 4, "RST value");
    hexdatafield(pagestart + 94, 4, "REQ value");
    hexdatafield(pagestart + 98, 4, "ACK value");
    hexdatafield(pagestart + 102, 4, "ATN value");
    hexdatafield(pagestart + 106, 4, "C/D value");
    hexdatafield(pagestart + 110, 4, "I/O value");
    hexdatafield(pagestart + 114, 4, "MSG value");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

/* SAS(2) SSP, shared protocol specific port mode subpage (subpage 2) */
static int
sas_shared_spec_port(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 1, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode subpage (0x%x,0x%x)\n", "SAS SSP shared protocol "
               "specific port", mpi->page, mpi->subpage);
        printf("-----------------------------------------------------\n");
    }
    intfield(pagestart + 6, 2, "Power loss timeout(ms)");

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
common_proto_spec_port_sp2(struct mpage_info * mpi, const char * prefix)
{
    int status, proto_id;

    status = get_protocol_id(1, cbuffer, &proto_id, NULL);
    if (status)
        return status;
    if (1 == proto_id)
        return spi4_training_config(mpi, prefix);
    else if (6 == proto_id)
        return sas_shared_spec_port(mpi, prefix);
    else
        return DECODE_FAILED_TRY_HEX;
}

static int
spi4_negotiated(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 7, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode subpage (0x%x,0x%x)\n", get_page_name(mpi), mpi->page,
               mpi->subpage);
        printf("--------------------------------------------\n");
    }
    intfield(pagestart + 6, 1, "Transfer period");
    intfield(pagestart + 8, 1, "REQ/ACK offset");
    intfield(pagestart + 9, 1, "Transfer width exponent");
    bitfield(pagestart + 10, "Protocol option bits", 0x7f, 0);
    bitfield(pagestart + 11, "Transceiver mode", 3, 2);
    bitfield(pagestart + 11, "Sent PCOMP_EN", 1, 1);
    bitfield(pagestart + 11, "Received PCOMP_EN", 1, 0);

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static int
spi4_report_xfer(struct mpage_info * mpi, const char * prefix)
{
    int status;
    unsigned char *pagestart;

    status = setup_mode_page(mpi, 4, cbuffer, &pagestart);
    if (status)
        return status;

    if (prefix[0])
        printf("%s", prefix);
    if (!x_interface && !replace) {
        printf("%s mode subpage (0x%x,0x%x)\n", get_page_name(mpi), mpi->page,
               mpi->subpage);
        printf("--------------------------------------------\n");
    }
    intfield(pagestart + 6, 1, "Mimimum transfer period factor");
    intfield(pagestart + 8, 1, "Maximum REQ/ACK offset");
    intfield(pagestart + 9, 1, "Maximum transfer width exponent");
    bitfield(pagestart + 10, "Protocol option bits supported", 0xff, 0);

    if (x_interface && replace)
        return put_mode_page(mpi, cbuffer);
    else
        printf("\n");
    return 0;
}

static void
print_hex_page(struct mpage_info * mpi, const char * prefix,
               unsigned char *pagestart, int off, int len)
{
    int k;
    char * pg_name;

    if (prefix[0])
        printf("%s", prefix);
    if (! x_interface) {
        pg_name = get_page_name(mpi);
        if (mpi->subpage) {
            if (pg_name && (unkn_page_str != pg_name))
                printf("mode page: 0x%02x  subpage: 0x%02x   [%s]\n",
                       mpi->page, mpi->subpage, pg_name);
            else
                printf("mode page: 0x%02x  subpage: 0x%02x\n", mpi->page,
                   mpi->subpage);
            printf("------------------------------\n");
        } else {
            if (pg_name && (unkn_page_str != pg_name))
                printf("mode page: 0x%02x   [%s]\n", mpi->page,
                       pg_name);
            else
                printf("mode page: 0x%02x\n", mpi->page);
            printf("---------------\n");
        }
    }
    for (k = off; k < len; k++)
    {
        char nm[8];

        snprintf(nm, sizeof(nm), "0x%02x", k);
        hexdatafield(pagestart + k, 1, nm);
    }
    printf("\n");
}

static int
do_user_page(struct mpage_info * mpi, int decode_in_hex)
{
    int status = 0;
    int len, off, res, done;
    int offset = 0;
    unsigned char *pagestart;
    char prefix[96];
    struct mpage_info local_mp_i;
    struct mpage_name_func * mpf;
    int multiple = ((MP_LIST_PAGES == mpi->page) ||
                    (MP_LIST_SUBPAGES == mpi->subpage));

    if (replace && multiple) {
        printf("Can't list all (sub)pages and use replace (-R) together\n");
        return 1;
    }
    status = get_mode_page(mpi, 0, cbuffer2);
    if (status) {
        printf("\n");
        return status;
    } else {
        offset = modePageOffset(cbuffer2, mpi->resp_len, mode6byte);
        if (offset < 0) {
            fprintf(stdout, "mode page=0x%x has bad page format\n",
                    mpi->page);
            fprintf(stdout, "   perhaps '-z' switch may help\n");
            return -1;
        }
        pagestart = cbuffer2 + offset;
    }

    memset(&local_mp_i, 0, sizeof(local_mp_i));
    local_mp_i.page_control = mpi->page_control;
    local_mp_i.peri_type = mpi->peri_type;
    local_mp_i.inq_byte6 = mpi->inq_byte6;
    local_mp_i.resp_len = mpi->resp_len;

    do {
        local_mp_i.page = (pagestart[0] & 0x3f);
        local_mp_i.subpage = (pagestart[0] & 0x40) ? pagestart[1] : 0;
        if(0 == local_mp_i.page) { /* page==0 vendor (unknown) format */
            off = 0;
            len = mpi->resp_len - offset;  /* should be last listed page */
        } else if (local_mp_i.subpage) {
            off = 4;
            len = (pagestart[2] << 8) + pagestart[3] + 4;
        } else {
            off = 2;
            len = pagestart[1] + 2;
        }

        prefix[0] = '\0';
        done = 0;
        if ((! decode_in_hex) && ((mpf = get_mpage_name_func(&local_mp_i))) &&
            mpf->func) {
            if (multiple && x_interface && !replace) {
                if (local_mp_i.subpage)
                    snprintf(prefix, sizeof(prefix), "sginfo -t 0x%x,0x%x"
                             " -XR %s ", local_mp_i.page, local_mp_i.subpage,
                             device_name);
                else
                    snprintf(prefix, sizeof(prefix), "sginfo -t 0x%x -XR %s ",
                             local_mp_i.page, device_name);
            }
            res = mpf->func(&local_mp_i, prefix);
            if (DECODE_FAILED_TRY_HEX != res) {
                done = 1;
                status |= res;
            }
        }
        if (! done) {
            if (x_interface && replace)
                return put_mode_page(&local_mp_i, cbuffer2);
            else {
                if (multiple && x_interface && !replace) {
                    if (local_mp_i.subpage)
                        snprintf(prefix, sizeof(prefix), "sginfo -u 0x%x,0x%x"
                                 " -XR %s ", local_mp_i.page,
                                 local_mp_i.subpage, device_name);
                    else
                        snprintf(prefix, sizeof(prefix), "sginfo -u 0x%x -XR "
                                 "%s ", local_mp_i.page, device_name);
                }
                print_hex_page(&local_mp_i, prefix, pagestart, off, len);
            }
        }
        offset += len;
        pagestart = cbuffer2 + offset;
    } while (multiple && (offset < mpi->resp_len));
    return status;
}

static int
do_inquiry(int * peri_type, int * resp_byte6, int inquiry_verbosity)
{
    int status;
    unsigned char cmd[6];
    unsigned char *pagestart;
    struct scsi_cmnd_io sci;

    memset(cbuffer, 0, INQUIRY_RESP_INITIAL_LEN);
    cbuffer[0] = 0x7f;

    cmd[0] = 0x12;              /* INQUIRY */
    cmd[1] = 0x00;              /* evpd=0 */
    cmd[2] = 0x00;              /* page code = 0 */
    cmd[3] = 0x00;              /* (reserved) */
    cmd[4] = INQUIRY_RESP_INITIAL_LEN;      /* allocation length */
    cmd[5] = 0x00;              /* control */

    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_FROM_DEVICE;
    sci.dxfer_len = INQUIRY_RESP_INITIAL_LEN;
    sci.dxferp = cbuffer;
    status = do_scsi_io(&sci);
    if (status) {
        printf("Error doing INQUIRY (1)\n");
        return status;
    }
    if (trace_cmd > 1) {
        printf("  inquiry response:\n");
        dump(cbuffer, INQUIRY_RESP_INITIAL_LEN);
    }
    pagestart = cbuffer;
    if (peri_type)
        *peri_type = pagestart[0] & 0x1f;
    if (resp_byte6)
        *resp_byte6 = pagestart[6];
    if (0 == inquiry_verbosity)
        return 0;
    if ((pagestart[4] + 5) < INQUIRY_RESP_INITIAL_LEN) {
        printf("INQUIRY response too short: expected 36 bytes, got %d\n",
               pagestart[4] + 5);
        return -EINVAL;
    }

    if (!x_interface && !replace) {
        printf("INQUIRY response (cmd: 0x12)\n");
        printf("----------------------------\n");
    };
    bitfield(pagestart + 0, "Device Type", 0x1f, 0);
    if (2 == inquiry_verbosity) {
        bitfield(pagestart + 0, "Peripheral Qualifier", 0x7, 5);
        bitfield(pagestart + 1, "Removable", 1, 7);
        bitfield(pagestart + 2, "Version", 0xff, 0);
        bitfield(pagestart + 3, "NormACA", 1, 5);
        bitfield(pagestart + 3, "HiSup", 1, 4);
        bitfield(pagestart + 3, "Response Data Format", 0xf, 0);
        bitfield(pagestart + 5, "SCCS", 1, 7);
        bitfield(pagestart + 5, "ACC", 1, 6);
        bitfield(pagestart + 5, "ALUA", 3, 4);
        bitfield(pagestart + 5, "3PC", 1, 3);
        bitfield(pagestart + 5, "Protect", 1, 0);
        bitfield(pagestart + 6, "BQue", 1, 7);
        bitfield(pagestart + 6, "EncServ", 1, 6);
        bitfield(pagestart + 6, "MultiP", 1, 4);
        bitfield(pagestart + 6, "MChngr", 1, 3);
        bitfield(pagestart + 6, "Addr16", 1, 0);
        bitfield(pagestart + 7, "Relative Address", 1, 7);
        bitfield(pagestart + 7, "Wide bus 16", 1, 5);
        bitfield(pagestart + 7, "Synchronous neg.", 1, 4);
        bitfield(pagestart + 7, "Linked Commands", 1, 3);
        bitfield(pagestart + 7, "Command Queueing", 1, 1);
    }
    if (x_interface)
        printf("\n");
    printf("%s%.8s\n", (!x_interface ? "Vendor:                    " : ""),
           pagestart + 8);

    printf("%s%.16s\n", (!x_interface ? "Product:                   " : ""),
           pagestart + 16);

    printf("%s%.4s\n", (!x_interface ? "Revision level:            " : ""),
           pagestart + 32);

    printf("\n");
    return status;

}

static int
do_serial_number(void)
{
    int status, pagelen;
    unsigned char cmd[6];
    unsigned char *pagestart;
    struct scsi_cmnd_io sci;
    const unsigned char serial_vpd = 0x80;
    const unsigned char supported_vpd = 0x0;

    /* check supported VPD pages + unit serial number well formed */
    cmd[0] = 0x12;              /* INQUIRY */
    cmd[1] = 0x01;              /* evpd=1 */
    cmd[2] = supported_vpd;
    cmd[3] = 0x00;              /* (reserved) */
    cmd[4] = 0x04;              /* allocation length */
    cmd[5] = 0x00;              /* control */

    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_FROM_DEVICE;
    sci.dxfer_len = 4;
    sci.dxferp = cbuffer;
    status = do_scsi_io(&sci);
    if (status) {
        printf("No serial number (error doing INQUIRY, supported VPDs)\n\n");
        return status;
    }
    if (! ((supported_vpd == cbuffer[1]) && (0 == cbuffer[2]))) {
        printf("No serial number (bad format for supported VPDs)\n\n");
        return -1;
    }

    cmd[0] = 0x12;              /* INQUIRY */
    cmd[1] = 0x01;              /* evpd=1 */
    cmd[2] = serial_vpd;
    cmd[3] = 0x00;              /* (reserved) */
    cmd[4] = 0x04;              /* allocation length */
    cmd[5] = 0x00;              /* control */

    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_FROM_DEVICE;
    sci.dxfer_len = 4;
    sci.dxferp = cbuffer;
    status = do_scsi_io(&sci);
    if (status) {
        printf("No serial number (error doing INQUIRY, serial number)\n\n");
        return status;
    }
    if (! ((serial_vpd == cbuffer[1]) && (0 == cbuffer[2]))) {
        printf("No serial number (bad format for serial number)\n\n");
        return -1;
    }

    pagestart = cbuffer;

    pagelen = 4 + pagestart[3];

    cmd[0] = 0x12;              /* INQUIRY */
    cmd[1] = 0x01;              /* evpd=1 */
    cmd[2] = serial_vpd;
    cmd[3] = 0x00;              /* (reserved) */
    cmd[4] = (unsigned char)pagelen; /* allocation length */
    cmd[5] = 0x00;              /* control */

    sci.cmnd = cmd;
    sci.cmnd_len = sizeof(cmd);
    sci.dxfer_dir = DXFER_FROM_DEVICE;
    sci.dxfer_len = pagelen;
    sci.dxferp = cbuffer;
    status = do_scsi_io(&sci);
    if (status) {
        printf("No serial number (error doing INQUIRY, serial number)\n\n");
        return status;
    }
    if (trace_cmd > 1) {
        printf("  inquiry (vpd page 0x80) response:\n");
        dump(cbuffer, pagelen);
    }

    pagestart[pagestart[3] + 4] = '\0';
    printf("Serial Number '%s'\n\n", pagestart + 4);
    return status;
}


typedef struct sg_map {
    int bus;
    int channel;
    int target_id;
    int lun;
    char * dev_name;
} Sg_map;

typedef struct my_scsi_idlun
{
    int mux4;
    int host_unique_id;

} My_scsi_idlun;

#define MDEV_NAME_SZ 256

static void
make_dev_name(char * fname, int k, int do_numeric)
{
    char buff[MDEV_NAME_SZ];
    size_t len;

    strncpy(fname, "/dev/sg", MDEV_NAME_SZ);
    fname[MDEV_NAME_SZ - 1] = '\0';
    len = strlen(fname);
    if (do_numeric)
        snprintf(fname + len, MDEV_NAME_SZ - len, "%d", k);
    else {
        if (k <= 26) {
            buff[0] = 'a' + (char)k;
            buff[1] = '\0';
            strcat(fname, buff);
        }
        else
            strcat(fname, "xxxx");
    }
}


static Sg_map sg_map_arr[MAX_SG_DEVS + 1];

#define MAX_HOLES 4

/* Print out a list of the known devices on the system */
static void
show_devices(int raw)
{
    int k, j, fd, err, bus;
    My_scsi_idlun m_idlun;
    char name[MDEV_NAME_SZ];
    char dev_name[MDEV_NAME_SZ];
    char ebuff[EBUFF_SZ];
    int do_numeric = 1;
    int max_holes = MAX_HOLES;
    DIR *dir_ptr;
    struct dirent *entry;
    char *tmpptr;

    dir_ptr=opendir("/dev");
    if ( dir_ptr == NULL ) {
        perror("/dev");
        exit(1);
    }

    j=0;
    while ( (entry=readdir(dir_ptr)) != NULL ) {
        switch(entry->d_type) {
        case DT_LNK:
        case DT_CHR:
        case DT_BLK:
                break;
        default:
                continue;
        }

        switch(entry->d_name[0]) {
        case 's':
        case 'n':
                break;
        default:
                continue;
        }

        if ( strncmp("sg",entry->d_name,2) == 0 ) {
                continue;
        }
        if ( strncmp("sd",entry->d_name,2) == 0 ) {
            continue;
        }
        if ( isdigit(entry->d_name[strlen(entry->d_name)-1]) ) {
            continue;
        }

        snprintf(dev_name, sizeof(dev_name),"/dev/%s",entry->d_name);

        fd = open(dev_name, O_RDONLY | O_NONBLOCK);
        if (fd < 0)
            continue;
        err = ioctl(fd, SCSI_IOCTL_GET_BUS_NUMBER, &(sg_map_arr[j].bus));
        if (err < 0) {
#if 0
            snprintf(ebuff, EBUFF_SZ,
                     "SCSI(1) ioctl on %s failed", dev_name);
            perror(ebuff);
#endif
            close(fd);
            continue;
        }
        err = ioctl(fd, SCSI_IOCTL_GET_IDLUN, &m_idlun);
        if (err < 0) {
            snprintf(ebuff, EBUFF_SZ,
                     "SCSI(2) ioctl on %s failed", dev_name);
            perror(ebuff);
            close(fd);
            continue;
        }
        sg_map_arr[j].channel = (m_idlun.mux4 >> 16) & 0xff;
        sg_map_arr[j].lun = (m_idlun.mux4 >> 8) & 0xff;
        sg_map_arr[j].target_id = m_idlun.mux4 & 0xff;
        tmpptr=(char *)malloc(strlen(dev_name)+1);
        strncpy(tmpptr,dev_name,strlen(dev_name)+1);
        sg_map_arr[j].dev_name = tmpptr;
#if 0
        printf("[scsi%d ch=%d id=%d lun=%d %s] ", sg_map_arr[j].bus,
        sg_map_arr[j].channel, sg_map_arr[j].target_id, sg_map_arr[j].lun,
        sg_map_arr[j].dev_name);
#endif
        printf("%s ", dev_name);
        close(fd);
        if (++j >= MAX_SG_DEVS)
            break;
    }
    closedir(dir_ptr);

    printf("\n"); /* <<<<<<<<<<<<<<<<<<<<< */
    for (k = 0; k < MAX_SG_DEVS; k++) {
        if ( raw ) {
                sprintf(name,"/dev/raw/raw%d",k);
                fd = open(name, O_RDWR | O_NONBLOCK);
                if (fd < 0) {
                        continue;
                }
        }
        else {
                make_dev_name(name, k, do_numeric);
                fd = open(name, O_RDWR | O_NONBLOCK);
        if (fd < 0) {
            if ((ENOENT == errno) && (0 == k)) {
                do_numeric = 0;
                make_dev_name(name, k, do_numeric);
                fd = open(name, O_RDWR | O_NONBLOCK);
            }
            if (fd < 0) {
                if (EBUSY == errno)
                    continue;   /* step over if O_EXCL already on it */
                else {
#if 0
                    snprintf(ebuff, EBUFF_SZ,
                             "open on %s failed (%d)", name, errno);
                    perror(ebuff);
#endif
                    if (max_holes-- > 0)
                        continue;
                    else
                        break;
                }
            }
        }
        }
        max_holes = MAX_HOLES;
        err = ioctl(fd, SCSI_IOCTL_GET_BUS_NUMBER, &bus);
        if (err < 0) {
            if ( ! raw ) {
                snprintf(ebuff, EBUFF_SZ, "SCSI(3) ioctl on %s failed", name);
                perror(ebuff);
            }
            close(fd);
            continue;
        }
        err = ioctl(fd, SCSI_IOCTL_GET_IDLUN, &m_idlun);
        if (err < 0) {
            if ( ! raw ) {
                snprintf(ebuff, EBUFF_SZ, "SCSI(3) ioctl on %s failed", name);
                perror(ebuff);
            }
            close(fd);
            continue;
        }
#if 0
        printf("[scsi%d ch=%d id=%d lun=%d %s]", bus,
               (m_idlun.mux4 >> 16) & 0xff, m_idlun.mux4 & 0xff,
               (m_idlun.mux4 >> 8) & 0xff, name);
#endif
        for (j = 0; sg_map_arr[j].dev_name; ++j) {
            if ((bus == sg_map_arr[j].bus) &&
                ((m_idlun.mux4 & 0xff) == sg_map_arr[j].target_id) &&
                (((m_idlun.mux4 >> 16) & 0xff) == sg_map_arr[j].channel) &&
                (((m_idlun.mux4 >> 8) & 0xff) == sg_map_arr[j].lun)) {
                printf("%s [=%s  scsi%d ch=%d id=%d lun=%d]\n", name,
                       sg_map_arr[j].dev_name, bus,
                       ((m_idlun.mux4 >> 16) & 0xff), m_idlun.mux4 & 0xff,
                       ((m_idlun.mux4 >> 8) & 0xff));
                break;
            }
        }
        if (NULL == sg_map_arr[j].dev_name)
            printf("%s [scsi%d ch=%d id=%d lun=%d]\n", name, bus,
                   ((m_idlun.mux4 >> 16) & 0xff), m_idlun.mux4 & 0xff,
                   ((m_idlun.mux4 >> 8) & 0xff));
        close(fd);
    }
    printf("\n");
}

#define DEVNAME_SZ 256

static int
open_sg_io_dev(char * devname)
{
    int fd, fdrw, err, bus, bbus, k, v;
    My_scsi_idlun m_idlun, mm_idlun;
    int do_numeric = 1;
    char name[DEVNAME_SZ];
    struct stat a_st;
    int block_dev = 0;

    strncpy(name, devname, DEVNAME_SZ);
    name[DEVNAME_SZ - 1] = '\0';
    fd = open(name, O_RDONLY | O_NONBLOCK);
    if (fd < 0)
        return fd;
    if ((ioctl(fd, SG_GET_VERSION_NUM, &v) >= 0) && (v >= 30000)) {
        fdrw = open(name, O_RDWR | O_NONBLOCK);
        if (fdrw >= 0) {
            close(fd);
            return fdrw;
        }
        return fd;
    }
    if (fstat(fd, &a_st) < 0) {
        fprintf(stderr, "could do fstat() on fd ??\n");
        close(fd);
        return -9999;
    }
    if (S_ISBLK(a_st.st_mode))
        block_dev = 1;

    if (block_dev || (ioctl(fd, SG_GET_TIMEOUT, 0) < 0)) {
        err = ioctl(fd, SCSI_IOCTL_GET_BUS_NUMBER, &bus);
        if (err < 0) {
            fprintf(stderr, "A device name that understands SCSI commands "
                    "is required\n");
            close(fd);
            return -9999;
        }
        err = ioctl(fd, SCSI_IOCTL_GET_IDLUN, &m_idlun);
        if (err < 0) {
            fprintf(stderr, "A SCSI device name is required(2)\n");
            close(fd);
            return -9999;
        }
        close(fd);

        for (k = 0; k < MAX_SG_DEVS; k++) {
            make_dev_name(name, k, do_numeric);
            fd = open(name, O_RDWR | O_NONBLOCK);
            if (fd < 0) {
                if ((ENOENT == errno) && (0 == k)) {
                    do_numeric = 0;
                    make_dev_name(name, k, do_numeric);
                    fd = open(name, O_RDWR | O_NONBLOCK);
                }
                if (fd < 0) {
                    if (EBUSY == errno)
                        continue;   /* step over if O_EXCL already on it */
                    else
                        break;
                }
            }
            err = ioctl(fd, SCSI_IOCTL_GET_BUS_NUMBER, &bbus);
            if (err < 0) {
                perror("sg ioctl failed");
                close(fd);
                fd = -9999;
            }
            err = ioctl(fd, SCSI_IOCTL_GET_IDLUN, &mm_idlun);
            if (err < 0) {
                perror("sg ioctl failed");
                close(fd);
                fd = -9999;
            }
            if ((bus == bbus) &&
                ((m_idlun.mux4 & 0xff) == (mm_idlun.mux4 & 0xff)) &&
                (((m_idlun.mux4 >> 8) & 0xff) ==
                                        ((mm_idlun.mux4 >> 8) & 0xff)) &&
                (((m_idlun.mux4 >> 16) & 0xff) ==
                                        ((mm_idlun.mux4 >> 16) & 0xff)))
                break;
            else {
                close(fd);
                fd = -9999;
            }
        }
    }
    if (fd >= 0) {
        if ((ioctl(fd, SG_GET_VERSION_NUM, &v) < 0) || (v < 30000)) {
            fprintf(stderr, "requires lk 2.4 (sg driver), lk 2.6 or lk 3 "
		    "series\n");
            close(fd);
            return -9999;
        }
        close(fd);
        return open(name, O_RDWR | O_NONBLOCK);
    }
    else
        return fd;
}

static void
usage(char *errtext)
{
    if (errtext)
        fprintf(stderr, "Error: sginfo: %s\n", errtext);
    fprintf(stderr, "Usage: sginfo [-options] [device] "
            "[replacement_values]\n");
    fputs("\tAllowed options are:\n"
          "\t-6    Do 6 byte mode sense and select commands (def: 10 "
          "bytes).\n"
          "\t-a    Display inquiry info, serial # and all mode pages.\n"
          "\t-A    Similar to '-a' but displays all subpages as well.\n"
          "\t-c    Access Caching Page.\n"
          "\t-C    Access Control Mode Page.\n"
          "\t-d    Display defect lists (default format: index).\n"
          "\t-D    Access Disconnect-Reconnect Page.\n"
          "\t-e    Access Read-Write Error Recovery page.\n"
          "\t-E    Access Control Extension page.\n"
          "\t-f    Access Format Device Page.\n"
          "\t-Farg Format of the defect list:\n"
          "\t\t-Flogical  - logical block addresses (32 bit)\n"
          "\t\t-Flba64    - logical block addresses (64 bit)\n"
          "\t\t-Fphysical - physical blocks\n"
          "\t\t-Findex    - defect bytes from index\n"
          "\t\t-Fhead     - sort by head\n", stdout);
    fputs("\t-g    Access Rigid Disk Drive Geometry Page.\n"
          "\t-G    Display 'grown' defect list (default format: index).\n"
          "\t-i    Display information from INQUIRY command.\n"
          "\t-I    Access Informational Exception page.\n"
          "\t-l    List known scsi devices on the system\n"
          "\t-n    Access Notch and Partition Page.\n"
          "\t-N    Negate (stop) storing to saved page (active with -R).\n"
          "\t-P    Access Power Condition Page.\n"
          "\t-r    List known raw scsi devices on the system\n"
          "\t-s    Display serial number (from INQUIRY VPD page).\n"
          "\t-t<pn[,sp]> Access mode page <pn> [subpage <sp>] and decode.\n"
          "\t-T    Trace commands (for debugging, double for more)\n"
          "\t-u<pn[,sp]> Access mode page <pn> [subpage <sp>], output in hex\n"
          "\t-v    Show version number\n"
          "\t-V    Access Verify Error Recovery Page.\n"
          "\t-z    single fetch mode pages (rather than double fetch)\n"
          "\n", stdout);
    fputs("\tOnly one of the following three options can be specified.\n"
   "\tNone of these three implies the current values are returned.\n", stdout);
    fputs("\t-m    Access modifiable fields instead of current values\n"
          "\t-M    Access manufacturer defaults instead of current values\n"
          "\t-S    Access saved defaults instead of current values\n\n"
          "\t-X    Use list (space separated values) rather than table.\n"
    "\t-R    Replace parameters - best used with -X (expert use only)\n"
    "\t      [replacement parameters placed after device on command line]\n\n",
    stdout);
    printf("\t      sginfo version: %s; See man page for more details.\n",
           version_str);
    exit(2);
}

int main(int argc, char *argv[])
{
    int k, j, n;
    unsigned int unum, unum2;
    int decode_in_hex = 0;
    char c;
    char * cp;
    int status = 0;
    long tmp;
    struct mpage_info mp_i;
    int inquiry_verbosity = 0;
    int show_devs = 0, show_raw = 0;
    int found = 0;

    if (argc < 2)
        usage(NULL);
    memset(&mp_i, 0, sizeof(mp_i));
    while ((k = getopt(argc, argv, "6aAcCdDeEfgGiIlmMnNPrRsSTvVXzF:t:u:")) !=
           EOF) {
        c = (char)k;
        switch (c) {
        case '6':
            mode6byte = 1;
            break;
        case 'a':
            inquiry_verbosity = 1;
            serial_number = 1;
            mp_i.page = MP_LIST_PAGES;
            break;
        case 'A':
            inquiry_verbosity = 1;
            serial_number = 1;
            mp_i.page = MP_LIST_PAGES;
            mp_i.subpage = MP_LIST_SUBPAGES;
            break;
        case 'c':
            mp_i.page = 0x8;
            break;
        case 'C':
            mp_i.page = 0xa;
            break;
        case 'd':
            defect = 1;
            break;
        case 'D':
            mp_i.page = 0x2;
            break;
        case 'e':
            mp_i.page = 0x1;
            break;
        case 'E':
            mp_i.page = 0xa;
            mp_i.subpage = 0x1;
            break;
        case 'f':
            mp_i.page = 0x3;
            break;
        case 'F':
            if (!strcasecmp(optarg, "logical"))
                defectformat = 0x0;
            else if (!strcasecmp(optarg, "lba64"))
                defectformat = 0x3;
            else if (!strcasecmp(optarg, "physical"))
                defectformat = 0x5;
            else if (!strcasecmp(optarg, "index"))
                defectformat = 0x4;
            else if (!strcasecmp(optarg, "head"))
                defectformat = HEAD_SORT_TOKEN;
            else
                usage("Illegal -F parameter, must be one of logical, "
                      "physical, index or head");
            break;
        case 'g':
            mp_i.page = 0x4;
            break;
        case 'G':
            grown_defect = 1;
            break;
        case 'i':       /* just vendor, product and revision for '-i -i' */
            inquiry_verbosity = (2 == inquiry_verbosity) ? 1 : 2;
            break;
        case 'I':
            mp_i.page = 0x1c;
            break;
        case 'l':
            show_devs = 1;
            break;
        case 'm': /* modifiable page control */
            if (0 == mp_i.page_control)
                mp_i.page_control = 1;
            else
                usage("can only have one of 'm', 'M' and 'S'");
            break;
        case 'M': /* manufacturer's==default page control */
            if (0 == mp_i.page_control)
                mp_i.page_control = 2;
            else
                usage("can only have one of 'M', 'm' and 'S'");
            break;
        case 'n':
            mp_i.page = 0xc;
            break;
        case 'N':
            negate_sp_bit = 1;
            break;
        case 'P':
            mp_i.page = 0x1a;
            break;
        case 'r':
            show_raw = 1;
            break;
        case 'R':
            replace = 1;
            break;
        case 's':
            serial_number = 1;
            break;
        case 'S': /* saved page control */
            if (0 == mp_i.page_control)
                mp_i.page_control = 3;
            else
                usage("can only have one of 'S', 'm' and 'M'");
            break;
        case 'T':
            trace_cmd++;
            break;
        case 't':
        case 'u':
            if ('u' == c)
                decode_in_hex = 1;
            while (' ' == *optarg)
                optarg++;
            if ('0' == *optarg) {
                unum = 0;
                unum2 = 0;
                j = sscanf(optarg, "0x%x,0x%x", &unum, &unum2);
                mp_i.page = unum;
                if (1 == j) {
                    cp = strchr(optarg, ',');
                    if (cp && (1 == sscanf(cp, ",%d", &mp_i.subpage)))
                        j = 2;
                } else
                    mp_i.subpage = unum2;
            } else
                j = sscanf(optarg, "%d,%d", &mp_i.page, &mp_i.subpage);
            if (1 == j)
                mp_i.subpage = 0;
            else if (j < 1)
                usage("argument following '-u' should be of form "
                      "<pg>[,<subpg>]");
            if ((mp_i.page < 0) || (mp_i.page > MP_LIST_PAGES) ||
                (mp_i.subpage < 0) || (mp_i.subpage > MP_LIST_SUBPAGES))
                usage("mode pages range from 0 .. 63, subpages from "
                      "1 .. 255");
            found = 1;
            break;
        case 'v':
            fprintf(stdout, "sginfo version: %s\n", version_str);
            return 0;
        case 'V':
            mp_i.page = 0x7;
            break;
        case 'X':
            x_interface = 1;
            break;
        case 'z':
            single_fetch = 1;
            break;
        case '?':
            usage("Unknown option");
            break;
        default:
            fprintf(stdout, "Unknown option '-%c' (ascii 0x%02x)\n", c, c);
            usage("bad option");
        }
    }

    if (replace && !x_interface)
        usage("-R requires -X");
    if (replace && mp_i.page_control)
        usage("-R not allowed for -m, -M or -S");
    if (x_interface && replace && ((MP_LIST_PAGES == mp_i.page) ||
                        (MP_LIST_SUBPAGES == mp_i.subpage)))
        usage("-XR can be used only with exactly one page.");

    if (replace && (3 != mp_i.page_control)) {
        memset (is_hex, 0, 32);
        for (j = 1; j < argc - optind; j++) {
            if (strncmp(argv[optind + j], "0x", 2) == 0) {
                char *pnt = argv[optind + j] + 2;
                replacement_values[j] = 0;
        /* This is a kluge, but we can handle 64 bit quantities this way. */
                while (*pnt) {
                    if (*pnt >= 'a' && *pnt <= 'f')
                        *pnt -= 32;
                    replacement_values[j] = (replacement_values[j] << 4) |
                        (*pnt > '9' ? (*pnt - 'A' + 10) : (*pnt - '0'));
                    pnt++;
                }
                continue;
            }
            if (argv[optind + j][0] == '@') {
        /*Ensure that this string contains an even number of hex-digits */
                int len = strlen(argv[optind + j] + 1);

                if ((len & 1) || (len != (int)strspn(argv[optind + j] + 1,
                                                "0123456789ABCDEFabcdef")))
                            usage("Odd number of chars or non-hex digit in "
                                  "@hexdatafield");

                replacement_values[j] = (unsigned long) argv[optind + j];
                is_hex[j] = 1;
                continue;
            }
            /* Using a tmp here is silly but the most clean approach */
            n = sscanf(argv[optind + j], "%ld", &tmp);
            replacement_values[j] = ((1 == n) ? tmp : 0);
        }
        n_replacement_values = argc - optind - 1;
    }
    if (show_devs) {
        show_devices(0);
        exit(0);
    }
    if (show_raw) {
        show_devices(1);
        exit(0);
    }
    if (optind >= argc)
        usage("no device name given");
    glob_fd = open_sg_io_dev(device_name = argv[optind]);
    if (glob_fd < 0) {
        if (-9999 == glob_fd)
            fprintf(stderr, "Couldn't find sg device corresponding to %s\n",
                    device_name);
        else {
            perror("sginfo(open)");
            fprintf(stderr, "file=%s, or no corresponding sg device found\n",
                    device_name);
            fprintf(stderr, "Is sg driver loaded?\n");
        }
        exit(1);
    }

#if 0
    if (!x_interface)
        printf("\n");
#endif
    if (! (found || mp_i.page || mp_i.subpage || inquiry_verbosity ||
           serial_number)) {
        if (trace_cmd > 0)
            fprintf(stdout, "nothing selected so do a short INQUIRY\n");
        inquiry_verbosity = 1;
    }

    status |= do_inquiry(&mp_i.peri_type, &mp_i.inq_byte6,
                         inquiry_verbosity);
    if (serial_number)
        do_serial_number();     /* ignore error */
    if (mp_i.page > 0)
        status |= do_user_page(&mp_i, decode_in_hex);
    if (defect)
        status |= read_defect_list(0);
    if (grown_defect)
        status |= read_defect_list(1);

    return status ? 1 : 0;
}

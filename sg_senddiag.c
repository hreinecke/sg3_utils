#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "sg_include.h"
#include "sg_err.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2003-2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI RECEIVE DIAGNOSTIC
   command.
*/

static char * version_str = "0.18 20040602";

#define ME "sg_senddiag: "

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */
#define LONG_TIMEOUT 3600000    /* 3,600,000 millisecs == 60 minutes */

#define SEND_DIAGNOSTIC_CMD     0x1d
#define SEND_DIAGNOSTIC_CMDLEN  6
#define RECEIVE_DIAGNOSTIC_CMD     0x1c
#define RECEIVE_DIAGNOSTIC_CMDLEN  6
#define MODE_SENSE6_CMD      0x1a
#define MODE_SENSE6_CMDLEN   6
#define MODE_SENSE10_CMD     0x5a
#define MODE_SENSE10_CMDLEN  10
#define MX_ALLOC_LEN (1024 * 4)

#define PG_CODE_ALL 0x0

#define EBUFF_SZ 256


static int do_senddiag(int sg_fd, int sf_code, int pf_bit, int sf_bit,
                       int devofl_bit, int unitofl_bit, void * outgoing_pg, 
                       int outgoing_len, int noisy)
{
    int res;
    unsigned char senddiagCmdBlk[SEND_DIAGNOSTIC_CMDLEN] = 
        {SEND_DIAGNOSTIC_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    senddiagCmdBlk[1] = (unsigned char)((sf_code << 5) | (pf_bit << 4) |
                        (sf_bit << 2) | (devofl_bit << 1) | unitofl_bit);
    senddiagCmdBlk[3] = (unsigned char)((outgoing_len >> 8) & 0xff);
    senddiagCmdBlk[4] = (unsigned char)(outgoing_len & 0xff);

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = SEND_DIAGNOSTIC_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = outgoing_len ? SG_DXFER_TO_DEV : SG_DXFER_NONE;
    io_hdr.dxfer_len = outgoing_len;
    io_hdr.dxferp = outgoing_pg;
    io_hdr.cmdp = senddiagCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = LONG_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (send diagnostic) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        return 0;
    default:
        if (noisy) {
            char ebuff[EBUFF_SZ];
            snprintf(ebuff, EBUFF_SZ, "Send diagnostic error, sf_code=0x%x, "
                     "pf_bit=%d, sf_bit=%d ", sf_code, pf_bit, sf_bit);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

static int do_rcvdiag(int sg_fd, int pcv, int pg_code, void * resp, 
                      int mx_resp_len, int noisy)
{
    int res;
    unsigned char rcvdiagCmdBlk[RECEIVE_DIAGNOSTIC_CMDLEN] = 
        {RECEIVE_DIAGNOSTIC_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    rcvdiagCmdBlk[1] = (unsigned char)(pcv ? 0x1 : 0);
    rcvdiagCmdBlk[2] = (unsigned char)(pg_code);
    rcvdiagCmdBlk[3] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    rcvdiagCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = RECEIVE_DIAGNOSTIC_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = rcvdiagCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (receive diagnostic) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        return 0;
    default:
        if (noisy) {
            char ebuff[EBUFF_SZ];
            snprintf(ebuff, EBUFF_SZ, "Receive diagnostic error, pcv=%d, "
                     "page_code=%x ", pcv, pg_code);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

/* Get expected extended self-test time from mode page 0xa (for '-e' option) */
static int do_modes_0a(int sg_fd, void * resp, int mx_resp_len, int noisy,
                       int mode6)
{
    int res;
    unsigned char modesCmdBlk[MODE_SENSE10_CMDLEN] = 
        {MODE_SENSE10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int dbd = 1;
    int pc = 0;
    int pg_code = 0xa;

    modesCmdBlk[1] = (unsigned char)(dbd ? 0x8 : 0);
    modesCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    if (mx_resp_len > (mode6 ? 0xff : 0xffff)) {
        printf( ME "mx_resp_len too big\n");
        return -1;
    }
    if(mode6) {
        modesCmdBlk[0] = MODE_SENSE6_CMD;
        modesCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
    } else {
        modesCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
        modesCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = mode6 ? MODE_SENSE6_CMDLEN : MODE_SENSE10_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = modesCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (mode sense) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        return 0;
    default:
        if (noisy) {
            char ebuff[EBUFF_SZ];
            snprintf(ebuff, EBUFF_SZ, "Mode sense error, dbd=%d, "
                     "pc=%d, page_code=%x ", dbd, pc, pg_code);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

struct page_code_desc {
        int page_code;
        const char * desc;
};
static struct page_code_desc pc_desc_arr[] = {
        {0x0, "Supported diagnostic pages"},
        {0x1, "Configuration (SES)"},
        {0x2, "Enclosure status/control (SES)"},
        {0x3, "Help text (SES)"},
        {0x4, "String In/Out (SES)"},
        {0x5, "Threshold In/Out (SES)"},
        {0x6, "Array Status/Control (SES)"},
        {0x7, "Element descriptor (SES)"},
        {0x8, "Short enclosure status (SES)"},
        {0x9, "Enclosure busy (SES-2)"},
        {0xa, "Device element status (SES-2)"},
        {0x40, "Translate address (direct access)"},
        {0x41, "Device status (direct access)"},
};

const char * find_page_code_desc(int page_num)
{
    int k;
    int num = sizeof(pc_desc_arr) / sizeof(pc_desc_arr[0]);
    const struct page_code_desc * pcdp = &pc_desc_arr[0];

    for (k = 0; k < num; ++k, ++pcdp) {
        if (page_num == pcdp->page_code)
            return pcdp->desc;
        else if (page_num < pcdp->page_code)
            return NULL;
    }
    return NULL;
}

static void list_page_codes()
{
    int k;
    int num = sizeof(pc_desc_arr) / sizeof(pc_desc_arr[0]);
    const struct page_code_desc * pcdp = &pc_desc_arr[0];

    printf("Page_Code  Description\n");
    for (k = 0; k < num; ++k, ++pcdp)
        printf(" 0x%02x      %s\n", pcdp->page_code, pcdp->desc);   
}

static void usage()
{
    printf("Usage: 'sg_senddiag [-doff] [-e] [-h] [-l] [-pf]"
           " [-s=<self_test_code>]\n"
           "                    [-t] [-uoff] [-V] [<sg_device>]'\n"
           " where -doff device online (def: 0, only with '-t')\n"
           "       -e   duration of an extended test (from mode page 0xa)\n"
           "       -h   output in hex\n"
           "       -l   list supported page codes\n"
           "       -pf  set PF bit (def: 0)\n"
           "       -s=<self_test_code> (def: 0)\n"
           "          1->background short, 2->background extended,"
           " 4->abort test\n"
           "          5->foreground short, 6->foreground extended\n"
           "       -t   default self test\n"
           "       -uoff unit online (def: 0, only with '-t')\n"
           "       -V   output version string\n"
           "       -?   output this usage message\n");
}

static void dStrHex(const char* str, int len, int no_ascii)
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
        if (no_ascii)
            buff[cpos++] = ' ';
        else {
            if ((c < ' ') || (c >= 0x7f))
                c='.';
            buff[cpos++] = c;
        }
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



int main(int argc, char * argv[])
{
    int sg_fd, k, num, rsp_len;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char rsp_buff[MX_ALLOC_LEN];
    int rsp_buff_size = MX_ALLOC_LEN;
    unsigned int u;
    int self_test_code = 0;
    int do_pf = 0;
    int do_doff = 0;
    int do_hex = 0;
    int do_list = 0;
    int do_def_test = 0;
    int do_uoff = 0;
    int do_ext_time = 0;
    int oflags = O_RDWR;

    for (k = 1; k < argc; ++k) {
        if (0 == strncmp("-s=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (u > 7)) {
                printf("Bad page code after '-s' switch\n");
                file_name = 0;
                break;
            }
            self_test_code = u;
        }
        else if (0 == strcmp("-pf", argv[k]))
            do_pf = 1;
        else if (0 == strcmp("-doff", argv[k]))
            do_doff = 1;
        else if (0 == strcmp("-h", argv[k]))
            do_hex = 1;
        else if (0 == strcmp("-l", argv[k]))
            do_list = 1;
        else if (0 == strcmp("-t", argv[k]))
            do_def_test = 1;
        else if (0 == strcmp("-uoff", argv[k]))
            do_uoff = 1;
        else if (0 == strcmp("-e", argv[k]))
            do_ext_time = 1;
        else if (0 == strcmp("-?", argv[k])) {
            usage();
            return 0;
        }
        else if (0 == strcmp("-V", argv[k])) {
            printf("Version string: %s\n", version_str);
            exit(0);
        }
        else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else if (0 == file_name)
            file_name = argv[k];
        else {
            printf("too many arguments\n");
            file_name = 0;
            break;
        }
    }
    if ((do_doff || do_uoff) && (! do_def_test)) {
        printf("setting -doff or -uoff only useful when -t is set\n");
        usage();
        return 1;
    }
    if ((self_test_code > 0) && do_def_test) {
        printf("either set -s=<num> or -t (not both)\n");
        usage();
        return 1;
    }
    if (0 == file_name) {
        if (do_list) {
            list_page_codes();
            return 0;
        }
        usage();
        return 1;
    }

    if ((sg_fd = open(file_name, oflags)) < 0) {
        snprintf(ebuff, EBUFF_SZ, ME "error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    if (do_ext_time) {
        if (0 == do_modes_0a(sg_fd, rsp_buff, 32, 1, 0)) {
            /* Assume mode sense(10) response without block descriptors */
            num = (rsp_buff[0] << 8) + rsp_buff[1] - 6;
            if (num >= 0xc) {
                int secs;

                secs = (rsp_buff[18] << 8) + rsp_buff[19];
                printf("Expected extended self-test duration=%d seconds "
                       "(%.2f minutes)\n", secs, secs / 60.0);
            } else
                printf("Extended self-test duration not available\n");
        } else
            printf("Extended self-test duration (mode page 0xa) failed\n");
        return 0;
    }
    if (do_list) {
        memset(rsp_buff, 0, sizeof(rsp_buff));
        if (0 == do_senddiag(sg_fd, 0, do_pf, 0, 0, 0, rsp_buff, 4, 1)) {
            if (0 == do_rcvdiag(sg_fd, 0, 0, rsp_buff, rsp_buff_size, 1)) {
                printf("Supported diagnostic pages response:\n");
                rsp_len = (rsp_buff[2] << 8) + rsp_buff[3] + 4;
                if (do_hex)
                    dStrHex((const char *)rsp_buff, rsp_len, 1);
                else {
                    for (k = 0; k < (rsp_len - 4); ++k)
                        printf("  %s\n", find_page_code_desc(rsp_buff[k + 4]));
                }
            }
        }
    } 
    else if (0 == do_senddiag(sg_fd, self_test_code, do_pf, do_def_test, 
                              do_doff, do_uoff, NULL, 0, 1)) {
        if ((5 == self_test_code) || (6 == self_test_code))
            printf("Foreground self test returned GOOD status\n");
        else if (do_def_test && (! do_doff) && (! do_uoff))
            printf("Default self test returned GOOD status\n");
    }
    close(sg_fd);
    return 0;
}

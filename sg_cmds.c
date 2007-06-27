/*
 * Copyright (c) 1999-2004 Douglas Gilbert.
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
 * CONTENTS
 *    Some SCSI commands are executed in many contexts and hence began
 *    to appear in several sg3_utils utilities. This files centralizes
 *    some of the low level command execution code. In most cases the
 *    interpretation of the command response is left to the each
 *    utility.
 *    One example is the SCSI INQUIRY command which is often required
 *    to identify and categorize (e.g. disk, tape or enclosure device)
 *    a SCSI target device.
 * CHANGELOG
 *      v1.00 (20041018)
 *        fetch low level command execution code from other utilities
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

static char * version_str = "1.00 20041019";


#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */
#define EBUFF_SZ 256

#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define SYNCHRONIZE_CACHE_CMD     0x35
#define SYNCHRONIZE_CACHE_CMDLEN  10
#define SERVICE_ACTION_IN_16_CMD 0x9e
#define SERVICE_ACTION_IN_16_CMDLEN 16
#define READ_CAPACITY_16_SA 0x10
#define READ_CAPACITY_10_CMD 0x25
#define READ_CAPACITY_10_CMDLEN 0x10
#define MODE_SENSE6_CMD      0x1a
#define MODE_SENSE6_CMDLEN   6
#define MODE_SENSE10_CMD     0x5a
#define MODE_SENSE10_CMDLEN  10
#define MODE_SELECT6_CMD   0x15
#define MODE_SELECT6_CMDLEN   6
#define MODE_SELECT10_CMD   0x55
#define MODE_SELECT10_CMDLEN  10
#define REQUEST_SENSE_CMD 0x3
#define REQUEST_SENSE_CMDLEN 6

#define MODE6_RESP_HDR_LEN 4
#define MODE10_RESP_HDR_LEN 8


const char * sg_cmds_version()
{
    return version_str;
}

/* Invokes a SCSI INQUIRY command and yields the response */
/* Returns 0 when successful, -1 -> SG_IO ioctl failed, -2 -> bad response */
int sg_ll_inquiry(int sg_fd, int cmddt, int evpd, int pg_op, 
                  void * resp, int mx_resp_len, int noisy, int verbose)
{
    int res, k;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (cmddt)
        inqCmdBlk[1] |= 2;
    if (evpd)
        inqCmdBlk[1] |= 1;
    inqCmdBlk[2] = (unsigned char)pg_op;
    /* 16 bit allocation length (was 8) is a recent SPC-3 addition */
    inqCmdBlk[3] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    inqCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (verbose) {
        fprintf(sg_warnings_str, "    inquiry cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", inqCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inqCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = inqCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        if (noisy || verbose)
            fprintf(sg_warnings_str, "SG_IO (inquiry) error: %s\n",
                    safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_RECOVERED:
        if (verbose && io_hdr.resid)
            fprintf(sg_warnings_str, "    inquiry: resid=%d\n", io_hdr.resid);
        return 0;
    default:
        if (noisy || verbose) {
            char ebuff[EBUFF_SZ];

            snprintf(ebuff, EBUFF_SZ, "Inquiry error, CmdDt=%d, "
                     "VPD=%d, page_opcode=%x ", cmddt, evpd, pg_op);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -2;
    }
}

/* Yields most of first 36 bytes of a standard INQUIRY (evpd==0) response. */
/* Returns 0 when successful, -1 -> SG_IO ioctl failed, -2 -> bad response */
int sg_simple_inquiry(int sg_fd, struct sg_simple_inquiry_resp * inq_data,
                      int noisy, int verbose)
{
    int res, k;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    unsigned char inq_resp[36];

    if (inq_data) {
        memset(inq_data, 0, sizeof(* inq_data));
        inq_data->peripheral_qualifier = 0x3;
        inq_data->peripheral_type = 0x1f;
    }
    inqCmdBlk[4] = (unsigned char)sizeof(inq_resp);
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (verbose) {
        fprintf(sg_warnings_str, "        inquiry cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", inqCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inqCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = sizeof(inq_resp);
    io_hdr.dxferp = inq_resp;
    io_hdr.cmdp = inqCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(sg_warnings_str, "SG_IO (inquiry) error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_RECOVERED:
        if (inq_data) {
            inq_data->peripheral_qualifier = (inq_resp[0] >> 5) & 0x7;
            inq_data->peripheral_type = inq_resp[0] & 0x1f;
            inq_data->rmb = (inq_resp[1] & 0x80) ? 1 : 0;
            inq_data->version = inq_resp[2];
            inq_data->byte_3 = inq_resp[3];
            inq_data->byte_5 = inq_resp[5];
            inq_data->byte_6 = inq_resp[6];
            inq_data->byte_7 = inq_resp[7];
            memcpy(inq_data->vendor, inq_resp + 8, 8);
            memcpy(inq_data->product, inq_resp + 16, 16);
            memcpy(inq_data->revision, inq_resp + 32, 4);
        }
        if (verbose && io_hdr.resid)
            fprintf(sg_warnings_str, "    inquiry: resid=%d\n", io_hdr.resid);
        return 0;
    default:
        if (noisy) {
            char ebuff[EBUFF_SZ];

            snprintf(ebuff, EBUFF_SZ, "Inquiry error ");
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -2;
    }
}

/* Invokes a SCSI SYNCHRONIZE CACHE (10) command */
/* Return of 0 -> success, -1 -> failure, 2 -> try again */
int sg_ll_sync_cache(int sg_fd, int sync_nv, int immed, int verbose)
{
    int res, k;
    unsigned char scCmdBlk[SYNCHRONIZE_CACHE_CMDLEN] =
                {SYNCHRONIZE_CACHE_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (sync_nv)
        scCmdBlk[1] |= 4;
    if (immed)
        scCmdBlk[1] |= 2;
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (verbose) {
        fprintf(sg_warnings_str, "        synchronize cache cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", scCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(scCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.dxfer_len = 0;
    io_hdr.dxferp = NULL;
    io_hdr.cmdp = scCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(sg_warnings_str, "synchronize_cache (SG_IO) error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    if (SG_LIB_CAT_MEDIA_CHANGED == res)
        return 2; /* probably have another go ... */
    else if (SG_LIB_CAT_INVALID_OP == res)
        return res;
    else if (SG_LIB_CAT_CLEAN != res) {
        sg_chk_n_print3("synchronize cache", &io_hdr);
        return -1;
    }
    return 0;
}


/* Invokes a SCSI READ CAPACITY (16) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, 2 -> media changed,
 * -1 -> other failure */
int sg_ll_readcap_16(int sg_fd, int pmi, unsigned long long llba, 
                     void * resp, int mx_resp_len, int verbose)
{
    int k, res;
    unsigned char rcCmdBlk[SERVICE_ACTION_IN_16_CMDLEN] = 
                        {SERVICE_ACTION_IN_16_CMD, READ_CAPACITY_16_SA, 
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (pmi) { /* lbs only valid when pmi set */
        rcCmdBlk[14] |= 1;
        rcCmdBlk[2] = (llba >> 56) & 0xff;
        rcCmdBlk[3] = (llba >> 48) & 0xff;
        rcCmdBlk[4] = (llba >> 40) & 0xff;
        rcCmdBlk[5] = (llba >> 32) & 0xff;
        rcCmdBlk[6] = (llba >> 24) & 0xff;
        rcCmdBlk[7] = (llba >> 16) & 0xff;
        rcCmdBlk[8] = (llba >> 8) & 0xff;
        rcCmdBlk[9] = llba & 0xff;
    }
    rcCmdBlk[13] = 12;  /* Allocation length */
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (verbose) {
        fprintf(sg_warnings_str, "        read capacity (16) cdb: ");
        for (k = 0; k < SERVICE_ACTION_IN_16_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", rcCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rcCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = rcCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(sg_warnings_str, "read_capacity16 (SG_IO) error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_RECOVERED:
        if (verbose && io_hdr.resid)
            fprintf(sg_warnings_str, "    read_capacity16: resid=%d\n",
                    io_hdr.resid);
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        return res;
    case SG_LIB_CAT_MEDIA_CHANGED:
        return 2;
    default:
        sg_chk_n_print3("READ CAPACITY 16 command error", &io_hdr);
        return -1;
    }
}

/* Invokes a SCSI READ CAPACITY (10) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, 2 -> media changed,
 * -1 -> other failure */
int sg_ll_readcap_10(int sg_fd, int pmi, unsigned int lba, 
                     void * resp, int mx_resp_len, int verbose)
{
    int k, res;
    unsigned char rcCmdBlk[READ_CAPACITY_10_CMDLEN] =
                         {READ_CAPACITY_10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (pmi) { /* lbs only valid when pmi set */
        rcCmdBlk[8] |= 1;
        rcCmdBlk[2] = (lba >> 24) & 0xff;
        rcCmdBlk[3] = (lba >> 16) & 0xff;
        rcCmdBlk[4] = (lba >> 8) & 0xff;
        rcCmdBlk[5] = lba & 0xff;
    }
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (verbose) {
        fprintf(sg_warnings_str, "        read capacity (10) cdb: ");
        for (k = 0; k < READ_CAPACITY_10_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", rcCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rcCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;     /* should be 8 */
    io_hdr.dxferp = resp;
    io_hdr.cmdp = rcCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(sg_warnings_str, "read_capacity (10) (SG_IO) error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_RECOVERED:
        if (verbose && io_hdr.resid)
            fprintf(sg_warnings_str, "    read_capacity16: resid=%d\n",
                    io_hdr.resid);
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        return res;
    case SG_LIB_CAT_MEDIA_CHANGED:
        return 2;
    default:
        sg_chk_n_print3("READ CAPACITY 10 command error", &io_hdr);
        return -1;
    }
}

/* Invokes a SCSI MODE SENSE (6) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, -1 -> other failure */
int sg_ll_mode_sense6(int sg_fd, int dbd, int pc, int pg_code, int sub_pg_code,
                      void * resp, int mx_resp_len, int noisy, int verbose)
{
    int res, k;
    unsigned char modesCmdBlk[MODE_SENSE6_CMDLEN] = 
        {MODE_SENSE6_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    modesCmdBlk[1] = (unsigned char)(dbd ? 0x8 : 0);
    modesCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    modesCmdBlk[3] = (unsigned char)(sub_pg_code & 0xff);
    modesCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (mx_resp_len > 0xff) {
        fprintf(sg_warnings_str, "mx_resp_len too big\n");
        return -1;
    }
    if (verbose) {
        fprintf(sg_warnings_str, "    mode sense (6) cdb: ");
        for (k = 0; k < MODE_SENSE6_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", modesCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    memset(sense_b, 0, sizeof(sense_b));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = MODE_SENSE6_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = modesCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(sg_warnings_str, "mode sense (6) SG_IO error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_RECOVERED:
        if (verbose && io_hdr.resid)
            fprintf(sg_warnings_str, "    mode sense (6): resid=%d\n",
                    io_hdr.resid);
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        return res;
    default:
        if (noisy | verbose) {
            char ebuff[EBUFF_SZ];

            snprintf(ebuff, EBUFF_SZ, "Mode sense (6) error, dbd=%d "
                    "pc=%d page_code=%x sub_page_code=%x\n     ", dbd,
                    pc, pg_code, sub_pg_code);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

/* Invokes a SCSI MODE SENSE (10) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, -1 -> other failure */
int sg_ll_mode_sense10(int sg_fd, int dbd, int pc, int pg_code,
                       int sub_pg_code, void * resp, int mx_resp_len,
                       int noisy, int verbose)
{
    int res, k;
    unsigned char modesCmdBlk[MODE_SENSE10_CMDLEN] = 
        {MODE_SENSE10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    modesCmdBlk[1] = (unsigned char)(dbd ? 0x8 : 0);
    modesCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    modesCmdBlk[3] = (unsigned char)(sub_pg_code & 0xff);
    modesCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    modesCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (mx_resp_len > 0xffff) {
        fprintf(sg_warnings_str, "mx_resp_len too big\n");
        return -1;
    }
    if (verbose) {
        fprintf(sg_warnings_str, "    mode sense (10) cdb: ");
        for (k = 0; k < MODE_SENSE10_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", modesCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    memset(sense_b, 0, sizeof(sense_b));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = MODE_SENSE10_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = modesCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(sg_warnings_str, "mode sense (10) SG_IO error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_RECOVERED:
        if (verbose && io_hdr.resid)
            fprintf(sg_warnings_str, "    mode sense (10): resid=%d\n",
                    io_hdr.resid);
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        return res;
    default:
        if (noisy | verbose) {
            char ebuff[EBUFF_SZ];

            snprintf(ebuff, EBUFF_SZ, "Mode sense (10) error, dbd=%d "
                    "pc=%d page_code=%x sub_page_code=%x\n     ", dbd,
                    pc, pg_code, sub_pg_code);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

/* Invokes a SCSI MODE SELECT (6) command.  Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, -1 -> other failure */
int sg_ll_mode_select6(int sg_fd, int pf, int sp, void * paramp,
                       int param_len, int noisy, int verbose)
{
    int res, k;
    unsigned char modesCmdBlk[MODE_SELECT6_CMDLEN] = 
        {MODE_SELECT6_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    modesCmdBlk[1] = (unsigned char)(((pf << 4) & 0x10) | (sp & 0x1));
    modesCmdBlk[4] = (unsigned char)(param_len & 0xff);
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (param_len > 0xff) {
        fprintf(sg_warnings_str, "mode select (6): param_len too big\n");
        return -1;
    }
    if (verbose) {
        fprintf(sg_warnings_str, "    mode select (6) cdb: ");
        for (k = 0; k < MODE_SELECT6_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", modesCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }
    if (verbose > 1) {
        fprintf(sg_warnings_str, "    mode select (6) parameter block\n");
        dStrHex((const char *)paramp, param_len, -1);
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    memset(sense_b, 0, sizeof(sense_b));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = MODE_SELECT6_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = param_len;
    io_hdr.dxferp = paramp;
    io_hdr.cmdp = modesCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(sg_warnings_str, "mode select (6) SG_IO error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_RECOVERED:
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        return res;
    default:
        if (noisy | verbose) {
            char ebuff[EBUFF_SZ];

            snprintf(ebuff, EBUFF_SZ, "Mode select (6) error, pf=%d "
                    "sp=%d\n     ", pf, sp);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

/* Invokes a SCSI MODE SELECT (10) command.  Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, -1 -> other failure */
int sg_ll_mode_select10(int sg_fd, int pf, int sp, void * paramp,
                       int param_len, int noisy, int verbose)
{
    int res, k;
    unsigned char modesCmdBlk[MODE_SELECT10_CMDLEN] = 
        {MODE_SELECT10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    modesCmdBlk[1] = (unsigned char)(((pf << 4) & 0x10) | (sp & 0x1));
    modesCmdBlk[7] = (unsigned char)((param_len >> 8) & 0xff);
    modesCmdBlk[8] = (unsigned char)(param_len & 0xff);
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (param_len > 0xffff) {
        fprintf(sg_warnings_str, "mode select (10): param_len too big\n");
        return -1;
    }
    if (verbose) {
        fprintf(sg_warnings_str, "    mode select (10) cdb: ");
        for (k = 0; k < MODE_SELECT10_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", modesCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }
    if (verbose > 1) {
        fprintf(sg_warnings_str, "    mode select (10) parameter block\n");
        dStrHex((const char *)paramp, param_len, -1);
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    memset(sense_b, 0, sizeof(sense_b));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = MODE_SELECT10_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = param_len;
    io_hdr.dxferp = paramp;
    io_hdr.cmdp = modesCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(sg_warnings_str, "mode select (10) SG_IO error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_CLEAN:
    case SG_LIB_CAT_RECOVERED:
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        return res;
    default:
        if (noisy | verbose) {
            char ebuff[EBUFF_SZ];

            snprintf(ebuff, EBUFF_SZ, "Mode select (10) error, pf=%d "
                    "sp=%d\n     ", pf, sp);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

/* MODE SENSE commands yield a response that has block descriptors followed
 * by mode pages. In most cases users are interested in the first mode page.
 * This function returns the (byte) offset of the start of the first mode
 * page. Set mode_sense_6 to 1 for MODE SENSE (6) and 0 for MODE SENSE (10).
 * Returns >= 0 is successful or -1 if failure. If there is a failure
 * a message is written to err_buff. */
int sg_mode_page_offset(const unsigned char * resp, int resp_len,
                        int mode_sense_6, char * err_buff, int err_buff_len)
{
    int bd_len;
    int calc_len;
    int offset;

    if ((NULL == resp) || (resp_len < 4) ||
        ((! mode_sense_6) && (resp_len < 8))) {
        snprintf(err_buff, err_buff_len, "given response length too short: "
                 "%d\n", resp_len);
        return -1;
    }
    if (mode_sense_6) {
        calc_len = resp[0] + 1;
        bd_len = resp[3];
        offset = bd_len + MODE6_RESP_HDR_LEN;
    } else {
        calc_len = (resp[0] << 8) + resp[1] + 2;
        bd_len = (resp[6] << 8) + resp[7];
        /* LongLBA doesn't change this calculation */
        offset = bd_len + MODE10_RESP_HDR_LEN;
    }
    if ((offset + 2) > resp_len) {
        snprintf(err_buff, err_buff_len, "given response length "
                 "too small, offset=%d given_len=%d bd_len=%d\n",
                 offset, resp_len, bd_len);
         offset = -1;
    } else if ((offset + 2) > calc_len) {
        snprintf(err_buff, err_buff_len, "calculated response "
                 "length too small, offset=%d calc_len=%d bd_len=%d\n",
                 offset, calc_len, bd_len);
        offset = -1;
    }
    return offset;
}

/* Invokes a SCSI REQUEST SENSE command */
/* Return of 0 -> success, SG_LIB_CAT_INVALID_OP -> Request Sense not
 *  supported??, -1 -> other failure */
int sg_ll_request_sense(int sg_fd, int desc, void * resp, int mx_resp_len,
                        int verbose)
{
    int k;
    unsigned char rsCmdBlk[REQUEST_SENSE_CMDLEN] = 
        {REQUEST_SENSE_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (desc)
        rsCmdBlk[1] |= 0x1;
    if (NULL == sg_warnings_str)
        sg_warnings_str = stderr;
    if (verbose) {
        fprintf(sg_warnings_str, "    Request Sense cmd: ");
        for (k = 0; k < REQUEST_SENSE_CMDLEN; ++k)
            fprintf(sg_warnings_str, "%02x ", rsCmdBlk[k]);
        fprintf(sg_warnings_str, "\n");
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = REQUEST_SENSE_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = rsCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(sg_warnings_str, "request sense SG_IO error: %s\n",
                safe_strerror(errno));
        return -1;
    }

    /* shouldn't get errors on Request Sense but it is best to be safe */
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        if (verbose && io_hdr.resid)
            fprintf(sg_warnings_str, "    request sense: resid=%d\n",
                    io_hdr.resid);
        return 0;
    case SG_LIB_CAT_RECOVERED:
        fprintf(sg_warnings_str, "Recovered error on REQUEST SENSE command, "
                "continuing\n");
        if (verbose && io_hdr.resid)
            fprintf(sg_warnings_str, "    request sense: resid=%d\n",
                    io_hdr.resid);
        return 0;
    case SG_LIB_CAT_INVALID_OP:
        return SG_LIB_CAT_INVALID_OP;
    default:
        sg_chk_n_print3("REQUEST SENSE command problem", &io_hdr);
        return -1;
    }
}

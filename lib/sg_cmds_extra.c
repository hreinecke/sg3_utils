/*
 * Copyright (c) 1999-2016 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_pt.h"
#include "sg_unaligned.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */

#define DEF_PT_TIMEOUT 60       /* 60 seconds */
#define LONG_PT_TIMEOUT 7200    /* 7,200 seconds == 120 minutes */

#define SERVICE_ACTION_IN_16_CMD 0x9e
#define SERVICE_ACTION_IN_16_CMDLEN 16
#define SERVICE_ACTION_OUT_16_CMD 0x9f
#define SERVICE_ACTION_OUT_16_CMDLEN 16
#define MAINTENANCE_IN_CMD 0xa3
#define MAINTENANCE_IN_CMDLEN 12
#define MAINTENANCE_OUT_CMD 0xa4
#define MAINTENANCE_OUT_CMDLEN 12

#define ATA_PT_12_CMD 0xa1
#define ATA_PT_12_CMDLEN 12
#define ATA_PT_16_CMD 0x85
#define ATA_PT_16_CMDLEN 16
#define FORMAT_UNIT_CMD 0x4
#define FORMAT_UNIT_CMDLEN 6
#define PERSISTENT_RESERVE_IN_CMD 0x5e
#define PERSISTENT_RESERVE_IN_CMDLEN 10
#define PERSISTENT_RESERVE_OUT_CMD 0x5f
#define PERSISTENT_RESERVE_OUT_CMDLEN 10
#define READ_BLOCK_LIMITS_CMD 0x5
#define READ_BLOCK_LIMITS_CMDLEN 6
#define READ_BUFFER_CMD 0x3c
#define READ_BUFFER_CMDLEN 10
#define READ_DEFECT10_CMD     0x37
#define READ_DEFECT10_CMDLEN    10
#define REASSIGN_BLKS_CMD     0x7
#define REASSIGN_BLKS_CMDLEN  6
#define RECEIVE_DIAGNOSTICS_CMD   0x1c
#define RECEIVE_DIAGNOSTICS_CMDLEN  6
#define THIRD_PARTY_COPY_OUT_CMD 0x83   /* was EXTENDED_COPY_CMD */
#define THIRD_PARTY_COPY_OUT_CMDLEN 16
#define THIRD_PARTY_COPY_IN_CMD 0x84     /* was RECEIVE_COPY_RESULTS_CMD */
#define THIRD_PARTY_COPY_IN_CMDLEN 16
#define SEND_DIAGNOSTIC_CMD   0x1d
#define SEND_DIAGNOSTIC_CMDLEN  6
#define SERVICE_ACTION_IN_12_CMD 0xab
#define SERVICE_ACTION_IN_12_CMDLEN 12
#define READ_LONG10_CMD 0x3e
#define READ_LONG10_CMDLEN 10
#define UNMAP_CMD 0x42
#define UNMAP_CMDLEN 10
#define VERIFY10_CMD 0x2f
#define VERIFY10_CMDLEN 10
#define VERIFY16_CMD 0x8f
#define VERIFY16_CMDLEN 16
#define WRITE_LONG10_CMD 0x3f
#define WRITE_LONG10_CMDLEN 10
#define WRITE_BUFFER_CMD 0x3b
#define WRITE_BUFFER_CMDLEN 10

#define GET_LBA_STATUS_SA 0x12
#define READ_LONG_16_SA 0x11
#define READ_MEDIA_SERIAL_NUM_SA 0x1
#define REPORT_IDENTIFYING_INFORMATION_SA 0x5
#define REPORT_TGT_PRT_GRP_SA 0xa
#define SET_IDENTIFYING_INFORMATION_SA 0x6
#define SET_TGT_PRT_GRP_SA 0xa
#define WRITE_LONG_16_SA 0x11
#define REPORT_REFERRALS_SA 0x13
#define EXTENDED_COPY_LID1_SA 0x0

#if defined(__GNUC__) || defined(__clang__)
static int pr2ws(const char * fmt, ...)
        __attribute__ ((format (printf, 1, 2)));
#else
static int pr2ws(const char * fmt, ...);
#endif


static int
pr2ws(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(sg_warnings_strm ? sg_warnings_strm : stderr, fmt, args);
    va_end(args);
    return n;
}


/* Invokes a SCSI GET LBA STATUS command (SBC). Returns 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_get_lba_status(int sg_fd, uint64_t start_llba, void * resp,
                     int alloc_len, int noisy, int verbose)
{
    int k, res, sense_cat, ret;
    unsigned char getLbaStatCmd[SERVICE_ACTION_IN_16_CMDLEN];
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    memset(getLbaStatCmd, 0, sizeof(getLbaStatCmd));
    getLbaStatCmd[0] = SERVICE_ACTION_IN_16_CMD;
    getLbaStatCmd[1] = GET_LBA_STATUS_SA;

    sg_put_unaligned_be64(start_llba, getLbaStatCmd + 2);
    sg_put_unaligned_be32((uint32_t)alloc_len, getLbaStatCmd + 10);
    if (verbose) {
        pr2ws("    Get LBA status cmd: ");
        for (k = 0; k < SERVICE_ACTION_IN_16_CMDLEN; ++k)
            pr2ws("%02x ", getLbaStatCmd[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("get LBA status: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, getLbaStatCmd, sizeof(getLbaStatCmd));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, alloc_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "get LBA status", res, alloc_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    get LBA status: response\n");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

int
sg_ll_report_tgt_prt_grp(int sg_fd, void * resp, int mx_resp_len,
                         int noisy, int verbose)
{
    return sg_ll_report_tgt_prt_grp2(sg_fd, resp, mx_resp_len, 0, noisy,
                                     verbose);
}

/* Invokes a SCSI REPORT TARGET PORT GROUPS command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_report_tgt_prt_grp2(int sg_fd, void * resp, int mx_resp_len,
                          int extended, int noisy, int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char rtpgCmdBlk[MAINTENANCE_IN_CMDLEN] =
                         {MAINTENANCE_IN_CMD, REPORT_TGT_PRT_GRP_SA,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (extended) {
        rtpgCmdBlk[1] |= 0x20;
    }
    sg_put_unaligned_be32((uint32_t)mx_resp_len, rtpgCmdBlk + 6);
    if (verbose) {
        pr2ws("    report target port groups cdb: ");
        for (k = 0; k < MAINTENANCE_IN_CMDLEN; ++k)
            pr2ws("%02x ", rtpgCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("report target port groups: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rtpgCmdBlk, sizeof(rtpgCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "report target port group", res,
                               mx_resp_len, sense_b, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    report target port group: response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI SET TARGET PORT GROUPS command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_set_tgt_prt_grp(int sg_fd, void * paramp, int param_len, int noisy,
                      int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char stpgCmdBlk[MAINTENANCE_OUT_CMDLEN] =
                         {MAINTENANCE_OUT_CMD, SET_TGT_PRT_GRP_SA,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be32((uint32_t)param_len, stpgCmdBlk + 6);
    if (verbose) {
        pr2ws("    set target port groups cdb: ");
        for (k = 0; k < MAINTENANCE_OUT_CMDLEN; ++k)
            pr2ws("%02x ", stpgCmdBlk[k]);
        pr2ws("\n");
        if ((verbose > 1) && paramp && param_len) {
            pr2ws("    set target port groups parameter list:\n");
            dStrHexErr((const char *)paramp, param_len, -1);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("set target port groups: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, stpgCmdBlk, sizeof(stpgCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "set target port group", res, 0,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI REPORT REFERRALS command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_report_referrals(int sg_fd, uint64_t start_llba, int one_seg,
                       void * resp, int mx_resp_len, int noisy,
                       int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char repRefCmdBlk[SERVICE_ACTION_IN_16_CMDLEN] =
                         {SERVICE_ACTION_IN_16_CMD, REPORT_REFERRALS_SA,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be64(start_llba, repRefCmdBlk + 2);
    sg_put_unaligned_be32((uint32_t)mx_resp_len, repRefCmdBlk + 10);
    repRefCmdBlk[14] = one_seg & 0x1;
    if (verbose) {
        pr2ws("    report referrals cdb: ");
        for (k = 0; k < SERVICE_ACTION_IN_16_CMDLEN; ++k)
            pr2ws("%02x ", repRefCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("report target port groups: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, repRefCmdBlk, sizeof(repRefCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "report referrals", res,
                               mx_resp_len, sense_b, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    report referrals: response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI SEND DIAGNOSTIC command. Foreground, extended self tests can
 * take a long time, if so set long_duration flag in which case the timeout
 * is set to 7200 seconds; if the value of long_duration is > 7200 then that
 * value is taken as the timeout value in seconds. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_send_diag(int sg_fd, int sf_code, int pf_bit, int sf_bit, int devofl_bit,
                int unitofl_bit, int long_duration, void * paramp,
                int param_len, int noisy, int verbose)
{
    int k, res, ret, sense_cat, tmout;
    unsigned char senddiagCmdBlk[SEND_DIAGNOSTIC_CMDLEN] =
        {SEND_DIAGNOSTIC_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    senddiagCmdBlk[1] = (unsigned char)((sf_code << 5) | (pf_bit << 4) |
                        (sf_bit << 2) | (devofl_bit << 1) | unitofl_bit);
    sg_put_unaligned_be16((uint16_t)param_len, senddiagCmdBlk + 3);
    if (long_duration > LONG_PT_TIMEOUT)
        tmout = long_duration;
    else
        tmout = long_duration ? LONG_PT_TIMEOUT : DEF_PT_TIMEOUT;

    if (verbose) {
        pr2ws("    Send diagnostic cmd: ");
        for (k = 0; k < SEND_DIAGNOSTIC_CMDLEN; ++k)
            pr2ws("%02x ", senddiagCmdBlk[k]);
        pr2ws("\n");
        if (verbose > 1) {
            if (paramp && param_len) {
                pr2ws("    Send diagnostic parameter list:\n");
                dStrHexErr((const char *)paramp, param_len, -1);
            }
            pr2ws("    Send diagnostic timeout: %d seconds\n", tmout);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("send diagnostic: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, senddiagCmdBlk, sizeof(senddiagCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, tmout, verbose);
    ret = sg_cmds_process_resp(ptvp, "send diagnostic", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI RECEIVE DIAGNOSTIC RESULTS command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_receive_diag(int sg_fd, int pcv, int pg_code, void * resp,
                   int mx_resp_len, int noisy, int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char rcvdiagCmdBlk[RECEIVE_DIAGNOSTICS_CMDLEN] =
        {RECEIVE_DIAGNOSTICS_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    rcvdiagCmdBlk[1] = (unsigned char)(pcv ? 0x1 : 0);
    rcvdiagCmdBlk[2] = (unsigned char)(pg_code);
    sg_put_unaligned_be16((uint16_t)mx_resp_len, rcvdiagCmdBlk + 3);

    if (verbose) {
        pr2ws("    Receive diagnostic results cmd: ");
        for (k = 0; k < RECEIVE_DIAGNOSTICS_CMDLEN; ++k)
            pr2ws("%02x ", rcvdiagCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("receive diagnostic results: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rcvdiagCmdBlk, sizeof(rcvdiagCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "receive diagnostic results", res,
                               mx_resp_len, sense_b, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    receive diagnostic results: response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI READ DEFECT DATA (10) command (SBC). Return of 0 -> success
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_read_defect10(int sg_fd, int req_plist, int req_glist, int dl_format,
                    void * resp, int mx_resp_len, int noisy, int verbose)
{
    int res, k, ret, sense_cat;
    unsigned char rdefCmdBlk[READ_DEFECT10_CMDLEN] =
        {READ_DEFECT10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    rdefCmdBlk[2] = (unsigned char)(((req_plist << 4) & 0x10) |
                         ((req_glist << 3) & 0x8) | (dl_format & 0x7));
    sg_put_unaligned_be16((uint16_t)mx_resp_len, rdefCmdBlk + 7);
    if (mx_resp_len > 0xffff) {
        pr2ws("mx_resp_len too big\n");
        return -1;
    }
    if (verbose) {
        pr2ws("    read defect (10) cdb: ");
        for (k = 0; k < READ_DEFECT10_CMDLEN; ++k)
            pr2ws("%02x ", rdefCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("read defect (10): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rdefCmdBlk, sizeof(rdefCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "read defect (10)", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    read defect (10): response\n");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI READ MEDIA SERIAL NUMBER command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_read_media_serial_num(int sg_fd, void * resp, int mx_resp_len,
                            int noisy, int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char rmsnCmdBlk[SERVICE_ACTION_IN_12_CMDLEN] =
                         {SERVICE_ACTION_IN_12_CMD, READ_MEDIA_SERIAL_NUM_SA,
                          0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be32((uint32_t)mx_resp_len, rmsnCmdBlk + 6);
    if (verbose) {
        pr2ws("    read media serial number cdb: ");
        for (k = 0; k < SERVICE_ACTION_IN_12_CMDLEN; ++k)
            pr2ws("%02x ", rmsnCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("read media serial number: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rmsnCmdBlk, sizeof(rmsnCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "read media serial number", res,
                               mx_resp_len, sense_b, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    read media serial number: response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI REPORT IDENTIFYING INFORMATION command. This command was
 * called REPORT DEVICE IDENTIFIER prior to spc4r07. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_report_id_info(int sg_fd, int itype, void * resp, int max_resp_len,
                     int noisy, int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char riiCmdBlk[MAINTENANCE_IN_CMDLEN] = {MAINTENANCE_IN_CMD,
                        REPORT_IDENTIFYING_INFORMATION_SA,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be32((uint32_t)max_resp_len, riiCmdBlk + 6);
    riiCmdBlk[10] |= (itype << 1) & 0xfe;

    if (verbose) {
        pr2ws("    Report identifying information cdb: ");
        for (k = 0; k < MAINTENANCE_IN_CMDLEN; ++k)
            pr2ws("%02x ", riiCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("report identifying information: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, riiCmdBlk, sizeof(riiCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, max_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "report identifying information", res,
                               max_resp_len, sense_b, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    report identifying information: response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI SET IDENTIFYING INFORMATION command. This command was
 * called SET DEVICE IDENTIFIER prior to spc4r07. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_set_id_info(int sg_fd, int itype, void * paramp, int param_len,
                  int noisy, int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char siiCmdBlk[MAINTENANCE_OUT_CMDLEN] = {MAINTENANCE_OUT_CMD,
                         SET_IDENTIFYING_INFORMATION_SA,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    sg_put_unaligned_be32((uint32_t)param_len, siiCmdBlk + 6);
    siiCmdBlk[10] |= (itype << 1) & 0xfe;
    if (verbose) {
        pr2ws("    Set identifying information cdb: ");
        for (k = 0; k < MAINTENANCE_OUT_CMDLEN; ++k)
            pr2ws("%02x ", siiCmdBlk[k]);
        pr2ws("\n");
        if ((verbose > 1) && paramp && param_len) {
            pr2ws("    Set identifying information parameter list:\n");
            dStrHexErr((const char *)paramp, param_len, -1);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("Set identifying information: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, siiCmdBlk, sizeof(siiCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "set identifying information", res, 0,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a FORMAT UNIT (SBC-3) command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_format_unit(int sg_fd, int fmtpinfo, int longlist, int fmtdata,
                  int cmplst, int dlist_format, int timeout_secs,
                  void * paramp, int param_len, int noisy, int verbose)
{
    return sg_ll_format_unit2(sg_fd, fmtpinfo, longlist, fmtdata, cmplst,
                              dlist_format, 0, timeout_secs, paramp,
                              param_len, noisy, verbose);
}

/* Invokes a FORMAT UNIT (SBC-4) command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors.
 * FFMT field added in sbc4r10 [20160121] */
int
sg_ll_format_unit2(int sg_fd, int fmtpinfo, int longlist, int fmtdata,
                   int cmplst, int dlist_format, int ffmt, int timeout_secs,
                   void * paramp, int param_len, int noisy, int verbose)
{
    int k, res, ret, sense_cat, tmout;
    unsigned char fuCmdBlk[FORMAT_UNIT_CMDLEN] =
                {FORMAT_UNIT_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (fmtpinfo)
        fuCmdBlk[1] |= (fmtpinfo << 6);
    if (longlist)
        fuCmdBlk[1] |= 0x20;
    if (fmtdata)
        fuCmdBlk[1] |= 0x10;
    if (cmplst)
        fuCmdBlk[1] |= 0x8;
    if (dlist_format)
        fuCmdBlk[1] |= (dlist_format & 0x7);
    if (ffmt)
        fuCmdBlk[4] |= (ffmt & 0x3);
    tmout = (timeout_secs > 0) ? timeout_secs : DEF_PT_TIMEOUT;
    if (verbose) {
        pr2ws("    format unit cdb: ");
        for (k = 0; k < 6; ++k)
            pr2ws("%02x ", fuCmdBlk[k]);
        pr2ws("\n");
        if (verbose > 1) {
            if (param_len > 0) {
                pr2ws("    format unit parameter list:\n");
                dStrHexErr((const char *)paramp, param_len, -1);
            }
            pr2ws("    format unit timeout: %d seconds\n", tmout);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("format unit: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, fuCmdBlk, sizeof(fuCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, tmout, verbose);
    ret = sg_cmds_process_resp(ptvp, "format unit", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI REASSIGN BLOCKS command.  Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_reassign_blocks(int sg_fd, int longlba, int longlist, void * paramp,
                      int param_len, int noisy, int verbose)
{
    int res, k, ret, sense_cat;
    unsigned char reassCmdBlk[REASSIGN_BLKS_CMDLEN] =
        {REASSIGN_BLKS_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    reassCmdBlk[1] = (unsigned char)(((longlba << 1) & 0x2) |
                     (longlist & 0x1));
    if (verbose) {
        pr2ws("    reassign blocks cdb: ");
        for (k = 0; k < REASSIGN_BLKS_CMDLEN; ++k)
            pr2ws("%02x ", reassCmdBlk[k]);
        pr2ws("\n");
    }
    if (verbose > 1) {
        pr2ws("    reassign blocks parameter list\n");
        dStrHexErr((const char *)paramp, param_len, -1);
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("reassign blocks: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, reassCmdBlk, sizeof(reassCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "reassign blocks", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI PERSISTENT RESERVE IN command (SPC). Returns 0
 * when successful, various SG_LIB_CAT_* positive values or
 * -1 -> other errors */
int
sg_ll_persistent_reserve_in(int sg_fd, int rq_servact, void * resp,
                            int mx_resp_len, int noisy, int verbose)
{
    int res, k, ret, sense_cat;
    unsigned char prinCmdBlk[PERSISTENT_RESERVE_IN_CMDLEN] =
                 {PERSISTENT_RESERVE_IN_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (rq_servact > 0)
        prinCmdBlk[1] = (unsigned char)(rq_servact & 0x1f);
    sg_put_unaligned_be16((uint16_t)mx_resp_len, prinCmdBlk + 7);

    if (verbose) {
        pr2ws("    Persistent Reservation In cmd: ");
        for (k = 0; k < PERSISTENT_RESERVE_IN_CMDLEN; ++k)
            pr2ws("%02x ", prinCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("persistent reservation in: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, prinCmdBlk, sizeof(prinCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "persistent reservation in", res,
                               mx_resp_len, sense_b, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    persistent reserve in: response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI PERSISTENT RESERVE OUT command (SPC). Returns 0
 * when successful, various SG_LIB_CAT_* positive values or
 * -1 -> other errors */
int
sg_ll_persistent_reserve_out(int sg_fd, int rq_servact, int rq_scope,
                             unsigned int rq_type, void * paramp,
                             int param_len, int noisy, int verbose)
{
    int res, k, ret, sense_cat;
    unsigned char proutCmdBlk[PERSISTENT_RESERVE_OUT_CMDLEN] =
                 {PERSISTENT_RESERVE_OUT_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (rq_servact > 0)
        proutCmdBlk[1] = (unsigned char)(rq_servact & 0x1f);
    proutCmdBlk[2] = (((rq_scope & 0xf) << 4) | (rq_type & 0xf));
    sg_put_unaligned_be16((uint16_t)param_len, proutCmdBlk + 7);

    if (verbose) {
        pr2ws("    Persistent Reservation Out cmd: ");
        for (k = 0; k < PERSISTENT_RESERVE_OUT_CMDLEN; ++k)
            pr2ws("%02x ", proutCmdBlk[k]);
        pr2ws("\n");
        if (verbose > 1) {
            pr2ws("    Persistent Reservation Out parameters:\n");
            dStrHexErr((const char *)paramp, param_len, 0);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("persistent reserve out: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, proutCmdBlk, sizeof(proutCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "persistent reserve out", res, 0,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static int
has_blk_ili(unsigned char * sensep, int sb_len)
{
    int resp_code;
    const unsigned char * cup;

    if (sb_len < 8)
        return 0;
    resp_code = (0x7f & sensep[0]);
    if (resp_code >= 0x72) { /* descriptor format */
        /* find block command descriptor */
        if ((cup = sg_scsi_sense_desc_find(sensep, sb_len, 0x5)))
            return ((cup[3] & 0x20) ? 1 : 0);
    } else /* fixed */
        return ((sensep[2] & 0x20) ? 1 : 0);
    return 0;
}

/* Invokes a SCSI READ LONG (10) command (SBC). Note that 'xfer_len'
 * is in bytes. Returns 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_read_long10(int sg_fd, int pblock, int correct, unsigned int lba,
                  void * resp, int xfer_len, int * offsetp, int noisy,
                  int verbose)
{
    int k, res, sense_cat, ret;
    unsigned char readLongCmdBlk[READ_LONG10_CMDLEN];
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    memset(readLongCmdBlk, 0, READ_LONG10_CMDLEN);
    readLongCmdBlk[0] = READ_LONG10_CMD;
    if (pblock)
        readLongCmdBlk[1] |= 0x4;
    if (correct)
        readLongCmdBlk[1] |= 0x2;

    sg_put_unaligned_be32((uint32_t)lba, readLongCmdBlk + 2);
    sg_put_unaligned_be16((uint16_t)xfer_len, readLongCmdBlk + 7);
    if (verbose) {
        pr2ws("    Read Long (10) cmd: ");
        for (k = 0; k < READ_LONG10_CMDLEN; ++k)
            pr2ws("%02x ", readLongCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("read long (10): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, readLongCmdBlk, sizeof(readLongCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, xfer_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "read long (10)", res, xfer_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            {
                int valid, slen, ili;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                ili = has_blk_ili(sense_b, slen);
                if (valid && ili) {
                    if (offsetp)
                        *offsetp = (int)(int64_t)ull;
                    ret = SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO;
                } else {
                    if (verbose > 1)
                        pr2ws("  info field: 0x%" PRIx64 ",  valid: %d, "
                              "ili: %d\n", ull, valid, ili);
                    ret = SG_LIB_CAT_ILLEGAL_REQ;
                }
            }
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    read long(10): response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI READ LONG (16) command (SBC). Note that 'xfer_len'
 * is in bytes. Returns 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_read_long16(int sg_fd, int pblock, int correct, uint64_t llba,
                  void * resp, int xfer_len, int * offsetp, int noisy,
                  int verbose)
{
    int k, res, sense_cat, ret;
    unsigned char readLongCmdBlk[SERVICE_ACTION_IN_16_CMDLEN];
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    memset(readLongCmdBlk, 0, sizeof(readLongCmdBlk));
    readLongCmdBlk[0] = SERVICE_ACTION_IN_16_CMD;
    readLongCmdBlk[1] = READ_LONG_16_SA;
    if (pblock)
        readLongCmdBlk[14] |= 0x2;
    if (correct)
        readLongCmdBlk[14] |= 0x1;

    sg_put_unaligned_be64(llba, readLongCmdBlk + 2);
    sg_put_unaligned_be16((uint16_t)xfer_len, readLongCmdBlk + 12);
    if (verbose) {
        pr2ws("    Read Long (16) cmd: ");
        for (k = 0; k < SERVICE_ACTION_IN_16_CMDLEN; ++k)
            pr2ws("%02x ", readLongCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("read long (16): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, readLongCmdBlk, sizeof(readLongCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, xfer_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "read long (16)", res, xfer_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            {
                int valid, slen, ili;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                ili = has_blk_ili(sense_b, slen);
                if (valid && ili) {
                    if (offsetp)
                        *offsetp = (int)(int64_t)ull;
                    ret = SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO;
                } else {
                    if (verbose > 1)
                        pr2ws("  info field: 0x%" PRIx64 ",  valid: %d, "
                              "ili: %d\n", ull, valid, ili);
                    ret = SG_LIB_CAT_ILLEGAL_REQ;
                }
            }
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    read long(16): response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI WRITE LONG (10) command (SBC). Note that 'xfer_len'
 * is in bytes. Returns 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_write_long10(int sg_fd, int cor_dis, int wr_uncor, int pblock,
                   unsigned int lba, void * data_out, int xfer_len,
                   int * offsetp, int noisy, int verbose)
{
    int k, res, sense_cat, ret;
    unsigned char writeLongCmdBlk[WRITE_LONG10_CMDLEN];
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    memset(writeLongCmdBlk, 0, WRITE_LONG10_CMDLEN);
    writeLongCmdBlk[0] = WRITE_LONG10_CMD;
    if (cor_dis)
        writeLongCmdBlk[1] |= 0x80;
    if (wr_uncor)
        writeLongCmdBlk[1] |= 0x40;
    if (pblock)
        writeLongCmdBlk[1] |= 0x20;

    sg_put_unaligned_be32((uint32_t)lba, writeLongCmdBlk + 2);
    sg_put_unaligned_be16((uint16_t)xfer_len, writeLongCmdBlk + 7);
    if (verbose) {
        pr2ws("    Write Long (10) cmd: ");
        for (k = 0; k < (int)sizeof(writeLongCmdBlk); ++k)
            pr2ws("%02x ", writeLongCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("write long(10): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, writeLongCmdBlk, sizeof(writeLongCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)data_out, xfer_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "write long(10)", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            {
                int valid, slen, ili;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                ili = has_blk_ili(sense_b, slen);
                if (valid && ili) {
                    if (offsetp)
                        *offsetp = (int)(int64_t)ull;
                    ret = SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO;
                } else {
                    if (verbose > 1)
                        pr2ws("  info field: 0x%" PRIx64 ",  valid: %d, "
                              "ili: %d\n", ull, valid, ili);
                    ret = SG_LIB_CAT_ILLEGAL_REQ;
                }
            }
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI WRITE LONG (16) command (SBC). Note that 'xfer_len'
 * is in bytes. Returns 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_write_long16(int sg_fd, int cor_dis, int wr_uncor, int pblock,
                   uint64_t llba, void * data_out, int xfer_len,
                   int * offsetp, int noisy, int verbose)
{
    int k, res, sense_cat, ret;
    unsigned char writeLongCmdBlk[SERVICE_ACTION_OUT_16_CMDLEN];
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    memset(writeLongCmdBlk, 0, sizeof(writeLongCmdBlk));
    writeLongCmdBlk[0] = SERVICE_ACTION_OUT_16_CMD;
    writeLongCmdBlk[1] = WRITE_LONG_16_SA;
    if (cor_dis)
        writeLongCmdBlk[1] |= 0x80;
    if (wr_uncor)
        writeLongCmdBlk[1] |= 0x40;
    if (pblock)
        writeLongCmdBlk[1] |= 0x20;

    sg_put_unaligned_be64(llba, writeLongCmdBlk + 2);
    sg_put_unaligned_be16((uint16_t)xfer_len, writeLongCmdBlk + 12);
    if (verbose) {
        pr2ws("    Write Long (16) cmd: ");
        for (k = 0; k < SERVICE_ACTION_OUT_16_CMDLEN; ++k)
            pr2ws("%02x ", writeLongCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("write long(16): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, writeLongCmdBlk, sizeof(writeLongCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)data_out, xfer_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "write long(16)", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_ILLEGAL_REQ:
            {
                int valid, slen, ili;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                ili = has_blk_ili(sense_b, slen);
                if (valid && ili) {
                    if (offsetp)
                        *offsetp = (int)(int64_t)ull;
                    ret = SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO;
                } else {
                    if (verbose > 1)
                        pr2ws("  info field: 0x%" PRIx64 ",  valid: %d, "
                              "ili: %d\n", ull, valid, ili);
                    ret = SG_LIB_CAT_ILLEGAL_REQ;
                }
            }
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI VERIFY (10) command (SBC and MMC).
 * Note that 'veri_len' is in blocks while 'data_out_len' is in bytes.
 * Returns of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_verify10(int sg_fd, int vrprotect, int dpo, int bytchk,
               unsigned int lba, int veri_len, void * data_out,
               int data_out_len, unsigned int * infop, int noisy,
               int verbose)
{
    int k, res, ret, sense_cat, slen;
    unsigned char vCmdBlk[VERIFY10_CMDLEN] =
                {VERIFY10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    /* N.B. BYTCHK field expanded to 2 bits sbc3r34 */
    vCmdBlk[1] = ((vrprotect & 0x7) << 5) | ((dpo & 0x1) << 4) |
                 ((bytchk & 0x3) << 1) ;
    sg_put_unaligned_be32((uint32_t)lba, vCmdBlk + 2);
    sg_put_unaligned_be16((uint16_t)veri_len, vCmdBlk + 7);
    if (verbose > 1) {
        pr2ws("    Verify(10) cdb: ");
        for (k = 0; k < VERIFY10_CMDLEN; ++k)
            pr2ws("%02x ", vCmdBlk[k]);
        pr2ws("\n");
        if ((verbose > 3) && bytchk && data_out && (data_out_len > 0)) {
            k = data_out_len > 4104 ? 4104 : data_out_len;
            pr2ws("    data_out buffer%s\n",
                  (data_out_len > 4104 ? ", first 4104 bytes" : ""));
            dStrHexErr((const char *)data_out, k, verbose < 5);
        }
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("verify (10): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, vCmdBlk, sizeof(vCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    if (data_out_len > 0)
        set_scsi_pt_data_out(ptvp, (unsigned char *)data_out, data_out_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "verify (10)", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            {
                int valid;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                if (valid) {
                    if (infop)
                        *infop = (unsigned int)ull;
                    ret = SG_LIB_CAT_MEDIUM_HARD_WITH_INFO;
                } else
                    ret = SG_LIB_CAT_MEDIUM_HARD;
            }
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI VERIFY (16) command (SBC and MMC).
 * Note that 'veri_len' is in blocks while 'data_out_len' is in bytes.
 * Returns of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_verify16(int sg_fd, int vrprotect, int dpo, int bytchk, uint64_t llba,
               int veri_len, int group_num, void * data_out,
               int data_out_len, uint64_t * infop, int noisy, int verbose)
{
    int k, res, ret, sense_cat, slen;
    unsigned char vCmdBlk[VERIFY16_CMDLEN] =
                {VERIFY16_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    /* N.B. BYTCHK field expanded to 2 bits sbc3r34 */
    vCmdBlk[1] = ((vrprotect & 0x7) << 5) | ((dpo & 0x1) << 4) |
                 ((bytchk & 0x3) << 1) ;
    sg_put_unaligned_be64(llba, vCmdBlk + 2);
    sg_put_unaligned_be32((uint32_t)veri_len, vCmdBlk + 10);
    vCmdBlk[14] = group_num & 0x1f;
    if (verbose > 1) {
        pr2ws("    Verify(16) cdb: ");
        for (k = 0; k < VERIFY16_CMDLEN; ++k)
            pr2ws("%02x ", vCmdBlk[k]);
        pr2ws("\n");
        if ((verbose > 3) && bytchk && data_out && (data_out_len > 0)) {
            k = data_out_len > 4104 ? 4104 : data_out_len;
            pr2ws("    data_out buffer%s\n",
                  (data_out_len > 4104 ? ", first 4104 bytes" : ""));
            dStrHexErr((const char *)data_out, k, verbose < 5);
        }
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("verify (16): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, vCmdBlk, sizeof(vCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    if (data_out_len > 0)
        set_scsi_pt_data_out(ptvp, (unsigned char *)data_out, data_out_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "verify (16)", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_MEDIUM_HARD:
            {
                int valid;
                uint64_t ull = 0;

                slen = get_scsi_pt_sense_len(ptvp);
                valid = sg_get_sense_info_fld(sense_b, slen, &ull);
                if (valid) {
                    if (infop)
                        *infop = ull;
                    ret = SG_LIB_CAT_MEDIUM_HARD_WITH_INFO;
                } else
                    ret = SG_LIB_CAT_MEDIUM_HARD;
            }
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a ATA PASS-THROUGH (12 or 16) SCSI command (SAT). If cdb_len
 * is 12 then a ATA PASS-THROUGH (12) command is called. If cdb_len is 16
 * then a ATA PASS-THROUGH (16) command is called. If cdb_len is any other
 * value -1 is returned. After copying from cdbp to an internal buffer,
 * the first byte (i.e. offset 0) is set to 0xa1 if cdb_len is 12; or is
 * set to 0x85 if cdb_len is 16. The last byte (offset 11 or offset 15) is
 * set to 0x0 in the internal buffer. If timeout_secs <= 0 then the timeout
 * is set to 60 seconds. For data in or out transfers set dinp or doutp,
 * and dlen to the number of bytes to transfer. If dlen is zero then no data
 * transfer is assumed. If sense buffer obtained then it is written to
 * sensep, else sensep[0] is set to 0x0. If ATA return descriptor is obtained
 * then written to ata_return_dp, else ata_return_dp[0] is set to 0x0. Either
 * sensep or ata_return_dp (or both) may be NULL pointers. Returns SCSI
 * status value (>= 0) or -1 if other error. Users are expected to check the
 * sense buffer themselves. If available the data in resid is written to
 * residp. Note in SAT-2 and later, fixed format sense data may be placed in
 * *sensep in which case sensep[0]==0x70 .
 */
int
sg_ll_ata_pt(int sg_fd, const unsigned char * cdbp, int cdb_len,
             int timeout_secs, void * dinp, void * doutp, int dlen,
             unsigned char * sensep, int max_sense_len,
             unsigned char * ata_return_dp, int max_ata_return_len,
             int * residp, int verbose)
{
    int k, res, slen, duration;
    unsigned char aptCmdBlk[ATA_PT_16_CMDLEN] =
                {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    unsigned char * sp;
    const unsigned char * bp;
    struct sg_pt_base * ptvp;
    const char * cnamep;
    char b[256];
    int ret = -1;

    b[0] = '\0';
    cnamep = (12 == cdb_len) ?
             "ATA pass through (12)" : "ATA pass through (16)";
    if ((NULL == cdbp) || ((12 != cdb_len) && (16 != cdb_len))) {
        if (verbose) {
            if (NULL == cdbp)
                pr2ws("%s NULL cdb pointer\n", cnamep);
            else
                pr2ws("cdb_len must be 12 or 16\n");
        }
        return -1;
    }
    aptCmdBlk[0] = (12 == cdb_len) ? ATA_PT_12_CMD : ATA_PT_16_CMD;
    if (sensep && (max_sense_len >= (int)sizeof(sense_b))) {
        sp = sensep;
        slen = max_sense_len;
    } else {
        sp = sense_b;
        slen = sizeof(sense_b);
    }
    if (12 == cdb_len)
        memcpy(aptCmdBlk + 1, cdbp + 1, ((cdb_len > 11) ? 10 : (cdb_len - 1)));
    else
        memcpy(aptCmdBlk + 1, cdbp + 1, ((cdb_len > 15) ? 14 : (cdb_len - 1)));
    if (verbose) {
        pr2ws("    %s cdb: ", cnamep);
        for (k = 0; k < cdb_len; ++k)
            pr2ws("%02x ", aptCmdBlk[k]);
        pr2ws("\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("%s: out of memory\n", cnamep);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, aptCmdBlk, cdb_len);
    set_scsi_pt_sense(ptvp, sp, slen);
    if (dlen > 0) {
        if (dinp)
            set_scsi_pt_data_in(ptvp, (unsigned char *)dinp, dlen);
        else if (doutp)
            set_scsi_pt_data_out(ptvp, (unsigned char *)doutp, dlen);
    }
    res = do_scsi_pt(ptvp, sg_fd,
                     ((timeout_secs > 0) ? timeout_secs : DEF_PT_TIMEOUT),
                     verbose);
    if (SCSI_PT_DO_BAD_PARAMS == res) {
        if (verbose)
            pr2ws("%s: bad parameters\n", cnamep);
        goto out;
    } else if (SCSI_PT_DO_TIMEOUT == res) {
        if (verbose)
            pr2ws("%s: timeout\n", cnamep);
        goto out;
    } else if (res > 2) {
        if (verbose)
            pr2ws("%s: do_scsi_pt: errno=%d\n", cnamep, -res);
    }

    if ((verbose > 2) && ((duration = get_scsi_pt_duration_ms(ptvp)) >= 0))
        pr2ws("      duration=%d ms\n", duration);

    switch (get_scsi_pt_result_category(ptvp)) {
    case SCSI_PT_RESULT_GOOD:
        if ((sensep) && (max_sense_len > 0))
            *sensep = 0;
        if ((ata_return_dp) && (max_ata_return_len > 0))
            *ata_return_dp = 0;
        if (residp && (dlen > 0))
            *residp = get_scsi_pt_resid(ptvp);
        ret = 0;
        break;
    case SCSI_PT_RESULT_STATUS: /* other than GOOD + CHECK CONDITION */
        if ((sensep) && (max_sense_len > 0))
            *sensep = 0;
        if ((ata_return_dp) && (max_ata_return_len > 0))
            *ata_return_dp = 0;
        ret = get_scsi_pt_status_response(ptvp);
        break;
    case SCSI_PT_RESULT_SENSE:
        if (sensep && (sp != sensep)) {
            k = get_scsi_pt_sense_len(ptvp);
            k = (k > max_sense_len) ? max_sense_len : k;
            memcpy(sensep, sp, k);
        }
        if (ata_return_dp && (max_ata_return_len > 0))  {
            /* search for ATA return descriptor */
            bp = sg_scsi_sense_desc_find(sp, slen, 0x9);
            if (bp) {
                k = bp[1] + 2;
                k = (k > max_ata_return_len) ? max_ata_return_len : k;
                memcpy(ata_return_dp, bp, k);
            } else
                ata_return_dp[0] = 0x0;
        }
        if (residp && (dlen > 0))
            *residp = get_scsi_pt_resid(ptvp);
        ret = get_scsi_pt_status_response(ptvp);
        break;
    case SCSI_PT_RESULT_TRANSPORT_ERR:
        if (verbose)
            pr2ws("%s: transport error: %s\n", cnamep,
                  get_scsi_pt_transport_err_str(ptvp, sizeof(b), b));
        break;
    case SCSI_PT_RESULT_OS_ERR:
        if (verbose)
            pr2ws("%s: os error: %s\n", cnamep,
                  get_scsi_pt_os_err_str(ptvp, sizeof(b) , b));
        break;
    default:
        if (verbose)
            pr2ws("%s: unknown pt_result_category=%d\n", cnamep,
                  get_scsi_pt_result_category(ptvp));
        break;
    }

out:
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI READ BUFFER command (SPC). Return of 0 -> success
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_read_buffer(int sg_fd, int mode, int buffer_id, int buffer_offset,
                  void * resp, int mx_resp_len, int noisy, int verbose)
{
    int res, k, ret, sense_cat;
    unsigned char rbufCmdBlk[READ_BUFFER_CMDLEN] =
        {READ_BUFFER_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    rbufCmdBlk[1] = (unsigned char)(mode & 0x1f);
    rbufCmdBlk[2] = (unsigned char)(buffer_id & 0xff);
    sg_put_unaligned_be24((uint32_t)buffer_offset, rbufCmdBlk + 3);
    sg_put_unaligned_be24((uint32_t)mx_resp_len, rbufCmdBlk + 6);
    if (verbose) {
        pr2ws("    read buffer cdb: ");
        for (k = 0; k < READ_BUFFER_CMDLEN; ++k)
            pr2ws("%02x ", rbufCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("read buffer: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rbufCmdBlk, sizeof(rbufCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "read buffer", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    read buffer: response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI WRITE BUFFER command (SPC). Return of 0 -> success
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_write_buffer(int sg_fd, int mode, int buffer_id, int buffer_offset,
                   void * paramp, int param_len, int noisy, int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char wbufCmdBlk[WRITE_BUFFER_CMDLEN] =
        {WRITE_BUFFER_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    wbufCmdBlk[1] = (unsigned char)(mode & 0x1f);
    wbufCmdBlk[2] = (unsigned char)(buffer_id & 0xff);
    sg_put_unaligned_be24((uint32_t)buffer_offset, wbufCmdBlk + 3);
    sg_put_unaligned_be24((uint32_t)param_len, wbufCmdBlk + 6);
    if (verbose) {
        pr2ws("    Write buffer cmd: ");
        for (k = 0; k < WRITE_BUFFER_CMDLEN; ++k)
            pr2ws("%02x ", wbufCmdBlk[k]);
        pr2ws("\n");
        if ((verbose > 1) && paramp && param_len) {
            pr2ws("    Write buffer parameter list");
            if (2 == verbose) {
                pr2ws("%s:\n", (param_len > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)paramp,
                           (param_len > 256 ? 256 : param_len), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)paramp, param_len, 0);
            }
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("write buffer: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, wbufCmdBlk, sizeof(wbufCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "write buffer", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI UNMAP command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_unmap(int sg_fd, int group_num, int timeout_secs, void * paramp,
            int param_len, int noisy, int verbose)
{
    return sg_ll_unmap_v2(sg_fd, 0, group_num, timeout_secs, paramp,
                          param_len, noisy, verbose);
}

/* Invokes a SCSI UNMAP (SBC-3) command. Version 2 adds anchor field
 * (sbc3r22). Otherwise same as sg_ll_unmap() . */
int
sg_ll_unmap_v2(int sg_fd, int anchor, int group_num, int timeout_secs,
               void * paramp, int param_len, int noisy, int verbose)
{
    int k, res, ret, sense_cat, tmout;
    unsigned char uCmdBlk[UNMAP_CMDLEN] =
                         {UNMAP_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (anchor)
        uCmdBlk[1] |= 0x1;
    tmout = (timeout_secs > 0) ? timeout_secs : DEF_PT_TIMEOUT;
    uCmdBlk[6] = group_num & 0x1f;
    sg_put_unaligned_be16((uint16_t)param_len, uCmdBlk + 7);
    if (verbose) {
        pr2ws("    unmap cdb: ");
        for (k = 0; k < UNMAP_CMDLEN; ++k)
            pr2ws("%02x ", uCmdBlk[k]);
        pr2ws("\n");
        if ((verbose > 1) && paramp && param_len) {
            pr2ws("    unmap parameter list:\n");
            dStrHexErr((const char *)paramp, param_len, -1);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("unmap: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, uCmdBlk, sizeof(uCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, tmout, verbose);
    ret = sg_cmds_process_resp(ptvp, "unmap", res, 0,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI READ BLOCK LIMITS command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_read_block_limits(int sg_fd, void * resp, int mx_resp_len,
                        int noisy, int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rlCmdBlk[READ_BLOCK_LIMITS_CMDLEN] =
      {READ_BLOCK_LIMITS_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (verbose) {
        pr2ws("    read block limits cdb: ");
        for (k = 0; k < READ_BLOCK_LIMITS_CMDLEN; ++k)
            pr2ws("%02x ", rlCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("read block limits: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rlCmdBlk, sizeof(rlCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "read block limits", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            pr2ws("    read block limits: response");
            if (3 == verbose) {
                pr2ws("%s:\n", (ret > 256 ? ", first 256 bytes" : ""));
                dStrHexErr((const char *)resp, (ret > 256 ? 256 : ret), -1);
            } else {
                pr2ws(":\n");
                dStrHexErr((const char *)resp, ret, 0);
            }
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI RECEIVE COPY RESULTS command. Actually cover all current
 * uses of opcode 0x84 (Third-party copy IN). Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_receive_copy_results(int sg_fd, int sa, int list_id, void * resp,
                           int mx_resp_len, int noisy, int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char rcvcopyresCmdBlk[THIRD_PARTY_COPY_IN_CMDLEN] =
      {THIRD_PARTY_COPY_IN_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;
    char b[64];

    sg_get_opcode_sa_name(THIRD_PARTY_COPY_IN_CMD, sa, 0, (int)sizeof(b), b);
    rcvcopyresCmdBlk[1] = (unsigned char)(sa & 0x1f);
    if (sa <= 4)        /* LID1 variants */
        rcvcopyresCmdBlk[2] = (unsigned char)(list_id);
    else if ((sa >= 5) && (sa <= 7))    /* LID4 variants */
        sg_put_unaligned_be32((uint32_t)list_id, rcvcopyresCmdBlk + 2);
    sg_put_unaligned_be32((uint32_t)mx_resp_len, rcvcopyresCmdBlk + 10);

    if (verbose) {
        pr2ws("    %s cmd: ", b);
        for (k = 0; k < THIRD_PARTY_COPY_IN_CMDLEN; ++k)
            pr2ws("%02x ", rcvcopyresCmdBlk[k]);
        pr2ws("\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("%s: out of memory\n", b);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rcvcopyresCmdBlk, sizeof(rcvcopyresCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, b, res, mx_resp_len, sense_b, noisy,
                               verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;
    destruct_scsi_pt_obj(ptvp);
    return ret;
}


/* SPC-4 rev 35 and later calls this opcode (0x83) "Third-party copy OUT"
 * The original EXTENDED COPY command (now called EXTENDED COPY (LID1))
 * is the only one supported by sg_ll_extended_copy(). See function
 * sg_ll_3party_copy_out() for the other service actions ( > 0 ). */

/* Invokes a SCSI EXTENDED COPY (LID1) command. Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_extended_copy(int sg_fd, void * paramp, int param_len, int noisy,
                    int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char xcopyCmdBlk[THIRD_PARTY_COPY_OUT_CMDLEN] =
      {THIRD_PARTY_COPY_OUT_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;
    const char * opcode_name = "Extended copy (LID1)";

    xcopyCmdBlk[1] = (unsigned char)(EXTENDED_COPY_LID1_SA & 0x1f);
    sg_put_unaligned_be32((uint32_t)param_len, xcopyCmdBlk + 10);

    if (verbose) {
        pr2ws("    %s cmd: ", opcode_name);
        for (k = 0; k < THIRD_PARTY_COPY_OUT_CMDLEN; ++k)
            pr2ws("%02x ", xcopyCmdBlk[k]);
        pr2ws("\n");
        if ((verbose > 1) && paramp && param_len) {
            pr2ws("    %s parameter list:\n", opcode_name);
            dStrHexErr((const char *)paramp, param_len, -1);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("%s: out of memory\n", opcode_name);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, xcopyCmdBlk, sizeof(xcopyCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, opcode_name, res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Handles various service actions associated with opcode 0x83 which is
 * called THIRD PARTY COPY OUT. These include the EXTENDED COPY(LID1 and
 * LID4), POPULATE TOKEN and WRITE USING TOKEN commands.
 * Return of 0 -> success,
 * various SG_LIB_CAT_* positive values or -1 -> other errors */
int
sg_ll_3party_copy_out(int sg_fd, int sa, unsigned int list_id, int group_num,
                      int timeout_secs, void * paramp, int param_len,
                      int noisy, int verbose)
{
    int k, res, ret, sense_cat, tmout;
    unsigned char xcopyCmdBlk[THIRD_PARTY_COPY_OUT_CMDLEN] =
      {THIRD_PARTY_COPY_OUT_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;
    char cname[80];

    sg_get_opcode_sa_name(THIRD_PARTY_COPY_OUT_CMD, sa, 0, sizeof(cname),
                          cname);
    xcopyCmdBlk[1] = (unsigned char)(sa & 0x1f);
    switch (sa) {
    case 0x0:   /* XCOPY(LID1) */
    case 0x1:   /* XCOPY(LID4) */
        sg_put_unaligned_be32((uint32_t)param_len, xcopyCmdBlk + 10);
        break;
    case 0x10:  /* POPULATE TOKEN (SBC-3) */
    case 0x11:  /* WRITE USING TOKEN (SBC-3) */
        sg_put_unaligned_be32((uint32_t)list_id, xcopyCmdBlk + 6);
        sg_put_unaligned_be32((uint32_t)param_len, xcopyCmdBlk + 10);
        xcopyCmdBlk[14] = (unsigned char)(group_num & 0x1f);
        break;
    case 0x1c:  /* COPY OPERATION ABORT */
        sg_put_unaligned_be32((uint32_t)list_id, xcopyCmdBlk + 2);
        break;
    default:
        pr2ws("sg_ll_3party_copy_out: unknown service action 0x%x\n", sa);
        return -1;
    }
    tmout = (timeout_secs > 0) ? timeout_secs : DEF_PT_TIMEOUT;

    if (verbose) {
        pr2ws("    %s cmd: ", cname);
        for (k = 0; k < THIRD_PARTY_COPY_OUT_CMDLEN; ++k)
            pr2ws("%02x ", xcopyCmdBlk[k]);
        pr2ws("\n");
        if ((verbose > 1) && paramp && param_len) {
            pr2ws("    %s parameter list:\n", cname);
            dStrHexErr((const char *)paramp, param_len, -1);
        }
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2ws("%s: out of memory\n", cname);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, xcopyCmdBlk, sizeof(xcopyCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, tmout, verbose);
    ret = sg_cmds_process_resp(ptvp, cname, res, 0, sense_b, noisy, verbose,
                               &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

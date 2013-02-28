/*
 * Copyright (c) 1999-2013 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

/*
 * CONTENTS
 *    Some SCSI commands are executed in many contexts and hence began
 *    to appear in several sg3_utils utilities. This files centralizes
 *    some of the low level command execution code. In most cases the
 *    interpretation of the command response is left to the each
 *    utility.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_pt.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif



#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define EBUFF_SZ 256

#define DEF_PT_TIMEOUT 60       /* 60 seconds */
#define START_PT_TIMEOUT 120    /* 120 seconds == 2 minutes */
#define LONG_PT_TIMEOUT 7200    /* 7,200 seconds == 120 minutes */

#define SYNCHRONIZE_CACHE_CMD     0x35
#define SYNCHRONIZE_CACHE_CMDLEN  10
#define SERVICE_ACTION_IN_16_CMD 0x9e
#define SERVICE_ACTION_IN_16_CMDLEN 16
#define READ_CAPACITY_16_SA 0x10
#define READ_CAPACITY_10_CMD 0x25
#define READ_CAPACITY_10_CMDLEN 10
#define MODE_SENSE6_CMD      0x1a
#define MODE_SENSE6_CMDLEN   6
#define MODE_SENSE10_CMD     0x5a
#define MODE_SENSE10_CMDLEN  10
#define MODE_SELECT6_CMD   0x15
#define MODE_SELECT6_CMDLEN   6
#define MODE_SELECT10_CMD   0x55
#define MODE_SELECT10_CMDLEN  10
#define LOG_SENSE_CMD     0x4d
#define LOG_SENSE_CMDLEN  10
#define LOG_SELECT_CMD     0x4c
#define LOG_SELECT_CMDLEN  10
#define START_STOP_CMD          0x1b
#define START_STOP_CMDLEN       6
#define PREVENT_ALLOW_CMD    0x1e
#define PREVENT_ALLOW_CMDLEN   6

#define MODE6_RESP_HDR_LEN 4
#define MODE10_RESP_HDR_LEN 8
#define MODE_RESP_ARB_LEN 1024

#define INQUIRY_RESP_INITIAL_LEN 36


/* Invokes a SCSI SYNCHRONIZE CACHE (10) command. Return of 0 -> success,
 * SG_LIB_CAT_UNIT_ATTENTION -> repeat,
 * SG_LIB_CAT_INVALID_OP -> cdb not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_ABORTED_COMMAND,
 * SG_LIB_CAT_NOT_READY -> device not ready, -1 -> other failure */
int
sg_ll_sync_cache_10(int sg_fd, int sync_nv, int immed, int group,
                    unsigned int lba, unsigned int count, int noisy,
                    int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char scCmdBlk[SYNCHRONIZE_CACHE_CMDLEN] =
                {SYNCHRONIZE_CACHE_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (sync_nv)
        scCmdBlk[1] |= 4;
    if (immed)
        scCmdBlk[1] |= 2;
    scCmdBlk[2] = (lba >> 24) & 0xff;
    scCmdBlk[3] = (lba >> 16) & 0xff;
    scCmdBlk[4] = (lba >> 8) & 0xff;
    scCmdBlk[5] = lba & 0xff;
    scCmdBlk[6] = group & 0x1f;
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (count > 0xffff) {
        fprintf(sg_warnings_strm, "count too big\n");
        return -1;
    }
    scCmdBlk[7] = (count >> 8) & 0xff;
    scCmdBlk[8] = count & 0xff;

    if (verbose) {
        fprintf(sg_warnings_strm, "    synchronize cache(10) cdb: ");
        for (k = 0; k < SYNCHRONIZE_CACHE_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", scCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "synchronize cache(10): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, scCmdBlk, sizeof(scCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "synchronize cache(10)", res, 0,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI READ CAPACITY (16) command. Returns 0 -> success,
 * SG_LIB_CAT_UNIT_ATTENTION -> media changed??, SG_LIB_CAT_INVALID_OP
 *  -> cdb not supported, SG_LIB_CAT_IlLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_ABORTED_COMMAND, SG_LIB_CAT_NOT_READY -> device not ready,
 * -1 -> other failure */
int
sg_ll_readcap_16(int sg_fd, int pmi, uint64_t llba, void * resp,
                 int mx_resp_len, int noisy, int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rcCmdBlk[SERVICE_ACTION_IN_16_CMDLEN] =
                        {SERVICE_ACTION_IN_16_CMD, READ_CAPACITY_16_SA,
                         0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

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
    /* Allocation length, no guidance in SBC-2 rev 15b */
    rcCmdBlk[10] = (mx_resp_len >> 24) & 0xff;
    rcCmdBlk[11] = (mx_resp_len >> 16) & 0xff;
    rcCmdBlk[12] = (mx_resp_len >> 8) & 0xff;
    rcCmdBlk[13] = mx_resp_len & 0xff;
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (verbose) {
        fprintf(sg_warnings_strm, "    read capacity (16) cdb: ");
        for (k = 0; k < SERVICE_ACTION_IN_16_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", rcCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "read capacity (16): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rcCmdBlk, sizeof(rcCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "read capacity (16)", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI READ CAPACITY (10) command. Returns 0 -> success,
 * SG_LIB_CAT_UNIT_ATTENTION -> media changed??, SG_LIB_CAT_INVALID_OP
 *  -> cdb not supported, SG_LIB_CAT_IlLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_ABORTED_COMMAND, SG_LIB_CAT_NOT_READY -> device not ready,
 * -1 -> other failure */
int
sg_ll_readcap_10(int sg_fd, int pmi, unsigned int lba, void * resp,
                 int mx_resp_len, int noisy, int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rcCmdBlk[READ_CAPACITY_10_CMDLEN] =
                         {READ_CAPACITY_10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (pmi) { /* lbs only valid when pmi set */
        rcCmdBlk[8] |= 1;
        rcCmdBlk[2] = (lba >> 24) & 0xff;
        rcCmdBlk[3] = (lba >> 16) & 0xff;
        rcCmdBlk[4] = (lba >> 8) & 0xff;
        rcCmdBlk[5] = lba & 0xff;
    }
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (verbose) {
        fprintf(sg_warnings_strm, "    read capacity (10) cdb: ");
        for (k = 0; k < READ_CAPACITY_10_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", rcCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "read capacity (10): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rcCmdBlk, sizeof(rcCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "read capacity (10)", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI MODE SENSE (6) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, * SG_LIB_CAT_NOT_READY -> device not ready,
 * SG_LIB_CAT_ABORTED_COMMAND, SG_LIB_CAT_UNIT_ATTENTION,
 * -1 -> other failure */
int
sg_ll_mode_sense6(int sg_fd, int dbd, int pc, int pg_code, int sub_pg_code,
                  void * resp, int mx_resp_len, int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char modesCmdBlk[MODE_SENSE6_CMDLEN] =
        {MODE_SENSE6_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    modesCmdBlk[1] = (unsigned char)(dbd ? 0x8 : 0);
    modesCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    modesCmdBlk[3] = (unsigned char)(sub_pg_code & 0xff);
    modesCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (mx_resp_len > 0xff) {
        fprintf(sg_warnings_strm, "mx_resp_len too big\n");
        return -1;
    }
    if (verbose) {
        fprintf(sg_warnings_strm, "    mode sense (6) cdb: ");
        for (k = 0; k < MODE_SENSE6_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", modesCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "mode sense (6): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, modesCmdBlk, sizeof(modesCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "mode sense (6)", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            fprintf(sg_warnings_strm, "    mode sense (6): response%s\n",
                    (ret > 256 ? ", first 256 bytes" : ""));
            dStrHex((const char *)resp, (ret > 256 ? 256 : ret), -1);
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI MODE SENSE (10) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, * SG_LIB_CAT_NOT_READY -> device not ready,
 * SG_LIB_CAT_ABORTED_COMMAND, SG_LIB_CAT_UNIT_ATTENTION,
 * -1 -> other failure */
int
sg_ll_mode_sense10(int sg_fd, int llbaa, int dbd, int pc, int pg_code,
                   int sub_pg_code, void * resp, int mx_resp_len,
                   int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char modesCmdBlk[MODE_SENSE10_CMDLEN] =
        {MODE_SENSE10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    modesCmdBlk[1] = (unsigned char)((dbd ? 0x8 : 0) | (llbaa ? 0x10 : 0));
    modesCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    modesCmdBlk[3] = (unsigned char)(sub_pg_code & 0xff);
    modesCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    modesCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (mx_resp_len > 0xffff) {
        fprintf(sg_warnings_strm, "mx_resp_len too big\n");
        return -1;
    }
    if (verbose) {
        fprintf(sg_warnings_strm, "    mode sense (10) cdb: ");
        for (k = 0; k < MODE_SENSE10_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", modesCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "mode sense (10): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, modesCmdBlk, sizeof(modesCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "mode sense (10)", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else {
        if ((verbose > 2) && (ret > 0)) {
            fprintf(sg_warnings_strm, "    mode sense (10): response%s\n",
                    (ret > 256 ? ", first 256 bytes" : ""));
            dStrHex((const char *)resp, (ret > 256 ? 256 : ret), -1);
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI MODE SELECT (6) command.  Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, * SG_LIB_CAT_NOT_READY -> device not ready,
 * SG_LIB_CAT_ABORTED_COMMAND, SG_LIB_CAT_UNIT_ATTENTION,
 * -1 -> other failure */
int
sg_ll_mode_select6(int sg_fd, int pf, int sp, void * paramp, int param_len,
                   int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char modesCmdBlk[MODE_SELECT6_CMDLEN] =
        {MODE_SELECT6_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    modesCmdBlk[1] = (unsigned char)(((pf << 4) & 0x10) | (sp & 0x1));
    modesCmdBlk[4] = (unsigned char)(param_len & 0xff);
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (param_len > 0xff) {
        fprintf(sg_warnings_strm, "mode select (6): param_len too big\n");
        return -1;
    }
    if (verbose) {
        fprintf(sg_warnings_strm, "    mode select (6) cdb: ");
        for (k = 0; k < MODE_SELECT6_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", modesCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    if (verbose > 1) {
        fprintf(sg_warnings_strm, "    mode select (6) parameter list\n");
        dStrHex((const char *)paramp, param_len, -1);
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "mode select (6): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, modesCmdBlk, sizeof(modesCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "mode select (6)", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI MODE SELECT (10) command.  Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, * SG_LIB_CAT_NOT_READY -> device not ready,
 * SG_LIB_CAT_ABORTED_COMMAND, SG_LIB_CAT_UNIT_ATTENTION,
 * -1 -> other failure */
int
sg_ll_mode_select10(int sg_fd, int pf, int sp, void * paramp, int param_len,
                    int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char modesCmdBlk[MODE_SELECT10_CMDLEN] =
        {MODE_SELECT10_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    modesCmdBlk[1] = (unsigned char)(((pf << 4) & 0x10) | (sp & 0x1));
    modesCmdBlk[7] = (unsigned char)((param_len >> 8) & 0xff);
    modesCmdBlk[8] = (unsigned char)(param_len & 0xff);
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (param_len > 0xffff) {
        fprintf(sg_warnings_strm, "mode select (10): param_len too big\n");
        return -1;
    }
    if (verbose) {
        fprintf(sg_warnings_strm, "    mode select (10) cdb: ");
        for (k = 0; k < MODE_SELECT10_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", modesCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    if (verbose > 1) {
        fprintf(sg_warnings_strm, "    mode select (10) parameter list\n");
        dStrHex((const char *)paramp, param_len, -1);
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "mode select (10): out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, modesCmdBlk, sizeof(modesCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, (unsigned char *)paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "mode select (10)", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* MODE SENSE commands yield a response that has block descriptors followed
 * by mode pages. In most cases users are interested in the first mode page.
 * This function returns the (byte) offset of the start of the first mode
 * page. Set mode_sense_6 to 1 for MODE SENSE (6) and 0 for MODE SENSE (10).
 * Returns >= 0 is successful or -1 if failure. If there is a failure
 * a message is written to err_buff. */
int
sg_mode_page_offset(const unsigned char * resp, int resp_len,
                    int mode_sense_6, char * err_buff, int err_buff_len)
{
    int bd_len;
    int calc_len;
    int offset;

    if ((NULL == resp) || (resp_len < 4) ||
        ((! mode_sense_6) && (resp_len < 8))) {
        if (err_buff_len > 0)
            snprintf(err_buff, err_buff_len, "given response length too "
                     "short: %d\n", resp_len);
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
        if (err_buff_len > 0)
            snprintf(err_buff, err_buff_len, "given response length "
                     "too small, offset=%d given_len=%d bd_len=%d\n",
                     offset, resp_len, bd_len);
        offset = -1;
    } else if ((offset + 2) > calc_len) {
        if (err_buff_len > 0)
            snprintf(err_buff, err_buff_len, "calculated response "
                     "length too small, offset=%d calc_len=%d bd_len=%d\n",
                     offset, calc_len, bd_len);
        offset = -1;
    }
    return offset;
}

/* Fetches current, changeable, default and/or saveable modes pages as
 * indicated by pcontrol_arr for given pg_code and sub_pg_code. If
 * mode6==0 then use MODE SENSE (10) else use MODE SENSE (6). If
 * flexible set and mode data length seems wrong then try and
 * fix (compensating hack for bad device or driver). pcontrol_arr
 * should have 4 elements for output of current, changeable, default
 * and saved values respectively. Each element should be NULL or
 * at least mx_mpage_len bytes long.
 * Return of 0 -> overall success, SG_LIB_CAT_INVALID_OP -> invalid opcode,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_NOT_READY -> device not ready,
 * SG_LIB_CAT_MALFORMED -> bad response, -1 -> other failure.
 * If success_mask pointer is not NULL then first zeros it. Then set bits
 * 0, 1, 2 and/or 3 if the current, changeable, default and saved values
 * respectively have been fetched. If error on current page
 * then stops and returns that error; otherwise continues if an error is
 * detected but returns the first error encountered.  */
int
sg_get_mode_page_controls(int sg_fd, int mode6, int pg_code, int sub_pg_code,
                          int dbd, int flexible, int mx_mpage_len,
                          int * success_mask, void * pcontrol_arr[],
                          int * reported_len, int verbose)
{
    int k, n, res, offset, calc_len, xfer_len, resp_mode6;
    unsigned char buff[MODE_RESP_ARB_LEN];
    char ebuff[EBUFF_SZ];
    int first_err = 0;

    if (success_mask)
        *success_mask = 0;
    if (reported_len)
        *reported_len = 0;
    if (mx_mpage_len < 4)
        return 0;
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    memset(ebuff, 0, sizeof(ebuff));
    /* first try to find length of current page response */
    memset(buff, 0, MODE10_RESP_HDR_LEN);
    if (mode6)  /* want first 8 bytes just in case */
        res = sg_ll_mode_sense6(sg_fd, dbd, 0 /* pc */, pg_code,
                                sub_pg_code, buff, MODE10_RESP_HDR_LEN, 1,
                                verbose);
    else
        res = sg_ll_mode_sense10(sg_fd, 0 /* llbaa */, dbd,
                                 0 /* pc */, pg_code, sub_pg_code, buff,
                                 MODE10_RESP_HDR_LEN, 1, verbose);
    if (0 != res)
        return res;
    n = buff[0];
    if (reported_len)
        *reported_len = mode6 ? (n + 1) : ((n << 8) + buff[1] + 2);
    resp_mode6 = mode6;
    if (flexible) {
        if (mode6 && (n < 3)) {
            resp_mode6 = 0;
            if (verbose)
                fprintf(sg_warnings_strm, ">>> msense(6) but resp[0]=%d so "
                        "try msense(10) response processing\n", n);
        }
        if ((0 == mode6) && (n > 5)) {
            if ((n > 11) && (0 == (n % 2)) && (0 == buff[4]) &&
                (0 == buff[5]) && (0 == buff[6])) {
                buff[1] = n;
                buff[0] = 0;
                if (verbose)
                    fprintf(sg_warnings_strm, ">>> msense(10) but resp[0]=%d "
                            "and not msense(6) response so fix length\n", n);
            } else
                resp_mode6 = 1;
        }
    }
    if (verbose && (resp_mode6 != mode6))
        fprintf(sg_warnings_strm, ">>> msense(%d) but resp[0]=%d "
                "so switch response processing\n", (mode6 ? 6 : 10),
                buff[0]);
    calc_len = resp_mode6 ? (buff[0] + 1) : ((buff[0] << 8) + buff[1] + 2);
    if (calc_len > MODE_RESP_ARB_LEN)
        calc_len = MODE_RESP_ARB_LEN;
    offset = sg_mode_page_offset(buff, calc_len, resp_mode6,
                                 ebuff, EBUFF_SZ);
    if (offset < 0) {
        if (('\0' != ebuff[0]) && (verbose > 0))
            fprintf(sg_warnings_strm, "sg_get_mode_page_controls: %s\n",
                    ebuff);
        return SG_LIB_CAT_MALFORMED;
    }
    xfer_len = calc_len - offset;
    if (xfer_len > mx_mpage_len)
        xfer_len = mx_mpage_len;

    for (k = 0; k < 4; ++k) {
        if (NULL == pcontrol_arr[k])
            continue;
        memset(pcontrol_arr[k], 0, mx_mpage_len);
        if (mode6)
            res = sg_ll_mode_sense6(sg_fd, dbd, k /* pc */,
                                    pg_code, sub_pg_code, buff,
                                    calc_len, 1, verbose);
        else
            res = sg_ll_mode_sense10(sg_fd, 0 /* llbaa */, dbd,
                                     k /* pc */, pg_code, sub_pg_code,
                                     buff, calc_len, 1, verbose);
        if (0 != res) {
            if (0 == first_err)
                first_err = res;
            if (0 == k)
                break;  /* if problem on current page, it won't improve */
            else
                continue;
        }
        if (xfer_len > 0)
            memcpy(pcontrol_arr[k], buff + offset, xfer_len);
        if (success_mask)
            *success_mask |= (1 << k);
    }
    return first_err;
}

/* Invokes a SCSI LOG SENSE command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Log Sense not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_NOT_READY -> device not ready, SG_LIB_CAT_ABORTED_COMMAND,
 * -1 -> other failure */
int
sg_ll_log_sense(int sg_fd, int ppc, int sp, int pc, int pg_code,
                int subpg_code, int paramp, unsigned char * resp,
                int mx_resp_len, int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char logsCmdBlk[LOG_SENSE_CMDLEN] =
        {LOG_SENSE_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (mx_resp_len > 0xffff) {
        fprintf(sg_warnings_strm, "mx_resp_len too big\n");
        return -1;
    }
    logsCmdBlk[1] = (unsigned char)((ppc ? 2 : 0) | (sp ? 1 : 0));
    logsCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    logsCmdBlk[3] = (unsigned char)(subpg_code & 0xff);
    logsCmdBlk[5] = (unsigned char)((paramp >> 8) & 0xff);
    logsCmdBlk[6] = (unsigned char)(paramp & 0xff);
    logsCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    logsCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);
    if (verbose) {
        fprintf(sg_warnings_strm, "    log sense cdb: ");
        for (k = 0; k < LOG_SENSE_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", logsCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "log sense: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, logsCmdBlk, sizeof(logsCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "log sense", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else {
        if ((mx_resp_len > 3) && (ret < 4)) {
            /* resid indicates LOG SENSE response length bad, so zero it */
            resp[2] = 0;
            resp[3] = 0;
        }
        ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI LOG SELECT command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Log Select not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_NOT_READY -> device not ready, SG_LIB_CAT_ABORTED_COMMAND,
 * -1 -> other failure */
int
sg_ll_log_select(int sg_fd, int pcr, int sp, int pc, int pg_code,
                 int subpg_code, unsigned char * paramp, int param_len,
                 int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char logsCmdBlk[LOG_SELECT_CMDLEN] =
        {LOG_SELECT_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (param_len > 0xffff) {
        fprintf(sg_warnings_strm, "log select: param_len too big\n");
        return -1;
    }
    logsCmdBlk[1] = (unsigned char)((pcr ? 2 : 0) | (sp ? 1 : 0));
    logsCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    logsCmdBlk[3] = (unsigned char)(subpg_code & 0xff);
    logsCmdBlk[7] = (unsigned char)((param_len >> 8) & 0xff);
    logsCmdBlk[8] = (unsigned char)(param_len & 0xff);
    if (verbose) {
        fprintf(sg_warnings_strm, "    log select cdb: ");
        for (k = 0; k < LOG_SELECT_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", logsCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    if ((verbose > 1) && (param_len > 0)) {
        fprintf(sg_warnings_strm, "    log select parameter list\n");
        dStrHex((const char *)paramp, param_len, -1);
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "log select: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, logsCmdBlk, sizeof(logsCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_out(ptvp, paramp, param_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "log select", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI START STOP UNIT command (SBC + MMC).
 * Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Start stop unit not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_NOT_READY -> device not ready, SG_LIB_CAT_ABORTED_COMMAND,
 * -1 -> other failure
 * SBC-3 and MMC partially overlap on the power_condition_modifier(sbc) and
 * format_layer_number(mmc) fields. They also overlap on the noflush(sbc)
 * and fl(mmc) one bit field. This is the cause of the awkardly named
 * pc_mod__fl_num and noflush__fl arguments to this function.
 *  */
int
sg_ll_start_stop_unit(int sg_fd, int immed, int pc_mod__fl_num,
                      int power_cond, int noflush__fl, int loej, int start,
                      int noisy, int verbose)
{
    unsigned char ssuBlk[START_STOP_CMDLEN] = {START_STOP_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    int k, res, ret, sense_cat;
    struct sg_pt_base * ptvp;

    ssuBlk[1] = immed & 1;
    ssuBlk[3] = pc_mod__fl_num & 0xf;  /* bits 2 and 3 are reserved in MMC */
    ssuBlk[4] = ((power_cond & 0xf) << 4) | (noflush__fl ? 0x4 : 0) |
                 (loej ? 0x2 : 0) | (start ? 0x1 : 0);
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (verbose) {
        fprintf(sg_warnings_strm, "    Start stop unit command:");
        for (k = 0; k < (int)sizeof(ssuBlk); ++k)
                fprintf (sg_warnings_strm, " %02x", ssuBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "start stop unit: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, ssuBlk, sizeof(ssuBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, sg_fd, START_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "start stop unit", res, 0,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else
            ret = 0;
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI PREVENT ALLOW MEDIUM REMOVAL command
 * [was in SPC-3 but displaced from SPC-4 into SBC-3, MMC-5, SSC-3]
 * prevent==0 allows removal, prevent==1 prevents removal ...
 * Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> command not supported
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_NOT_READY -> device not ready, SG_LIB_CAT_ABORTED_COMMAND,
 * -1 -> other failure */
int
sg_ll_prevent_allow(int sg_fd, int prevent, int noisy, int verbose)
{
    int k, res, ret, sense_cat;
    unsigned char pCmdBlk[PREVENT_ALLOW_CMDLEN] =
                {PREVENT_ALLOW_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if ((prevent < 0) || (prevent > 3)) {
        fprintf(sg_warnings_strm, "prevent argument should be 0, 1, 2 or 3\n");
        return -1;
    }
    pCmdBlk[4] |= (prevent & 0x3);
    if (verbose) {
        fprintf(sg_warnings_strm, "    Prevent allow medium removal cdb: ");
        for (k = 0; k < PREVENT_ALLOW_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", pCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "prevent allow medium removal: out of "
                "memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, pCmdBlk, sizeof(pCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "prevent allow medium removal", res, 0,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = -1;
            break;
        }
    } else
            ret = 0;
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

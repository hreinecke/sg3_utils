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


static char * version_str = "1.61 20130311";


#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define EBUFF_SZ 256

#define DEF_PT_TIMEOUT 60       /* 60 seconds */
#define START_PT_TIMEOUT 120    /* 120 seconds == 2 minutes */
#define LONG_PT_TIMEOUT 7200    /* 7,200 seconds == 120 minutes */

#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6
#define REQUEST_SENSE_CMD 0x3
#define REQUEST_SENSE_CMDLEN 6
#define REPORT_LUNS_CMD 0xa0
#define REPORT_LUNS_CMDLEN 12
#define TUR_CMD  0x0
#define TUR_CMDLEN  6

#define INQUIRY_RESP_INITIAL_LEN 36


const char *
sg_cmds_version()
{
    return version_str;
}

/* Returns file descriptor >= 0 if successful. If error in Unix returns
   negated errno. */
int
sg_cmds_open_device(const char * device_name, int read_only, int verbose)
{
    return scsi_pt_open_device(device_name, read_only, verbose);
}

/* Returns file descriptor >= 0 if successful. If error in Unix returns
   negated errno. */
int
sg_cmds_open_flags(const char * device_name, int flags, int verbose)
{
    return scsi_pt_open_flags(device_name, flags, verbose);
}

/* Returns 0 if successful. If error in Unix returns negated errno. */
int
sg_cmds_close_device(int device_fd)
{
    return scsi_pt_close_device(device_fd);
}

static int
sg_cmds_process_helper(const char * leadin, int mx_di_len, int resid,
                       const unsigned char * sbp, int slen, int noisy,
                       int verbose, int * o_sense_cat)
{
    int scat, got;
    int n = 0;
    int check_data_in = 0;
    char b[512];

    scat = sg_err_category_sense(sbp, slen);
    switch (scat) {
    case SG_LIB_CAT_NOT_READY:
    case SG_LIB_CAT_INVALID_OP:
    case SG_LIB_CAT_ILLEGAL_REQ:
    case SG_LIB_CAT_ABORTED_COMMAND:
    case SG_LIB_CAT_NO_SENSE:
        n = 0;
        break;
    case SG_LIB_CAT_RECOVERED:
    case SG_LIB_CAT_MEDIUM_HARD:
        ++check_data_in;
	/* drop through */
    case SG_LIB_CAT_UNIT_ATTENTION:
    default:
        n = noisy;
        break;
    }
    if (verbose || n) {
        sg_get_sense_str(leadin, sbp, slen, (verbose > 1),
                         sizeof(b), b);
        fprintf(sg_warnings_strm, "%s", b);
        if ((mx_di_len > 0) && (resid > 0)) {
            got = mx_di_len - resid;
            if ((verbose > 2) || check_data_in || (got > 0))
                fprintf(sg_warnings_strm, "    pass-through requested "
                        "%d bytes but got %d bytes\n", mx_di_len, got);
        }
    }
    if (o_sense_cat)
        *o_sense_cat = scat;
    return -2;
}

/* This is a helper function used by sg_cmds_* implementations after
 * the call to the pass-through. pt_res is returned from do_scsi_pt().
 * If valid sense data is found it is decoded and output to sg_warnings_strm
 * (def: stderr); depending on the 'noisy' and 'verbose' settings.
 * Returns -2 for sense data (may not be fatal), -1 for failed, or the
 * number of data in bytes received. For data out (to device) or no data,
 * set 'mx_di_len' to 0 or less. If -2 returned then sense category
 * output via 'o_sense_cat' pointer (if not NULL). Note that several sense
 * categories also have data in bytes received; -2 is still returned. */
int
sg_cmds_process_resp(struct sg_pt_base * ptvp, const char * leadin,
                     int pt_res, int mx_di_len, const unsigned char * sbp,
                     int noisy, int verbose, int * o_sense_cat)
{
    int got, cat, duration, slen, resid, resp_code;
    char b[1024];

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (NULL == leadin)
        leadin = "";
    if (pt_res < 0) {
        if (noisy || verbose)
            fprintf(sg_warnings_strm, "%s: pass through os error: %s\n",
                    leadin, safe_strerror(-pt_res));
        return -1;
    } else if (SCSI_PT_DO_BAD_PARAMS == pt_res) {
        fprintf(sg_warnings_strm, "%s: bad pass through setup\n", leadin);
        return -1;
    } else if (SCSI_PT_DO_TIMEOUT == pt_res) {
        fprintf(sg_warnings_strm, "%s: pass through timeout\n", leadin);
        return -1;
    }
    if ((verbose > 2) && ((duration = get_scsi_pt_duration_ms(ptvp)) >= 0))
        fprintf(sg_warnings_strm, "      duration=%d ms\n", duration);
    resid = (mx_di_len > 0) ? get_scsi_pt_resid(ptvp) : 0;
    slen = get_scsi_pt_sense_len(ptvp);
    switch ((cat = get_scsi_pt_result_category(ptvp))) {
    case SCSI_PT_RESULT_GOOD:
        if (slen > 7) {
            resp_code = sbp[0] & 0x7f;
            /* SBC referrals can have status=GOOD and sense_key=COMPLETED */
            if (resp_code >= 0x70) {
                if (resp_code < 0x72) {
                    if (SPC_SK_NO_SENSE != (0xf & sbp[2]))
                        sg_err_category_sense(sbp, slen);
                } else if (resp_code < 0x74) {
                    if (SPC_SK_NO_SENSE != (0xf & sbp[1]))
                        sg_err_category_sense(sbp, slen);
                }
            }
        }
        if (mx_di_len > 0) {
            got = mx_di_len - resid;
            if (verbose && (resid > 0))
                fprintf(sg_warnings_strm, "    %s: pass-through requested "
                        "%d bytes but got %d bytes\n", leadin, mx_di_len,
                        got);
            return got;
        } else
            return 0;
    case SCSI_PT_RESULT_STATUS: /* other than GOOD and CHECK CONDITION */
        if (verbose || noisy) {
            sg_get_scsi_status_str(get_scsi_pt_status_response(ptvp),
                                   sizeof(b), b);
            fprintf(sg_warnings_strm, "%s: scsi status: %s\n", leadin, b);
        }
        return -1;
    case SCSI_PT_RESULT_SENSE:
        return sg_cmds_process_helper(leadin, mx_di_len, resid, sbp, slen,
                                      noisy, verbose, o_sense_cat);
    case SCSI_PT_RESULT_TRANSPORT_ERR:
        if (verbose || noisy) {
            get_scsi_pt_transport_err_str(ptvp, sizeof(b), b);
            fprintf(sg_warnings_strm, "%s: transport: %s\n", leadin, b);
        }
        if ((SAM_STAT_CHECK_CONDITION == get_scsi_pt_status_response(ptvp))
            && (slen > 0))
            return sg_cmds_process_helper(leadin, mx_di_len, resid, sbp,
                                          slen, noisy, verbose, o_sense_cat);
        else
            return -1;
    case SCSI_PT_RESULT_OS_ERR:
        if (verbose || noisy) {
            get_scsi_pt_os_err_str(ptvp, sizeof(b), b);
            fprintf(sg_warnings_strm, "%s: os: %s\n", leadin, b);
        }
        return -1;
    default:
        fprintf(sg_warnings_strm, "%s: unknown pass through result "
                "category (%d)\n", leadin, cat);
        return -1;
    }
}

/* Invokes a SCSI INQUIRY command and yields the response
 * Returns 0 when successful, SG_LIB_CAT_INVALID_OP -> not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_ABORTED_COMMAND,
 * SG_LIB_CAT_MALFORMED -> bad response, -1 -> other errors */
int
sg_ll_inquiry(int sg_fd, int cmddt, int evpd, int pg_op, void * resp,
              int mx_resp_len, int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    unsigned char * up;
    struct sg_pt_base * ptvp;

    if (cmddt)
        inqCmdBlk[1] |= 2;
    if (evpd)
        inqCmdBlk[1] |= 1;
    inqCmdBlk[2] = (unsigned char)pg_op;
    /* 16 bit allocation length (was 8) is a recent SPC-3 addition */
    inqCmdBlk[3] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    inqCmdBlk[4] = (unsigned char)(mx_resp_len & 0xff);
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (verbose) {
        fprintf(sg_warnings_strm, "    inquiry cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", inqCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    if (resp && (mx_resp_len > 0)) {
        up = (unsigned char *)resp;
        up[0] = 0x7f;   /* defensive prefill */
        if (mx_resp_len > 4)
            up[4] = 0;
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "inquiry: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, inqCmdBlk, sizeof(inqCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "inquiry", res, mx_resp_len, sense_b,
                               noisy, verbose, &sense_cat);
    destruct_scsi_pt_obj(ptvp);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
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
    } else if (ret < 4) {
        if (verbose)
            fprintf(sg_warnings_strm, "inquiry: got too few "
                    "bytes (%d)\n", ret);
        ret = SG_LIB_CAT_MALFORMED;
    } else
        ret = 0;

    return ret;
}

/* Yields most of first 36 bytes of a standard INQUIRY (evpd==0) response.
 * Returns 0 when successful, SG_LIB_CAT_INVALID_OP -> not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, SG_LIB_CAT_ABORTED_COMMAND,
 * SG_LIB_CAT_MALFORMED -> bad response, -1 -> other errors */
int
sg_simple_inquiry(int sg_fd, struct sg_simple_inquiry_resp * inq_data,
                  int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    unsigned char inq_resp[INQUIRY_RESP_INITIAL_LEN];
    struct sg_pt_base * ptvp;

    if (inq_data) {
        memset(inq_data, 0, sizeof(* inq_data));
        inq_data->peripheral_qualifier = 0x3;
        inq_data->peripheral_type = 0x1f;
    }
    inqCmdBlk[4] = (unsigned char)sizeof(inq_resp);
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (verbose) {
        fprintf(sg_warnings_strm, "    inquiry cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", inqCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }
    memset(inq_resp, 0, sizeof(inq_resp));
    inq_resp[0] = 0x7f; /* defensive prefill */
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "inquiry: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, inqCmdBlk, sizeof(inqCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, inq_resp, sizeof(inq_resp));
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "inquiry", res, sizeof(inq_resp),
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
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
    } else if (ret < 4) {
        if (verbose)
            fprintf(sg_warnings_strm, "inquiry: got too few "
                    "bytes (%d)\n", ret);
        ret = SG_LIB_CAT_MALFORMED;
    } else
        ret = 0;

    if (0 == ret) {
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
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI TEST UNIT READY command.
 * 'pack_id' is just for diagnostics, safe to set to 0.
 * Looks for progress indicator if 'progress' non-NULL;
 * if found writes value [0..65535] else write -1.
 * Return of 0 -> success, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_ABORTED_COMMAND, SG_LIB_CAT_NOT_READY ->
 * device not ready, -1 -> other failure */
int
sg_ll_test_unit_ready_progress(int sg_fd, int pack_id, int * progress,
                               int noisy, int verbose)
{
    int res, ret, k, sense_cat;
    unsigned char turCmdBlk[TUR_CMDLEN] = {TUR_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (verbose) {
        fprintf(sg_warnings_strm, "    test unit ready cdb: ");
        for (k = 0; k < TUR_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", turCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "test unit ready: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, turCmdBlk, sizeof(turCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_packet_id(ptvp, pack_id);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "test unit ready", res, 0, sense_b,
                               noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        if (progress) {
            int slen = get_scsi_pt_sense_len(ptvp);

            if (! sg_get_sense_progress_fld(sense_b, slen, progress))
                *progress = -1;
        }
        switch (sense_cat) {
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        default:
            ret = -1;
            break;
        }
    } else
        ret = 0;

    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI TEST UNIT READY command.
 * 'pack_id' is just for diagnostics, safe to set to 0.
 * Return of 0 -> success, SG_LIB_CAT_UNIT_ATTENTION,
 * SG_LIB_CAT_ABORTED_COMMAND, SG_LIB_CAT_NOT_READY ->
 * device not ready, -1 -> other failure */
int
sg_ll_test_unit_ready(int sg_fd, int pack_id, int noisy, int verbose)
{
    return sg_ll_test_unit_ready_progress(sg_fd, pack_id, NULL, noisy,
                                          verbose);
}

/* Invokes a SCSI REQUEST SENSE command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Request Sense not supported??,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_ABORTED_COMMAND, -1 -> other failure */
int
sg_ll_request_sense(int sg_fd, int desc, void * resp, int mx_resp_len,
                    int noisy, int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rsCmdBlk[REQUEST_SENSE_CMDLEN] =
        {REQUEST_SENSE_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    if (desc)
        rsCmdBlk[1] |= 0x1;
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (mx_resp_len > 0xff) {
        fprintf(sg_warnings_strm, "mx_resp_len cannot exceed 255\n");
        return -1;
    }
    rsCmdBlk[4] = mx_resp_len & 0xff;
    if (verbose) {
        fprintf(sg_warnings_strm, "    Request Sense cmd: ");
        for (k = 0; k < REQUEST_SENSE_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", rsCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "request sense: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rsCmdBlk, sizeof(rsCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "request sense", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_ABORTED_COMMAND:
            ret = sense_cat;
            break;
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        case SG_LIB_CAT_NOT_READY:      /* shouldn't happen ?? */
        default:
            ret = -1;
            break;
        }
    } else {
        if ((mx_resp_len >= 8) && (ret < 8)) {
            if (verbose)
                fprintf(sg_warnings_strm, "    request sense: got %d "
                        "bytes in response, too short\n", ret);
            ret = -1;
        } else
            ret = 0;
    }
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

/* Invokes a SCSI REPORT LUNS command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Report Luns not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_ABORTED_COMMAND,
 * SG_LIB_NOT_READY (shouldn't happen), -1 -> other failure */
int
sg_ll_report_luns(int sg_fd, int select_report, void * resp, int mx_resp_len,
                  int noisy, int verbose)
{
    int k, ret, res, sense_cat;
    unsigned char rlCmdBlk[REPORT_LUNS_CMDLEN] =
                         {REPORT_LUNS_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_pt_base * ptvp;

    rlCmdBlk[2] = select_report & 0xff;
    rlCmdBlk[6] = (mx_resp_len >> 24) & 0xff;
    rlCmdBlk[7] = (mx_resp_len >> 16) & 0xff;
    rlCmdBlk[8] = (mx_resp_len >> 8) & 0xff;
    rlCmdBlk[9] = mx_resp_len & 0xff;
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    if (verbose) {
        fprintf(sg_warnings_strm, "    report luns cdb: ");
        for (k = 0; k < REPORT_LUNS_CMDLEN; ++k)
            fprintf(sg_warnings_strm, "%02x ", rlCmdBlk[k]);
        fprintf(sg_warnings_strm, "\n");
    }

    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        fprintf(sg_warnings_strm, "report luns: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, rlCmdBlk, sizeof(rlCmdBlk));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, verbose);
    ret = sg_cmds_process_resp(ptvp, "report luns", res, mx_resp_len,
                               sense_b, noisy, verbose, &sense_cat);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_ABORTED_COMMAND:
        case SG_LIB_CAT_NOT_READY:      /* shouldn't happen ?? */
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

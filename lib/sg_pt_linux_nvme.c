/*
 * Copyright (c) 2017 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * The code to use the NVMe Management Interface (MI) SES pass-through
 * was provided by WDC in November 2017.
 */

/* sg_pt_linux_nvme version 1.00 20171207 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>      /* to define 'major' */
#ifndef major
#include <sys/types.h>
#endif


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <linux/major.h>

#include "sg_pt.h"
#include "sg_lib.h"
#include "sg_linux_inc.h"
#include "sg_pt_linux.h"
#include "sg_unaligned.h"

#define SCSI_INQUIRY_OPC     0x12
#define SCSI_REPORT_LUNS_OPC 0xa0
#define SCSI_TEST_UNIT_READY_OPC  0x0
#define SCSI_REQUEST_SENSE_OPC  0x3
#define SCSI_SEND_DIAGNOSTIC_OPC  0x1d
#define SCSI_RECEIVE_DIAGNOSTIC_OPC  0x1c

/* Additional Sense Code (ASC) */
#define NO_ADDITIONAL_SENSE 0x0
#define LOGICAL_UNIT_NOT_READY 0x4
#define LOGICAL_UNIT_COMMUNICATION_FAILURE 0x8
#define UNRECOVERED_READ_ERR 0x11
#define PARAMETER_LIST_LENGTH_ERR 0x1a
#define INVALID_OPCODE 0x20
#define LBA_OUT_OF_RANGE 0x21
#define INVALID_FIELD_IN_CDB 0x24
#define INVALID_FIELD_IN_PARAM_LIST 0x26
#define UA_RESET_ASC 0x29
#define UA_CHANGED_ASC 0x2a
#define TARGET_CHANGED_ASC 0x3f
#define LUNS_CHANGED_ASCQ 0x0e
#define INSUFF_RES_ASC 0x55
#define INSUFF_RES_ASCQ 0x3
#define LOW_POWER_COND_ON_ASC  0x5e     /* ASCQ=0 */
#define POWER_ON_RESET_ASCQ 0x0
#define BUS_RESET_ASCQ 0x2      /* scsi bus reset occurred */
#define MODE_CHANGED_ASCQ 0x1   /* mode parameters changed */
#define CAPACITY_CHANGED_ASCQ 0x9
#define SAVING_PARAMS_UNSUP 0x39
#define TRANSPORT_PROBLEM 0x4b
#define THRESHOLD_EXCEEDED 0x5d
#define LOW_POWER_COND_ON 0x5e
#define MISCOMPARE_VERIFY_ASC 0x1d
#define MICROCODE_CHANGED_ASCQ 0x1      /* with TARGET_CHANGED_ASC */
#define MICROCODE_CHANGED_WO_RESET_ASCQ 0x16


static inline bool is_aligned(const void * pointer, size_t byte_count)
{
       return (sg_uintptr_t)pointer % byte_count == 0;
}


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

/* The web claims that all NVMe commands are 64 bytes long. Believe it until
 * contradicted. The only SCSI commands that can be longer than 16 bytes are
 * the Variable Length Commands (opcode 0x7f) and the XCDB wrapped commands
 * (opcode 0x7e). Both have an inbuilt length field which can be cross
 * checked with clen. */
static bool
is_scsi_command(const uint8_t * cdbp, int clen)
{
    int ilen, sa;

    if (clen <= 16)
        return true;
    if (0 == (clen % 4)) {
        if (0x7f == cdbp[0]) {
            ilen = 8 + cdbp[7];
            sa = sg_get_unaligned_be16(cdbp + 8);
            if ((ilen == clen) && sa)
                return true;
        } else if (0x7e == cdbp[0]) {
            ilen = 4 + sg_get_unaligned_be16(cdbp + 2);
            if (ilen == clen)
                return true;
        }
    }
    if ((clen >= 64) && (clen <= 72))
        return false;
    pr2ws("%s: irregular command, assume NVMe:\n", __func__);
    dStrHexErr((const char *)cdbp, clen, 1);
    return false;
}

static void
build_sense_buffer(bool desc, uint8_t *buf, uint8_t skey, uint8_t asc,
                   uint8_t ascq)
{
    if (desc) {
        buf[0] = 0x72;  /* descriptor, current */
        buf[1] = skey;
        buf[2] = asc;
        buf[3] = ascq;
        buf[7] = 0;
    } else {
        buf[0] = 0x70;  /* fixed, current */
        buf[2] = skey;
        buf[7] = 0xa;   /* Assumes length is 18 bytes */
        buf[12] = asc;
        buf[13] = ascq;
    }
}

/* Set in_bit to -1 to indicate no bit position of invalid field */
static void
mk_sense_asc_ascq(struct sg_pt_linux_scsi * ptp, int sk, int asc, int ascq,
                  int vb)
{
    bool dsense = ptp->scsi_dsense;
    int n;
    uint8_t * sbp = (uint8_t *)ptp->io_hdr.response;

    ptp->io_hdr.device_status = SAM_STAT_CHECK_CONDITION;
    n = ptp->io_hdr.max_response_len;
    if ((n < 8) || ((! dsense) && (n < 14))) {
        pr2ws("%s: max_response_len=%d too short, want 14 or more\n",
              __func__, n);
        return;
    } else
        ptp->io_hdr.response_len = dsense ? 8 : ((n < 18) ? n : 18);
    memset(sbp, 0, n);
    build_sense_buffer(dsense, sbp, sk, asc, ascq);
    if (vb > 3)
        pr2ws("%s:  [sense_key,asc,ascq]: [0x5,0x%x,0x%x]\n", __func__, asc,
              ascq);
}

/* Set in_bit to -1 to indicate no bit position of invalid field */
static void
mk_sense_invalid_fld(struct sg_pt_linux_scsi * ptp, bool in_cdb, int in_byte,
                     int in_bit, int vb)
{
    bool dsense = ptp->scsi_dsense;
    int sl, asc, n;
    uint8_t * sbp = (uint8_t *)ptp->io_hdr.response;
    uint8_t sks[4];

    ptp->io_hdr.device_status = SAM_STAT_CHECK_CONDITION;
    asc = in_cdb ? INVALID_FIELD_IN_CDB : INVALID_FIELD_IN_PARAM_LIST;
    n = ptp->io_hdr.max_response_len;
    if ((n < 8) || ((! dsense) && (n < 14))) {
        pr2ws("%s: max_response_len=%d too short, want 14 or more\n",
              __func__, n);
        return;
    } else
        ptp->io_hdr.response_len = dsense ? 8 : ((n < 18) ? n : 18);
    memset(sbp, 0, n);
    build_sense_buffer(dsense, sbp, SPC_SK_ILLEGAL_REQUEST, asc, 0);
    memset(sks, 0, sizeof(sks));
    sks[0] = 0x80;
    if (in_cdb)
        sks[0] |= 0x40;
    if (in_bit >= 0) {
        sks[0] |= 0x8;
        sks[0] |= (0x7 & in_bit);
    }
    sg_put_unaligned_be16(in_byte, sks + 1);
    if (dsense) {
        sl = sbp[7] + 8;
        sbp[7] = sl;
        sbp[sl] = 0x2;
        sbp[sl + 1] = 0x6;
        memcpy(sbp + sl + 4, sks, 3);
    } else
        memcpy(sbp + 15, sks, 3);
    if (vb > 3)
        pr2ws("%s:  [sense_key,asc,ascq]: [0x5,0x%x,0x0] %c byte=%d, bit=%d\n",
              __func__, asc, in_cdb ? 'C' : 'D', in_byte, in_bit);
}

static int
do_nvme_admin_cmd(struct sg_pt_linux_scsi * ptp,
                  struct sg_nvme_passthru_cmd *cmdp, int time_secs,
                  bool cp_cmd_out2resp, int vb)
{
    const uint32_t cmd_len = sizeof(struct sg_nvme_passthru_cmd);
    uint32_t n;

    cmdp->timeout_ms = (time_secs < 0) ? 0 : (1000 * time_secs);
    if (vb > 2) {
        pr2ws("NVMe command:\n");
        dStrHex((const char *)cmdp, cmd_len, 1);
    }
    if (ioctl(ptp->dev_fd, NVME_IOCTL_ADMIN_CMD, cmdp) < 0) {
        ptp->os_err = errno;
        if (vb > 2)
            pr2ws("%s: ioctl(NVME_IOCTL_ADMIN_CMD) failed: %s (errno=%d)\n",
                  __func__, strerror(ptp->os_err), ptp->os_err);
        return -ptp->os_err;
    } else
        ptp->os_err = 0;
    ptp->nvme_result = cmdp->result;
    if (cp_cmd_out2resp) {
        n = ptp->io_hdr.max_response_len;
        if ((n > 0) && ptp->io_hdr.response) {
            n = (n < cmd_len) ? n : cmd_len;
            memcpy((uint8_t *)ptp->io_hdr.response, cmdp, n);
            ptp->io_hdr.response_len = n;
        } else
            ptp->io_hdr.response_len = 0;
    } else
        ptp->io_hdr.response_len = 0;

    if (vb > 2)
        pr2ws("%s: timeout_ms=%u, result=%u\n", __func__, cmdp->timeout_ms,
              cmdp->result);
    return 0;
}

static int
sntl_cache_identity(struct sg_pt_linux_scsi * ptp, int time_secs, int vb)
{
    int err;
    struct sg_nvme_passthru_cmd cmd;
    uint32_t pg_sz = sg_get_page_size();

    ptp->nvme_id_ctlp = sg_memalign(pg_sz, pg_sz, &ptp->free_nvme_id_ctlp,
                                    vb > 3);
    if (NULL == ptp->nvme_id_ctlp) {
        pr2ws("%s: sg_memalign() failed to get memory\n", __func__);
        return SG_LIB_OS_BASE_ERR + ENOMEM;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = 0x6;   /* Identify */
    cmd.cdw10 = 0x1;    /* CNS=0x1 Identify controller */
    cmd.addr = (uint64_t)(sg_uintptr_t)ptp->nvme_id_ctlp;
    cmd.data_len = pg_sz;
    cmd.timeout_ms = (time_secs < 0) ? 0 : (1000 * time_secs);
    if (ioctl(ptp->dev_fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
        err = errno;
        if (vb > 2)
            pr2ws("%s: ioctl(NVME_IOCTL_ADMIN_CMD) failed: %s (errno=%d)"
                  "\n", __func__, strerror(err), err);
        ptp->os_err = err;
        return -err;
    }
    return 0;
}

static const char * nvme_scsi_vendor_str = "NVMe    ";
static const uint16_t inq_resp_len = 36;

static int
sntl_inq(struct sg_pt_linux_scsi * ptp, const uint8_t * cdbp, int time_secs,
         int vb)
{
    bool evpd;
    int res;
    uint16_t k, n, alloc_len, pg_cd;
    uint8_t inq_dout[128];

    if (vb > 3)
        pr2ws("%s: time_secs=%d\n", __func__, time_secs);

    if (0x2 & cdbp[1]) {
        mk_sense_invalid_fld(ptp, true, 1, 1, vb);
        return 0;
    }
    if (NULL == ptp->nvme_id_ctlp) {
        res = sntl_cache_identity(ptp, time_secs, vb);
        if (res)
            return res;
    }
    memset(inq_dout, 0, sizeof(inq_dout));
    alloc_len = sg_get_unaligned_be16(cdbp + 3);
    evpd = !!(0x1 & cdbp[1]);
    pg_cd = cdbp[2];
    if (evpd) {         /* VPD page responses */
        switch (pg_cd) {
        case 0:
            /* inq_dout[0] = (PQ=0)<<5 | (PDT=0); prefer pdt=0xd --> SES */
            inq_dout[1] = pg_cd;
            sg_put_unaligned_be16(3, inq_dout + 2);
            inq_dout[4] = 0x0;
            inq_dout[5] = 0x80;
            inq_dout[6] = 0x83;
            n = 7;
            break;
        case 0x80:
            /* inq_dout[0] = (PQ=0)<<5 | (PDT=0); prefer pdt=0xd --> SES */
            inq_dout[1] = pg_cd;
            sg_put_unaligned_be16(20, inq_dout + 2);
            memcpy(inq_dout + 4, ptp->nvme_id_ctlp + 4, 20);    /* SN */
            n = 24;
            break;
        case 0x83:
            /* inq_dout[0] = (PQ=0)<<5 | (PDT=0); prefer pdt=0xd --> SES */
            inq_dout[1] = pg_cd;
            inq_dout[4] = 0x2;  /* Prococol id=0, code_set=2 (ASCII) */
            inq_dout[5] = 0x1;  /* PIV=0, ASSOC=0 (LU ??), desig_id=1 */
            /* Building T10 Vendor ID base designator, SNTL document 1.5
             * dated 20150624 confuses this with SCSI name string
             * descriptor, desig_id=8 */
            memcpy(inq_dout + 8, nvme_scsi_vendor_str, 8);
            memcpy(inq_dout + 16, ptp->nvme_id_ctlp + 24, 40);  /* MN */
            for (k = 40; k > 0; --k) {
                if (' ' == inq_dout[16 + k - 1])
                    inq_dout[16 + k - 1] = '_'; /* convert trailing spaces */
                else
                    break;
            }
            memcpy(inq_dout + 16 + k + 1, ptp->nvme_id_ctlp + 4, 20); /* SN */
            n = 16 + k + 1 + 20;
            inq_dout[7] = 8 + k + 1 + 20;
            sg_put_unaligned_be16(n - 4, inq_dout + 2);
            break;
        default:        /* Point to page_code field in cdb */
            mk_sense_invalid_fld(ptp, true, 2, 7, vb);
            return 0;
        }
        if (alloc_len > 0) {
            n = (alloc_len < n) ? alloc_len : n;
            n = (n < ptp->io_hdr.din_xfer_len) ? n : ptp->io_hdr.din_xfer_len;
            if (n > 0)
                memcpy((uint8_t *)ptp->io_hdr.din_xferp, inq_dout, n);
        }
    } else {            /* Standard INQUIRY response */
        /* inq_dout[0] = (PQ=0)<<5 | (PDT=0); pdt=0 --> SBC; 0xd --> SES */
        inq_dout[2] = 6;   /* version: SPC-4 */
        inq_dout[3] = 2;   /* NORMACA=0, HISUP=0, response data format: 2 */
        inq_dout[4] = 31;  /* so response length is (or could be) 36 bytes */
        inq_dout[6] = 0x40;   /* ENCSERV=1 */
        inq_dout[7] = 0x2;    /* CMDQUE=1 */
        memcpy(inq_dout + 8, nvme_scsi_vendor_str, 8);  /* NVMe not Intel */
        memcpy(inq_dout + 16, ptp->nvme_id_ctlp + 24, 16); /* Prod <-- MN */
        memcpy(inq_dout + 32, ptp->nvme_id_ctlp + 64, 4);  /* Rev <-- FR */
        if (alloc_len > 0) {
            n = (alloc_len < inq_resp_len) ? alloc_len : inq_resp_len;
            n = (n < ptp->io_hdr.din_xfer_len) ? n : ptp->io_hdr.din_xfer_len;
            if (n > 0)
                memcpy((uint8_t *)ptp->io_hdr.din_xferp, inq_dout, n);
        }
    }
    return 0;
}

static int
sntl_rluns(struct sg_pt_linux_scsi * ptp, const uint8_t * cdbp, int time_secs,
           int vb)
{
    int res;
    uint16_t sel_report;
    uint32_t alloc_len, k, n, num, max_nsid;
    uint8_t * rl_doutp;
    uint8_t * up;

    if (vb > 3)
        pr2ws("%s: time_secs=%d\n", __func__, time_secs);

    sel_report = cdbp[2];
    alloc_len = sg_get_unaligned_be32(cdbp + 6);
    if (NULL == ptp->nvme_id_ctlp) {
        res = sntl_cache_identity(ptp, time_secs, vb);
        if (res)
            return res;
    }
    max_nsid = sg_get_unaligned_le32(ptp->nvme_id_ctlp + 516);
    switch (sel_report) {
    case 0:
    case 2:
        num = max_nsid;
        break;
    case 1:
    case 0x10:
    case 0x12:
        num = 0;
        break;
    case 0x11:
        num = (1 == ptp->nvme_nsid) ? max_nsid :  0;
        break;
    default:
        if (vb > 1)
            pr2ws("%s: bad select_report value: 0x%x\n", __func__,
                  sel_report);
        mk_sense_invalid_fld(ptp, true, 2, 7, vb);
        return 0;
    }
    rl_doutp = (uint8_t *)calloc(num + 1, 8);
    if (NULL == rl_doutp) {
        pr2ws("%s: calloc() failed to get memory\n", __func__);
        return SG_LIB_OS_BASE_ERR + ENOMEM;
    }
    for (k = 0, up = rl_doutp + 8; k < num; ++k, up += 8)
        sg_put_unaligned_be16(k, up);
    n = num * 8;
    sg_put_unaligned_be32(n, rl_doutp);
    n+= 8;
    if (alloc_len > 0) {
        n = (alloc_len < n) ? alloc_len : n;
        n = (n < ptp->io_hdr.din_xfer_len) ? n : ptp->io_hdr.din_xfer_len;
        if (n > 0) {
            memcpy((uint8_t *)ptp->io_hdr.din_xferp, rl_doutp, n);
            ptp->io_hdr.din_resid = ptp->io_hdr.din_xfer_len - n;
        }
    }
    res = 0;
    free(rl_doutp);
    return res;
}

static int
sntl_tur(struct sg_pt_linux_scsi * ptp, int time_secs, int vb)
{
    int res, err;
    uint32_t pow_state;
    struct sg_nvme_passthru_cmd cmd;

    if (vb > 3)
        pr2ws("%s: time_secs=%d\n", __func__, time_secs);
    if (NULL == ptp->nvme_id_ctlp) {
        res = sntl_cache_identity(ptp, time_secs, vb);
        if (res)
            return res;
    }
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = 0xa;   /* Get feature */
    cmd.nsid = SG_NVME_BROADCAST_NSID;
    cmd.cdw10 = 0x2;    /* SEL=0 (current), Feature=2 Power Management */
    cmd.timeout_ms = (time_secs < 0) ? 0 : (1000 * time_secs);
    if (ioctl(ptp->dev_fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
        err = errno;
        if (vb > 2)
            pr2ws("%s: ioctl(NVME_ADMIN(Get feature)) failed: %s (errno=%d)"
                  "\n", __func__, strerror(err), err);
        ptp->os_err = err;
        return -err;
    }
    pow_state = (0x1f & cmd.result);
    if (vb > 3)
        pr2ws("%s: pow_state=%u\n", __func__, pow_state);
#if 0   /* pow_state bounces around too much on laptop */
    if (pow_state)
        mk_sense_asc_ascq(ptp, SPC_SK_NOT_READY, LOW_POWER_COND_ON_ASC, 0,
                          vb);
#endif
    return 0;
}

static int
sntl_req_sense(struct sg_pt_linux_scsi * ptp, const uint8_t * cdbp,
               int time_secs, int vb)
{
    bool desc;
    int res, err;
    uint32_t pow_state, alloc_len, n;
    struct sg_nvme_passthru_cmd cmd;
    uint8_t rs_dout[64];

    if (vb > 3)
        pr2ws("%s: time_secs=%d\n", __func__, time_secs);
    if (NULL == ptp->nvme_id_ctlp) {
        res = sntl_cache_identity(ptp, time_secs, vb);
        if (res)
            return res;
    }
    desc = !!(0x1 & cdbp[1]);
    alloc_len = cdbp[4];
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = 0xa;   /* Get feature */
    cmd.nsid = SG_NVME_BROADCAST_NSID;
    cmd.cdw10 = 0x2;    /* SEL=0 (current), Feature=2 Power Management */
    cmd.timeout_ms = (time_secs < 0) ? 0 : (1000 * time_secs);
    if (ioctl(ptp->dev_fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
        err = errno;
        if (vb > 2)
            pr2ws("%s: ioctl(NVME_ADMIN(Get feature)) failed: %s (errno=%d)"
                  "\n", __func__, strerror(err), err);
        ptp->os_err = err;
        return -err;
    }
    pow_state = (0x1f & cmd.result);
    if (vb > 3)
        pr2ws("%s: pow_state=%u\n", __func__, pow_state);
    memset(rs_dout, 0, sizeof(rs_dout));
    if (pow_state)
            build_sense_buffer(desc, rs_dout, SPC_SK_NO_SENSE,
                               LOW_POWER_COND_ON_ASC, 0);
    else
            build_sense_buffer(desc, rs_dout, SPC_SK_NO_SENSE,
                               NO_ADDITIONAL_SENSE, 0);
    n = desc ? 8 : 18;
    n = (n < alloc_len) ? n : alloc_len;
    n = (n < ptp->io_hdr.din_xfer_len) ? n : ptp->io_hdr.din_xfer_len;
    if (n > 0) {
        memcpy((uint8_t *)ptp->io_hdr.din_xferp, rs_dout, n);
        ptp->io_hdr.din_resid = ptp->io_hdr.din_xfer_len - n;
    }
    return 0;
}

/* This is not really a SNTL. For SCSI SEND DIAGNOSTIC(PF=1) NVMe-MI
 * has a special command (SES Send) to tunnel through pages to an
 * enclosure. The NVMe enclosure is meant to understand the SES
 * (SCSI Enclosure Services) use of diagnostics pages that are
 * related to SES. */
static int
sntl_senddiag(struct sg_pt_linux_scsi * ptp, const uint8_t * cdbp,
              int time_secs, int vb)
{
    bool pf, self_test;
    uint8_t st_cd, dpg_cd;
    uint32_t alloc_len, n, dout_len, dpg_len;
    uint32_t pg_sz = sg_get_page_size();
    const uint8_t * dop;
    struct sg_nvme_passthru_cmd cmd;

    st_cd = 0x7 & (cdbp[1] >> 5);
    pf = !! (0x4 & cdbp[1]);
    self_test = !! (0x10 & cdbp[1]);
    if (vb > 3)
        pr2ws("%s: pf=%d, self_test=%d (st_code=%d)\n", __func__, (int)pf,
              (int)self_test, (int)st_cd);
    if (self_test)
        return 0;       /* NVMe has no self-test, just say OK */
    alloc_len = sg_get_unaligned_be16(cdbp + 3); /* parameter list length */
    dout_len = ptp->io_hdr.dout_xfer_len;
    if (pf) {
        if (0 == alloc_len) {
            mk_sense_invalid_fld(ptp, true, 3, 7, vb);
            if (vb)
                pr2ws("%s: PF bit set bit param_list_len=0\n", __func__);
            return 0;
        }
    } else {    /* PF bit clear */
        if (alloc_len) {
            mk_sense_invalid_fld(ptp, true, 3, 7, vb);
            if (vb)
                pr2ws("%s: param_list_len>0 but PF clear\n", __func__);
            return 0;
        } else
            return 0;     /* nothing to do */
        if (dout_len > 0) {
            if (vb)
                pr2ws("%s: dout given but PF clear\n", __func__);
            return SCSI_PT_DO_BAD_PARAMS;
        }
    }
    if (dout_len < 4) {
        if (vb)
            pr2ws("%s: dout length (%u bytes) too short\n", __func__,
                  dout_len);
        return SCSI_PT_DO_BAD_PARAMS;
    }
    n = dout_len;
    n = (n < alloc_len) ? n : alloc_len;
    dop = (const uint8_t *)ptp->io_hdr.dout_xferp;
    if (! is_aligned(dop, pg_sz)) {  /* caller best use sg_memalign(,pg_sz) */
        if (vb)
            pr2ws("%s: dout [0x%" PRIx64 "] not page aligned\n", __func__,
                  (uint64_t)ptp->io_hdr.dout_xferp);
        return SCSI_PT_DO_BAD_PARAMS;
    }
    dpg_cd = dop[0];
    dpg_len = sg_get_unaligned_be16(dop + 2) + 4;
    /* should we allow for more than one D_PG is dout ?? */
    n = (n < dpg_len) ? n : dpg_len;    /* not yet ... */

    if (vb)
        pr2ws("%s: passing through d_pg=0x%x, len=%u to NVME_MI SES send\n",
              __func__, dpg_cd, dpg_len);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = 0x1d;  /* MI send; hmmm same opcode as SEND DIAG */
    cmd.addr = (uint64_t)(sg_uintptr_t)ptp->io_hdr.dout_xferp;
    cmd.data_len = 0x1000;   /* NVMe 4k page size. Maybe determine this? */
                             /* dout_len > 0x1000, is this a problem?? */
    cmd.cdw10 = 0x0804;      /* NVMe Message Header */
    cmd.cdw11 = 0x9;         /* nvme_mi_ses_send; (0x8 -> mi_ses_recv) */
    cmd.cdw13 = n;
    return do_nvme_admin_cmd(ptp, &cmd, time_secs, false, vb);
}

/* This is not really a SNTL. For SCSI RECEIVE DIAGNOSTIC RESULTS(PCV=1)
 * NVMe-MI has a special command (SES Receive) to read pages through a
 * tunnel from an enclosure. The NVMe enclosure is meant to understand the
 * SES (SCSI Enclosure Services) use of diagnostics pages that are
 * related to SES. */
static int
sntl_recvdiag(struct sg_pt_linux_scsi * ptp, const uint8_t * cdbp,
              int time_secs, int vb)
{
    bool pcv;
    int res;
    uint8_t dpg_cd;
    uint32_t alloc_len, n, din_len;
    uint32_t pg_sz = sg_get_page_size();
    const uint8_t * dip;
    struct sg_nvme_passthru_cmd cmd;

    pcv = !! (0x1 & cdbp[1]);
    dpg_cd = cdbp[2];
    alloc_len = sg_get_unaligned_be16(cdbp + 3); /* parameter list length */
    if (vb > 3)
        pr2ws("%s: dpg_cd=0x%x, pcv=%d, alloc_len=0x%x\n", __func__,
              dpg_cd, (int)pcv, alloc_len);
    din_len = ptp->io_hdr.din_xfer_len;
    if (pcv) {
        if (0 == alloc_len) {
            /* T10 says not an error, hmmm */
            mk_sense_invalid_fld(ptp, true, 3, 7, vb);
            if (vb)
                pr2ws("%s: PCV bit set bit but alloc_len=0\n", __func__);
            return 0;
        }
    } else {    /* PCV bit clear */
        if (alloc_len) {
            mk_sense_invalid_fld(ptp, true, 3, 7, vb);
            if (vb)
                pr2ws("%s: alloc_len>0 but PCV clear\n", __func__);
            return 0;
        } else
            return 0;     /* nothing to do */
        if (din_len > 0) {
            if (vb)
                pr2ws("%s: din given but PCV clear\n", __func__);
            return SCSI_PT_DO_BAD_PARAMS;
        }
    }
    n = din_len;
    n = (n < alloc_len) ? n : alloc_len;
    dip = (const uint8_t *)ptp->io_hdr.din_xferp;
    if (! is_aligned(dip, pg_sz)) {  /* caller best use sg_memalign(,pg_sz) */
        if (vb)
            pr2ws("%s: din [0x%" PRIx64 "] not page aligned\n", __func__,
                  (uint64_t)ptp->io_hdr.din_xferp);
        return SCSI_PT_DO_BAD_PARAMS;
    }

    if (vb)
        pr2ws("%s: expecting d_pg=0x%x from NVME_MI SES receive\n", __func__,
              dpg_cd);
    memset(&cmd, 0, sizeof(cmd));
    cmd.opcode = 0x1e;  /* MI receive */
    cmd.addr = (uint64_t)(sg_uintptr_t)ptp->io_hdr.din_xferp;
    cmd.data_len = 0x1000;   /* NVMe 4k page size. Maybe determine this? */
                             /* din_len > 0x1000, is this a problem?? */
    cmd.cdw10 = 0x0804;      /* NVMe Message Header */
    cmd.cdw11 = 0x8;         /* nvme_mi_ses_receive */
    cmd.cdw12 = dpg_cd;
    cmd.cdw13 = n;
    res = do_nvme_admin_cmd(ptp, &cmd, time_secs, false, vb);
    ptp->io_hdr.din_resid = din_len - n;
    return res;
}

/* Executes NVMe Admin command (or at least forwards it to lower layers).
 * Returns 0 for success, negative numbers are negated 'errno' values from
 * OS system calls. Positive return values are errors from this package.
 * When time_secs is 0 the Linux NVMe Admin command default of 60 seconds
 * is used. */
int
sg_do_nvme_pt(struct sg_pt_base * vp, int fd, int time_secs, int vb)
{
    bool scsi_cmd;
    int n, len;
    struct sg_pt_linux_scsi * ptp = &vp->impl;
    struct sg_nvme_passthru_cmd cmd;
    const uint8_t * cdbp;

    if (! ptp->io_hdr.request) {
        if (vb)
            pr2ws("No NVMe command given (set_scsi_pt_cdb())\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }
    if (fd >= 0) {
        if ((ptp->dev_fd >= 0) && (fd != ptp->dev_fd)) {
            if (vb)
                pr2ws("%s: file descriptor given to create() and here "
                      "differ\n", __func__);
            return SCSI_PT_DO_BAD_PARAMS;
        }
        ptp->dev_fd = fd;
    } else if (ptp->dev_fd < 0) {
        if (vb)
            pr2ws("%s: invalid file descriptors\n", __func__);
        return SCSI_PT_DO_BAD_PARAMS;
    }
    n = ptp->io_hdr.request_len;
    cdbp = (const uint8_t *)ptp->io_hdr.request;
    if (vb > 3)
        pr2ws("%s: opcode=0x%x, fd=%d, time_secs=%d\n", __func__, cdbp[0],
              fd, time_secs);
    scsi_cmd = is_scsi_command(cdbp, n);
    if (scsi_cmd) {
        switch (cdbp[0]) {
        case SCSI_INQUIRY_OPC:
            return sntl_inq(ptp, cdbp, time_secs, vb);
        case SCSI_REPORT_LUNS_OPC:
            return sntl_rluns(ptp, cdbp, time_secs, vb);
        case SCSI_TEST_UNIT_READY_OPC:
            return sntl_tur(ptp, time_secs, vb);
        case SCSI_REQUEST_SENSE_OPC:
            return sntl_req_sense(ptp, cdbp, time_secs, vb);
        case SCSI_SEND_DIAGNOSTIC_OPC:
            return sntl_senddiag(ptp, cdbp, time_secs, vb);
        case SCSI_RECEIVE_DIAGNOSTIC_OPC:
            return sntl_recvdiag(ptp, cdbp, time_secs, vb);
// xxxxxxxxxx
        default:
            mk_sense_asc_ascq(ptp, SPC_SK_ILLEGAL_REQUEST, INVALID_OPCODE,
                              0, vb);
            return 0;
        }
    }
    len = (int)sizeof(cmd);
    n = (n < len) ? n : len;
    if (n < 64) {
        if (vb)
            pr2ws("%s: command length of %d bytes is too short\n", __func__,
                  n);
        return SCSI_PT_DO_BAD_PARAMS;
    }
    memcpy(&cmd, (const uint8_t *)ptp->io_hdr.request, n);
    if (n < len)        /* zero out rest of 'cmd' */
        memset((unsigned char *)&cmd + n, 0, len - n);
    if (ptp->io_hdr.din_xfer_len > 0) {
        cmd.data_len = ptp->io_hdr.din_xfer_len;
        cmd.addr = (uint64_t)(sg_uintptr_t)ptp->io_hdr.din_xferp;
    } else if (ptp->io_hdr.dout_xfer_len > 0) {
        cmd.data_len = ptp->io_hdr.dout_xfer_len;
        cmd.addr = (uint64_t)(sg_uintptr_t)ptp->io_hdr.dout_xferp;
    }
    return do_nvme_admin_cmd(ptp, &cmd, time_secs, true, vb);
}

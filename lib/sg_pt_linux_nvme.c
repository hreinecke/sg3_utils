PROPS-END
/*
 * Copyright (c) 2017 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

/* sg_pt_linux_nvme version 1.00 20171206 */


#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
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
#define SCSI_TEST_UNIT_READY_OPC  0x0

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

#if (__STDC_VERSION__ >= 199901L)  /* C99 or later */
typedef intptr_t sg_uintptr_t;
#else
typedef long sg_uintptr_t;
#endif


static inline bool is_aligned(const void *restrict pointer,
                              size_t byte_count)
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
build_sense_buffer(bool desc, uint8_t *buf, uint8_t key, uint8_t asc,
                   uint8_t ascq)
{
    if (desc) {
        buf[0] = 0x72;  /* descriptor, current */
        buf[1] = key;
        buf[2] = asc;
        buf[3] = ascq;
        buf[7] = 0;
    } else {
        buf[0] = 0x70;  /* fixed, current */
        buf[2] = key;
        buf[7] = 0xa;
        buf[12] = asc;
        buf[13] = ascq;
    }
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
    if (vb > 1)
        pr2ws("%s:  [sense_key,asc,ascq]: [0x5,0x%x,0x0] %c byte=%d, bit=%d\n",
              __func__, asc, in_cdb ? 'C' : 'D', in_byte, in_bit);
}

static const char * nvme_scsi_vendor_str = "NVMe    ";
static const uint16_t inq_resp_len = 36;

static int
sntl_inq(struct sg_pt_linux_scsi * ptp, const uint8_t * cdbp, int fd,
         int time_secs, int vb)
{
    bool evpd;
    int err;
    uint16_t k, n, alloc_len, pg_cd;
    uint8_t inq_dout[128];

    if (vb > 3)
        pr2ws("%s: fd=%d, time_secs=%d\n", __func__, fd, time_secs);

    if (0x2 & cdbp[1]) {
        mk_sense_invalid_fld(ptp, true, 1, 1, vb);
        return 0;
    }
    if (NULL == ptp->nvme_id_ctlp) {
        struct sg_nvme_passthru_cmd cmd;
        uint32_t pg_sz = sg_get_page_size();

        ptp->nvme_id_ctlp = sg_memalign(pg_sz, pg_sz, &ptp->free_nvme_id_ctlp,
                                        vb > 3);
        if (NULL == ptp->nvme_id_ctlp) {
            pr2ws("%s: sg_memalign() failed to get memory\n", __func__);
            return SG_LIB_OS_BASE_ERR + ENOMEM;
        }
        memset(&cmd, 0, sizeof(cmd));
        cmd.opcode = 0x6;
        cmd.cdw10 = 0x1;       /* CNS=0x1 Identify controller */
        cmd.addr = (uint64_t)ptp->nvme_id_ctlp;
        cmd.data_len = pg_sz;
        if (ioctl(ptp->dev_fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
            err = errno;
            if (vb > 2)
                pr2ws("%s: ioctl(NVME_IOCTL_ADMIN_CMD) failed: %s (errno=%d)"
                      "\n", __func__, strerror(err), err);
            ptp->os_err = err;
            return -err;
        }
    }
    memset(inq_dout, 0, sizeof(inq_dout));
    alloc_len = sg_get_unaligned_be16(cdbp + 3);
    evpd = !!(0x1 & cdbp[1]);
    pg_cd = cdbp[2];
    if (evpd) {         /* VPD page responses */
        inq_dout[1] = pg_cd;
        n = 0;
        switch (pg_cd) {
        case 0:
            /* inq_dout[0] = (PQ=0)<<5 | (PDT=0); prefer pdt=0xd --> SES */
            sg_put_unaligned_be16(3, inq_dout + 2);
            inq_dout[4] = 0x0;
            inq_dout[5] = 0x80;
            inq_dout[6] = 0x83;
            n = 7;
            break;
        case 0x80:
            /* inq_dout[0] = (PQ=0)<<5 | (PDT=0); prefer pdt=0xd --> SES */
            sg_put_unaligned_be16(20, inq_dout + 2);
            memcpy(inq_dout + 4, ptp->nvme_id_ctlp + 4, 20);    /* SN */
            n = 24;
            break;
        case 0x83:
            /* inq_dout[0] = (PQ=0)<<5 | (PDT=0); prefer pdt=0xd --> SES */
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

    if (vb > 4)
        pr2ws("%s: fd=%d, time_secs=%d\n", __func__, fd, time_secs);
    if (! ptp->io_hdr.request) {
        if (vb)
            pr2ws("No NVMe command given (set_scsi_pt_cdb())\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }
    n = ptp->io_hdr.request_len;
    cdbp = (const uint8_t *)ptp->io_hdr.request;
    scsi_cmd = is_scsi_command(cdbp, n);
    if (scsi_cmd) {
        if (SCSI_INQUIRY_OPC == cdbp[0])
            return sntl_inq(ptp, cdbp, fd, time_secs, vb);

    }
    len = (int)sizeof(cmd);
    n = (n < len) ? n : len;
    if (n < 64) {
        if (vb)
            pr2ws("%s: command length of %d bytes is too short\n", __func__,
                  n);
        return SCSI_PT_DO_BAD_PARAMS;
    }
    memcpy(&cmd, (unsigned char *)ptp->io_hdr.request, n);
    if (n < len)        /* zero out rest of 'cmd' */
        memset((unsigned char *)&cmd + n, 0, len - n);
    if (ptp->io_hdr.din_xfer_len > 0) {
        cmd.data_len = ptp->io_hdr.din_xfer_len;
        cmd.addr = (__u64)(sg_uintptr_t)ptp->io_hdr.din_xferp;
    } else if (ptp->io_hdr.dout_xfer_len > 0) {
        cmd.data_len = ptp->io_hdr.dout_xfer_len;
        cmd.addr = (__u64)(sg_uintptr_t)ptp->io_hdr.dout_xferp;
    }
    if (time_secs < 0)
        cmd.timeout_ms = 0;
    else
        cmd.timeout_ms = 1000 * cmd.timeout_ms;
    if (vb > 2) {
        pr2ws("NVMe command:\n");
        dStrHex((const char *)&cmd, len, 1);
    }
    if (ioctl(ptp->dev_fd, NVME_IOCTL_ADMIN_CMD, &cmd) < 0) {
        ptp->os_err = errno;
        if (vb > 2)
            pr2ws("%s: ioctl(NVME_IOCTL_ADMIN_CMD) failed: %s (errno=%d)\n",
                  __func__, strerror(ptp->os_err), ptp->os_err);
        return -ptp->os_err;
    } else
        ptp->os_err = 0;
    ptp->nvme_result = cmd.result;
    n = ptp->io_hdr.max_response_len;
    if ((n > 0) && ptp->io_hdr.response) {
        n = (n < len) ? n : len;
        memcpy((uint8_t *)ptp->io_hdr.response, &cmd, n);
        ptp->io_hdr.response_len = n;
    }
    if (vb > 2)
        pr2ws("%s: timeout_ms=%u, result=%u\n", __func__, cmd.timeout_ms,
              cmd.result);
    return 0;
}

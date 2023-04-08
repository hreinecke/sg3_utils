/*
 * Copyright (c) 2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <sys/device.h>
#include <sys/param.h>
#include <sys/sysctl.h>

#include <sys/scsiio.h>

#include "sg_pt.h"
#include "sg_lib.h"
#include "sg_pr2serr.h"

/* Version 1.00 20230402 */

/* List of function names with external linkage that need to be defined
 *
 *   check_pt_file_handle
 *   clear_scsi_pt_obj
 *   construct_scsi_pt_obj
 *   construct_scsi_pt_obj_with_fd
 *   destruct_scsi_pt_obj
 *   do_scsi_pt
 *   do_nvm_pt
 *   get_pt_actual_lengths
 *   get_pt_duration_ns
 *   get_pt_file_handle
 *   get_pt_nvme_nsid
 *   get_pt_req_lengths
 *   get_pt_result
 *   get_scsi_pt_cdb_buf
 *   get_scsi_pt_cdb_len
 *   get_scsi_pt_duration_ms
 *   get_scsi_pt_os_err
 *   get_scsi_pt_os_err_str
 *   get_scsi_pt_resid
 *   get_scsi_pt_result_category
 *   get_scsi_pt_sense_buf
 *   get_scsi_pt_sense_len
 *   get_scsi_pt_status_response
 *   get_scsi_pt_transport_err
 *   get_scsi_pt_transport_err_str
 *   partial_clear_scsi_pt_obj
 *   pt_device_is_nvme
 *   scsi_pt_close_device
 *   scsi_pt_open_device
 *   scsi_pt_open_flags
 *   set_pt_file_handle
 *   set_pt_metadata_xfer
 *   set_scsi_pt_cdb
 *   set_scsi_pt_data_in
 *   set_scsi_pt_data_out
 *   set_scsi_pt_flags
 *   set_scsi_pt_packet_id
 *   set_scsi_pt_sense
 *   set_scsi_pt_tag
 *   set_scsi_pt_task_attr
 *   set_scsi_pt_task_management
 *   set_scsi_pt_transport_err
 */

/* In NetBSD, the standard SCSI system administration utility is called
 * 'scsisctl' which looks similar in functionality to FreeBSD's camcontrol. */

#define DEF_TIMEOUT_MS 60000

/* Simply defines all the functions needed by the pt interface (see sg_pt.h).
 * They do nothing. This allows decoding of hex files (e.g. with the --in=
 * or --inhex= option) with utilities like sg_vpd and sg_logs. */

struct sg_pt_netbsd {
    struct scsireq sc;
    uint8_t * sensep;
    const uint8_t * cdbp;
    uint64_t tag;
    // int data_len;
    int in_err;
    int os_err;
    int transport_err;  /* always zero currently */
    int pack_id;
    int dev_fd;
};

struct sg_pt_base {
    struct sg_pt_netbsd impl;
};


/* Returns >= 0 if successful. If error in Unix returns negated errno. */
int
scsi_pt_open_device(const char * device_name, bool read_only, int verbose)
{
    int oflags = 0 /* O_NONBLOCK*/ ;

    oflags |= (read_only ? O_RDONLY : O_RDWR);
    return scsi_pt_open_flags(device_name, oflags, verbose);
}

/* Similar to scsi_pt_open_device() but takes Unix style open flags OR-ed
 * together. The 'flags' argument is ignored in OSF-1.
 * Returns >= 0 if successful, otherwise returns negated errno. */
int
scsi_pt_open_flags(const char * device_name, int flags, int verbose)
{
    int fd;
    int oflags = flags | O_NONBLOCK;

    fd = open(device_name, oflags);
    if (fd < 0)
        fd = -errno;
    if (verbose > 1)
        fprintf(sg_warnings_strm ? sg_warnings_strm : stderr,
                "open %s with flags=0x%x --> fd=%d\n", device_name, oflags,
                fd);
    return fd;
}

/* Returns 0 if successful. If error in Unix returns negated errno. */
int
scsi_pt_close_device(int device_fd)
{
    if (device_fd >= 0)
        close(device_fd);
    return 0;
}

struct sg_pt_base *
construct_scsi_pt_obj_with_fd(int device_fd, int verbose)
{
    struct sg_pt_netbsd * ptp;

    ptp = (struct sg_pt_netbsd *)malloc(sizeof(struct sg_pt_netbsd));
    if (ptp) {
        memset(ptp, 0, sizeof(struct sg_pt_netbsd));
        ptp->dev_fd = (device_fd < 0) ? -1 : device_fd;
        ptp->sc.flags = SCCMD_READ;     /* also used for no data-in or out */
        ptp->sc.timeout = DEF_TIMEOUT_MS;
    } else if (verbose)
        pr2ws("%s: malloc() out of memory\n", __func__);
    return (struct sg_pt_base *)ptp;
}

struct sg_pt_base *
construct_scsi_pt_obj(void)
{
    return construct_scsi_pt_obj_with_fd(-1, 0);
}

void
destruct_scsi_pt_obj(struct sg_pt_base * vp)
{
    if (vp) {
        struct sg_pt_netbsd * ptp = &vp->impl;

        free(ptp);
    }
}

void
clear_scsi_pt_obj(struct sg_pt_base * vp)
{
    if (vp) {
        struct sg_pt_netbsd * ptp = &vp->impl;

        int fd = ptp->dev_fd;

        memset(ptp, 0, sizeof(struct sg_pt_netbsd));
        ptp->dev_fd = fd;
    }
}

void
partial_clear_scsi_pt_obj(struct sg_pt_base * vp)
{
    if (vp) {
        struct sg_pt_netbsd * ptp = &vp->impl;

        /* keep ptp->dev_fd, cdb and sense */
        ptp->in_err = 0;
        ptp->os_err = 0;
        ptp->transport_err = 0;
        ptp->pack_id = 0;
        ptp->tag = 0;
        ptp->sc.datalen = 0;
        ptp->sc.databuf = NULL;
    }
}

void
set_scsi_pt_cdb(struct sg_pt_base * vp, const uint8_t * cdb,
                int cdb_len)
{
    struct sg_pt_netbsd * ptp = &vp->impl;
    static const int max_cdb_len = sizeof(ptp->sc.cmd);

    if (cdb_len > max_cdb_len)
        ++ptp->in_err;
    else {
        if (cdb_len > 0)
            memcpy(ptp->sc.cmd, cdb, cdb_len);
        ptp->cdbp = cdb;
        ptp->sc.cmdlen = cdb_len;
    }
}

int
get_scsi_pt_cdb_len(const struct sg_pt_base * vp)
{
    const struct sg_pt_netbsd * ptp = &vp->impl;

    return ptp->sc.cmdlen;
}

uint8_t *
get_scsi_pt_cdb_buf(const struct sg_pt_base * vp)
{
    const struct sg_pt_netbsd * ptp = &vp->impl;

    return (uint8_t *)ptp->cdbp;
}

void
set_scsi_pt_sense(struct sg_pt_base * vp, uint8_t * sense,
                  int max_sense_len)
{
    struct sg_pt_netbsd * ptp = &vp->impl;

    ptp->sc.senselen = (max_sense_len > SENSEBUFLEN) ? SENSEBUFLEN :
                                                       max_sense_len;
    ptp->sensep = sense;
}

/* from device */
void
set_scsi_pt_data_in(struct sg_pt_base * vp, uint8_t * dxferp,
                    int dxfer_len)
{
    struct sg_pt_netbsd * ptp = &vp->impl;

    if (dxferp && ptp->sc.databuf)
        ++ptp->in_err;
    ptp->sc.databuf = dxferp;
    ptp->sc.datalen = dxfer_len;
    ptp->sc.flags = SCCMD_READ;
}

/* to device */
void
set_scsi_pt_data_out(struct sg_pt_base * vp, const uint8_t * dxferp,
                     int dxfer_len)
{
    struct sg_pt_netbsd * ptp = &vp->impl;

    if (dxferp && ptp->sc.databuf)
        ++ptp->in_err;
    ptp->sc.databuf = (uint8_t *)dxferp;
    ptp->sc.datalen = dxfer_len;
    ptp->sc.flags = SCCMD_WRITE;
}

void
set_scsi_pt_packet_id(struct sg_pt_base * vp, int pack_id)
{
    if (vp) {
        struct sg_pt_netbsd * ptp = &vp->impl;

        ptp->pack_id = pack_id;
    }
}

void
set_scsi_pt_tag(struct sg_pt_base * vp, uint64_t tag)
{
    if (vp) {
        struct sg_pt_netbsd * ptp = &vp->impl;

        ptp->tag = tag;
    }
}

void
set_scsi_pt_task_management(struct sg_pt_base * vp, int tmf_code)
{
    if (vp) {
        struct sg_pt_netbsd * ptp = &vp->impl;

        ++ptp->in_err;
    }
    if (tmf_code) {}
}

void
set_scsi_pt_task_attr(struct sg_pt_base * vp, int attrib, int priority)
{
    if (vp) {}
    if (attrib) {}
    if (priority) {}
}

void
set_scsi_pt_flags(struct sg_pt_base * vp, int flags)
{
    if (vp) {}
    if (flags) {}
}

int
do_scsi_pt(struct sg_pt_base * vp, int device_fd, int time_secs, int verbose)
{
    int ret = SCSI_PT_DO_START_OK;
    struct sg_pt_netbsd * ptp;
    FILE * ferr = sg_warnings_strm ? sg_warnings_strm : stderr;

    if (NULL == vp) {
            fprintf(ferr, "%s: sg_pt_base is NULL, bad\n", __func__);
    }
    ptp = (struct sg_pt_netbsd *)&vp->impl;
    ptp->os_err = 0;
    if (ptp->in_err) {
        if (verbose) {
            if (ptp->in_err)
                fprintf(ferr, "NetBSD cdb length is 16, or some "
                        "other problem\n");
            else
                fprintf(ferr, "Replicated or unused set_scsi_pt... "
                        "functions\n");
        }
        return SCSI_PT_DO_BAD_PARAMS;
    }
    if (device_fd < 0) {
        if (ptp->dev_fd < 0) {
            if (verbose)
                fprintf(ferr, "%s: No device file descriptor given\n",
                        __func__);
            return SCSI_PT_DO_BAD_PARAMS;
        }
    } else {
        if (ptp->dev_fd >= 0) {
            if (device_fd != ptp->dev_fd) {
                if (verbose)
                    fprintf(ferr, "%s: file descriptor given to create and "
                            "this differ\n", __func__);
                return SCSI_PT_DO_BAD_PARAMS;
            }
        } else
            ptp->dev_fd = device_fd;
    }
    if (0 == ptp->sc.cmdlen) {
        if (verbose)
            fprintf(ferr, "%s: No SCSI command (cdb) given\n", __func__);
        return SCSI_PT_DO_BAD_PARAMS;
    }
    if (time_secs > 0)
        ptp->sc.timeout = 1000 * time_secs;
    else if (ptp->sc.timeout <= 0)
        ptp->sc.timeout = DEF_TIMEOUT_MS;
    /* else we go with value in ptp->sc.timeout */
    ptp->sc.timeout = (time_secs == 0) ? 60000 : (1000 * time_secs);

    /* code taken from smartmontools rev 5470 file: os_netbsd.cpp  */
    if (ioctl(ptp->dev_fd, SCIOCCOMMAND, &ptp->sc) < 0) {
        ptp->os_err = errno;
        if ((EIO == ptp->os_err) && (SCCMD_SENSE == ptp->sc.retsts)) {
            ptp->os_err = 0;
            return 0;
        }
        if (verbose)
            fprintf(ferr, "%s: ioctl(SCIOCCOMMAND) failed with os_err "
                    "(errno) = %d\n", __func__, ptp->os_err);
        return -ptp->os_err;
    }
    /* sc.status: 'scsi status was from the adapter' , huh?? */
    ptp->transport_err = ptp->sc.status;
    if (ptp->sensep && (ptp->sc.senselen_used > 0))
        memcpy(ptp->sensep, ptp->sc.sense, ptp->sc.senselen_used);

    switch (ptp->sc.retsts) {
    case SCCMD_OK:
        break;
    case SCCMD_TIMEOUT:
        ret = SCSI_PT_DO_TIMEOUT;
        break;
    case SCCMD_BUSY:
        ptp->os_err = EBUSY;
        break;
    case SCCMD_SENSE:
        break;
    default:    /* SCCMD_UNKNOWN and ??? */
        ptp->os_err = EIO;
        break;
    }
    return ret;
}

int
get_scsi_pt_result_category(const struct sg_pt_base * vp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;

        if (ptp->os_err)
            return SCSI_PT_RESULT_OS_ERR;
        else if (ptp->transport_err)
            return SCSI_PT_RESULT_TRANSPORT_ERR;
        else if (SCCMD_OK == ptp->sc.retsts)
            return SCSI_PT_RESULT_GOOD;
        else if (SCCMD_SENSE == ptp->sc.retsts)
            return SCSI_PT_RESULT_SENSE;
        else    /* not sure about this */
            return SCSI_PT_RESULT_STATUS;
    } else
        return SCSI_PT_RESULT_GOOD;
}

int
get_scsi_pt_resid(const struct sg_pt_base * vp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;

        return ptp->sc.datalen - ptp->sc.datalen_used;
    }
    return 0;
}

void
get_pt_req_lengths(const struct sg_pt_base * vp, int * req_dinp,
                   int * req_doutp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;
        int flags = ptp->sc.flags;

        if (req_dinp)
            *req_dinp = (SCCMD_READ & flags) ? ptp->sc.datalen : 0;
        if (req_doutp)
            *req_doutp = (SCCMD_WRITE & flags) ? ptp->sc.datalen : 0;
    } else {
        if (req_dinp)
            *req_dinp = 0;
        if (req_doutp)
            *req_doutp = 0;
    }
}

void
get_pt_actual_lengths(const struct sg_pt_base * vp, int * act_dinp,
                      int * act_doutp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;
        int flags = ptp->sc.flags;

        if (act_dinp)
            *act_dinp = (SCCMD_READ & flags) ? ptp->sc.datalen_used : 0;
        if (act_doutp)
            *act_doutp = (SCCMD_WRITE & flags) ? ptp->sc.datalen_used : 0;
    } else {
        if (act_dinp)
            *act_dinp = 0;
        if (act_doutp)
            *act_doutp = 0;
    }
}


int
get_scsi_pt_status_response(const struct sg_pt_base * vp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;

        return (SCCMD_SENSE == ptp->sc.retsts) ? SAM_STAT_GOOD :
                                                 SAM_STAT_CHECK_CONDITION;
    }
    return SAM_STAT_GOOD;
}

int
get_scsi_pt_sense_len(const struct sg_pt_base * vp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;

        return ptp->sc.senselen_used;
    }
    return 0;
}

uint8_t *
get_scsi_pt_sense_buf(const struct sg_pt_base * vp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;

        return ptp->sensep;
    }
    return NULL;
}

int
get_scsi_pt_duration_ms(const struct sg_pt_base * vp)
{
    if (vp) {}
    return 0;
}

/* If not available return 0 otherwise return number of nanoseconds that the
 * lower layers (and hardware) took to execute the command just completed. */
uint64_t
get_pt_duration_ns(const struct sg_pt_base * vp __attribute__ ((unused)))
{
    return 0;
}

int
get_scsi_pt_transport_err(const struct sg_pt_base * vp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;

        return ptp->transport_err;
    }
    return 0;
}

int
get_scsi_pt_os_err(const struct sg_pt_base * vp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;

        return ptp->os_err;
    }
    return 0;
}

bool
pt_device_is_nvme(const struct sg_pt_base * vp)
{
    if (vp) {}
    return false;
}

char *
get_scsi_pt_transport_err_str(const struct sg_pt_base * vp, int max_b_len,
                              char * b)
{
    if (vp) {}
    if (max_b_len) {}
    if (b) {}
    return NULL;
}

char *
get_scsi_pt_os_err_str(const struct sg_pt_base * vp, int max_b_len, char * b)
{
    if (vp) {}
    if (max_b_len) {}
    if (b) {}
    return NULL;
}

int
do_nvm_pt(struct sg_pt_base * vp, int submq, int timeout_secs, int verbose)
{
    if (vp) { }
    if (submq) { }
    if (timeout_secs) { }
    if (verbose) { }
    return SCSI_PT_DO_NOT_SUPPORTED;
}

int
check_pt_file_handle(int device_fd, const char * device_name, int vb)
{
    if (device_fd) {}
    if (device_name) {}
    if (vb) {}
    return 0;
}

/* Valid file handles (which is the return value) are >= 0 . Returns -1
 * if there is no valid file handle. */
int
get_pt_file_handle(const struct sg_pt_base * vp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;

        return ptp->dev_fd;
    }
    return -1;
}

/* If a NVMe block device (which includes the NSID) handle is associated
 * with 'vp', then its NSID is returned (values range from 0x1 to
 * 0xffffffe). Otherwise 0 is returned. */
uint32_t
get_pt_nvme_nsid(const struct sg_pt_base * vp)
{
    if (vp) { }
    return 0;
}

uint32_t
get_pt_result(const struct sg_pt_base * vp)
{
    if (vp) {
        const struct sg_pt_netbsd * ptp = &vp->impl;

        switch (ptp->sc.retsts) {
        case SCCMD_OK:
            return SAM_STAT_GOOD;
        default:
            return SAM_STAT_CHECK_CONDITION;
        }
    }
    return 0;
}

int
set_pt_file_handle(struct sg_pt_base * vp, int dev_han, int vb)
{
    if (vp) {
        struct sg_pt_netbsd * ptp = &vp->impl;

        if (vb > 2)
            pr2ws("%s: old dev_fd=%d, new dev_fd=%d\n", __func__,
                  ptp->dev_fd, dev_han);
        ptp->dev_fd = dev_han;
    }
    return 0;
}

void
set_pt_metadata_xfer(struct sg_pt_base * vp, uint8_t * mdxferp,
                     uint32_t mdxfer_len, bool out_true)
{
    if (vp) { }
    if (mdxferp) { }
    if (mdxfer_len) { }
    if (out_true) { }
}

void
set_scsi_pt_transport_err(struct sg_pt_base * vp, int err)
{
    if (vp) {
        struct sg_pt_netbsd * ptp = &vp->impl;

        ptp->transport_err = err;
    }
}

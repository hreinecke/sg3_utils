/*
 * Copyright (c) 2017 Leorize.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <device/CAM.h>
#include <scsi.h>

#include "sg_lib.h"
#include "sg_pt.h"

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

struct sg_pt_haiku_scsi {
    raw_device_command raw_command;
    size_t data_len;
    int in_err;
    int os_err;
    int dev_fd;
};

struct sg_pt_base {
    struct sg_pt_haiku_scsi impl;
};

/* Returns >= 0 if successful. If error in Unix returns negated errno. */
int
scsi_pt_open_device(const char * device_name, bool read_only, int verbose)
{
    int oflags = O_NONBLOCK;

    oflags |= (read_only ? O_RDONLY : O_RDWR);
    return scsi_pt_open_flags(device_name, oflags, verbose);
}

/* Similar to scsi_pt_open_device() but takes Unix style open flags OR-ed */
/* together. The 'flags' argument is advisory and may be ignored. */
/* Returns >= 0 if successful, otherwise returns negated errno. */
int
scsi_pt_open_flags(const char * device_name, int flags, int verbose)
{
    int fd;

    if (verbose > 1) {
        pr2ws("open %s with flags=0x%x\n", device_name, flags);
    }
    fd = open(device_name, flags);
    if (fd < 0)
        fd = -errno;
    return fd;
}

/* Returns 0 if successful. If error in Unix returns negated errno. */
int
scsi_pt_close_device(int device_fd)
{
    int res;

    res = close(device_fd);
    if (res < 0)
        res = -errno;
    return res;
}

struct sg_pt_base *
construct_scsi_pt_obj_with_fd(int device_fd, int verbose)
{
    struct sg_pt_haiku_scsi * ptp;

    /* The following 2 lines are temporary. It is to avoid a NULL pointer
     * crash when an old utility is used with a newer library built after
     * the sg_warnings_strm cleanup */
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;

    ptp = (struct sg_pt_haiku_scsi *)
           calloc(1, sizeof(struct sg_pt_haiku_scsi));
    if (ptp) {
        ptp->raw_command.flags = B_RAW_DEVICE_REPORT_RESIDUAL;
        ptp->dev_fd = device_fd;
    } else if (verbose)
        pr2ws("%s: malloc() out of memory\n", __func__);
    return (struct sg_pt_base *)ptp;
}

struct sg_pt_base *
construct_scsi_pt_obj()
{
    return construct_scsi_pt_obj_with_fd(-1, 0);
}

void
destruct_scsi_pt_obj(struct sg_pt_base * vp)
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (ptp)
        free(ptp);
}

void
clear_scsi_pt_obj(struct sg_pt_base * vp)
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (ptp) {

        int fd = ptp->dev_fd;
        memset(ptp, 0, sizeof(struct sg_pt_haiku_scsi));
        ptp->dev_fd = fd;
        ptp->raw_command.flags = B_RAW_DEVICE_REPORT_RESIDUAL;
    }
}

void
set_scsi_pt_cdb(struct sg_pt_base * vp, const unsigned char * cdb,
                int cdb_len)
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    for (int i = 0; i < 16; ++i)
        if (ptp->raw_command.command[i])
            ++ptp->in_err;
    memcpy(ptp->raw_command.command, cdb, cdb_len);
    ptp->raw_command.command_length = (uint8_t)cdb_len;
}

void
set_scsi_pt_sense(struct sg_pt_base * vp, unsigned char * sense,
                  int max_sense_len)
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (ptp->raw_command.sense_data)
        ++ptp->in_err;
    memset(sense, 0, max_sense_len);
    ptp->raw_command.sense_data = sense;
    ptp->raw_command.sense_data_length = max_sense_len;
}

/* Setup for data transfer from device */
void
set_scsi_pt_data_in(struct sg_pt_base * vp, unsigned char * dxferp,
                    int dxfer_len)
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (ptp->raw_command.data)
        ++ptp->in_err;
    if (dxfer_len > 0) {
        ptp->raw_command.data = dxferp;
        ptp->raw_command.data_length = dxfer_len;
        ptp->data_len = dxfer_len;
        ptp->raw_command.flags |= B_RAW_DEVICE_DATA_IN;
    }
}

/* Setup for data transfer toward device */
void
set_scsi_pt_data_out(struct sg_pt_base * vp, const unsigned char * dxferp,
                     int dxfer_len)
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (ptp->raw_command.data)
        ++ptp->in_err;
    if (dxfer_len > 0) {
        ptp->raw_command.data = (unsigned char *)dxferp;
        ptp->raw_command.data_length = dxfer_len;
        ptp->data_len = dxfer_len;
        ptp->raw_command.flags &= ~B_RAW_DEVICE_DATA_IN;
    }
}

void
set_scsi_pt_packet_id(struct sg_pt_base * vp __attribute__ ((unused)),
                      int pack_id __attribute__ ((unused)))
{
}

void
set_scsi_pt_tag(struct sg_pt_base * vp, uint64_t tag __attribute__ ((unused)))
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    ++ptp->in_err;
}

void
set_scsi_pt_task_management(struct sg_pt_base * vp,
                            int tmf_code __attribute__ ((unused)))
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    ++ptp->in_err;
}

void
set_scsi_pt_task_attr(struct sg_pt_base * vp,
                      int attrib __attribute__ ((unused)),
                      int priority __attribute__ ((unused)))
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    ++ptp->in_err;
}

void
set_scsi_pt_flags(struct sg_pt_base * vp __attribute__ ((unused)),
                  int flags __attribute__ ((unused)))
{
}

/* Executes SCSI command (or at least forwards it to lower layers).
 * Clears os_err field prior to active call (whose result may set it
 * again). */
int
do_scsi_pt(struct sg_pt_base * vp, int fd, int timeout_secs, int verbose)
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    ptp->os_err = 0;
    if (ptp->in_err) {
        if (verbose)
            pr2ws("Replicated or unused set_scsi_pt...\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }
    if (fd >= 0) {
        if ((ptp->dev_fd >= 0) && (fd != ptp->dev_fd)) {
            if (verbose)
                pr2ws("%s: file descriptor given to create() and here "
                      "differ\n", __func__);
            return SCSI_PT_DO_BAD_PARAMS;
        }
        ptp->dev_fd = fd;
    } else if (ptp->dev_fd < 0) {
        if (verbose)
            pr2ws("%s: invalid file descriptors\n", __func__);
        return SCSI_PT_DO_BAD_PARAMS;
    } else
        fd = ptp->dev_fd;

    if (NULL == ptp->raw_command.command) {
        if (verbose)
            pr2ws("No SCSI command (cdb) given\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }
    /* raw_command.timeout is in microseconds */
    ptp->raw_command.timeout = ((timeout_secs > 0) ? (timeout_secs * 1000000) :
                                                   CAM_TIME_DEFAULT);

    if (ioctl(fd, B_RAW_DEVICE_COMMAND, &ptp->raw_command) < 0) {
        ptp->os_err = errno;
        if (verbose > 1)
            pr2ws("ioctl(B_RAW_DEVICE_COMMAND) failed: %s (errno=%d)\n",
                  safe_strerror(ptp->os_err), ptp->os_err);
        return -ptp->os_err;
    }

    return SCSI_PT_DO_START_OK;
}

int
get_scsi_pt_result_category(const struct sg_pt_base * vp)
{
    int cam_status_masked;
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (ptp->os_err)
        return SCSI_PT_RESULT_OS_ERR;
    cam_status_masked = ptp->raw_command.cam_status & CAM_STATUS_MASK;
    if (cam_status_masked != CAM_REQ_CMP &&
        cam_status_masked != CAM_REQ_CMP_ERR)
        return SCSI_PT_RESULT_TRANSPORT_ERR;
    else if ((SAM_STAT_CHECK_CONDITION == ptp->raw_command.scsi_status) ||
             (SAM_STAT_COMMAND_TERMINATED == ptp->raw_command.scsi_status))
        return SCSI_PT_RESULT_SENSE;
    else if (ptp->raw_command.scsi_status)
        return SCSI_PT_RESULT_STATUS;
    else
        return SCSI_PT_RESULT_GOOD;
}

int
get_scsi_pt_resid(const struct sg_pt_base * vp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    /* For various reasons Haiku return data_len - data_resid */
    return ptp->data_len - ptp->raw_command.data_length;
}

int
get_scsi_pt_status_response(const struct sg_pt_base * vp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    return ptp->raw_command.scsi_status;
}

uint8_t *
get_scsi_pt_sense_buf(const struct sg_pt_base * vp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    return (uint8_t *)ptp->raw_command.sense_data;
}

int
get_scsi_pt_sense_len(const struct sg_pt_base * vp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    return ptp->raw_command.sense_data_length;
}

int
get_scsi_pt_os_err(const struct sg_pt_base * vp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    return ptp->os_err;
}

char *
get_scsi_pt_os_err_str(const struct sg_pt_base * vp __attribute__ ((unused)),
                       int max_b_len, char * b)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    const char *cp;

    cp = safe_strerror(ptp->os_err);
    strncpy(b, cp, max_b_len);
    if ((int)strlen(cp) >= max_b_len)
        b[max_b_len - 1] = '\0';
    return b;
}

int
get_scsi_pt_transport_err(const struct sg_pt_base * vp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if ((ptp->raw_command.cam_status & CAM_STATUS_MASK) != CAM_REQ_CMP ||
        (ptp->raw_command.cam_status & CAM_STATUS_MASK) != CAM_REQ_CMP_ERR)
        return ptp->raw_command.cam_status & CAM_STATUS_MASK;

    return 0;
}

char *
get_scsi_pt_transport_err_str(
                const struct sg_pt_base * vp __attribute__ ((unused)),
                              int max_b_len, char * b)
{
    strncpy(b, "no transport error available", max_b_len);
    b[max_b_len - 1] = '\0';
    return b;
}

int
get_scsi_pt_duration_ms(const struct sg_pt_base * vp __attribute__ ((unused)))
{
    return -1;
}

void
partial_clear_scsi_pt_obj(struct sg_pt_base * vp)
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (NULL == ptp)
        return;
    ptp->in_err = 0;
    ptp->os_err = 0;
    ptp->data_len = 0;
    ptp->raw_command.cam_status = 0;
    ptp->raw_command.data_length = 0;
}

bool pt_device_is_nvme(const struct sg_pt_base * vp __attribute__ ((unused)))
{
    return 0;
}

int
check_pt_file_handle(int device_fd, const char * device_name, int vb)
{
    if (device_fd) {}
    if (device_name) {}
    if (vb) {}
    return 1;   /* guess it is a SCSI generic pass-though device */
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

void
get_pt_actual_lengths(const struct sg_pt_base * vp, int * act_dinp,
                      int * act_doutp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (ptp->data_len == 0) {
        if (act_dinp)
            *act_dinp = 0;
        if (act_doutp)
            *act_doutp = 0;
    } else if (act_dinp && (ptp->raw_command.flags & B_RAW_DEVICE_DATA_IN)) {
        /* "For various reasons Haiku return data_len - data_resid" */
        *act_dinp = ptp->raw_command.data_length;
        if (act_doutp)
            *act_doutp = 0;
    } else if (act_doutp &&
               !(ptp->raw_command.flags & B_RAW_DEVICE_DATA_IN)) {
        *act_doutp = ptp->raw_command.data_length;
        if (act_dinp)
            *act_dinp = 0;
    } else {
        if (act_dinp)
            *act_dinp = 0;
        if (act_doutp)
            *act_doutp = 0;
    }
}

/* If not available return 0 otherwise return number of nanoseconds that the
 * lower layers (and hardware) took to execute the command just completed. */
uint64_t
get_pt_duration_ns(const struct sg_pt_base * vp __attribute__ ((unused)))
{
    return 0;
}

/* Valid file handles (which is the return value) are >= 0 . Returns -1
 * if there is no valid file handle. */
int
get_pt_file_handle(const struct sg_pt_base * vp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    return ptp->dev_fd;
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

void
get_pt_req_lengths(const struct sg_pt_base * vp, int * req_dinp,
                   int * req_doutp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (ptp->data_len == 0) {
        if (req_dinp)
            *req_dinp = 0;
        if (req_doutp)
            *req_doutp = 0;
    } else if (req_dinp && (ptp->raw_command.flags & B_RAW_DEVICE_DATA_IN)) {
        /* "For various reasons Haiku return data_len - data_resid" */
        *req_dinp = ptp->data_len;
        if (req_doutp)
            *req_doutp = 0;
    } else if (req_doutp &&
               !(ptp->raw_command.flags & B_RAW_DEVICE_DATA_IN)) {
        *req_doutp = ptp->data_len;
        if (req_dinp)
            *req_dinp = 0;
    } else {
        if (req_dinp)
            *req_dinp = 0;
        if (req_doutp)
            *req_doutp = 0;
    }
}

uint32_t
get_pt_result(const struct sg_pt_base * vp)
{
    return (uint32_t)get_scsi_pt_status_response(vp);
}

uint8_t *
get_scsi_pt_cdb_buf(const struct sg_pt_base * vp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    return (uint8_t *)ptp->raw_command.command;
}

int
get_scsi_pt_cdb_len(const struct sg_pt_base * vp)
{
    const struct sg_pt_haiku_scsi * ptp = &vp->impl;

    return (int)ptp->raw_command.command_length;
}

/* Forget any previous dev_han and install the one given. May attempt to
 * find file type (e.g. if pass-though) from OS so there could be an error.
 * Returns 0 for success or the same value as get_scsi_pt_os_err()
 * will return. dev_han should be >= 0 for a valid file handle or -1 . */
int
set_pt_file_handle(struct sg_pt_base * vp, int dev_han, int vb)
{
    struct sg_pt_haiku_scsi * ptp = &vp->impl;

    if (vb) {}
    ptp->dev_fd = (dev_han < 0) ? -1 : dev_han;
    ptp->in_err = 0;
    ptp->os_err = 0;
    return 0;
}

void
set_scsi_pt_transport_err(struct sg_pt_base * vp, int err)
{
    if (vp) { }
    if (err) { }
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

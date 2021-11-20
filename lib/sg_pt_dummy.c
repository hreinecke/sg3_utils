/*
 * Copyright (c) 2021 Douglas Gilbert.
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
#include <string.h>
#include <errno.h>

#include "sg_pt.h"
#include "sg_lib.h"
#include "sg_pr2serr.h"

/* Version 1.02 20210618 */

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

/* Simply defines all the functions needed by the pt interface (see sg_pt.h).
 * They do nothing. This allows decoding of hex files (e.g. with the --in=
 * or --inhex= option) with utilities like sg_vpd and sg_logs. */

struct sg_pt_dummy {
    int dummy;
};

struct sg_pt_base {
    struct sg_pt_dummy impl;
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
    if (device_name) {}
    if (flags) {}
    if (verbose) {}
    errno = EINVAL;
    return -1;
}

/* Returns 0 if successful. If error in Unix returns negated errno. */
int
scsi_pt_close_device(int device_fd)
{
    if (device_fd) {}
    return 0;
}

struct sg_pt_base *
construct_scsi_pt_obj_with_fd(int device_fd, int verbose)
{
    struct sg_pt_dummy * ptp;

    if (device_fd) {}
    ptp = (struct sg_pt_dummy *)malloc(sizeof(struct sg_pt_dummy));
    if (ptp) {
        memset(ptp, 0, sizeof(struct sg_pt_dummy));
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
    struct sg_pt_dummy * ptp = &vp->impl;

    if (ptp)
        free(ptp);
}

void
clear_scsi_pt_obj(struct sg_pt_base * vp)
{
    struct sg_pt_dummy * ptp = &vp->impl;

    if (ptp) {
        ptp->dummy = 0;
    }
}

void
partial_clear_scsi_pt_obj(struct sg_pt_base * vp)
{
    struct sg_pt_dummy * ptp = &vp->impl;

    if (NULL == ptp)
        return;
    ptp->dummy = 0;
}

void
set_scsi_pt_cdb(struct sg_pt_base * vp, const uint8_t * cdb,
                int cdb_len)
{
    if (vp) {}
    if (cdb) {}
    if (cdb_len) {}
}

int
get_scsi_pt_cdb_len(const struct sg_pt_base * vp)
{
    if (vp) {}
    return 6;
}

uint8_t *
get_scsi_pt_cdb_buf(const struct sg_pt_base * vp)
{
    if (vp) {}
    return NULL;
}

void
set_scsi_pt_sense(struct sg_pt_base * vp, uint8_t * sense,
                  int max_sense_len)
{
    if (vp) {}
    if (sense) {}
    if (max_sense_len) {}
}

/* from device */
void
set_scsi_pt_data_in(struct sg_pt_base * vp, uint8_t * dxferp,
                    int dxfer_len)
{
    if (vp) {}
    if (dxferp) {}
    if (dxfer_len) {}
}

/* to device */
void
set_scsi_pt_data_out(struct sg_pt_base * vp, const uint8_t * dxferp,
                     int dxfer_len)
{
    if (vp) {}
    if (dxferp) {}
    if (dxfer_len) {}
}

void
set_scsi_pt_packet_id(struct sg_pt_base * vp, int pack_id)
{
    if (vp) {}
    if (pack_id) {}
}

void
set_scsi_pt_tag(struct sg_pt_base * vp, uint64_t tag)
{
    if (vp) {}
    if (tag) {}
}

void
set_scsi_pt_task_management(struct sg_pt_base * vp, int tmf_code)
{
    if (vp) {}
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
    if (vp) {}
    if (device_fd) {}
    if (time_secs) {}
    if (verbose) {}
    return 0;
}

int
get_scsi_pt_result_category(const struct sg_pt_base * vp)
{
    if (vp) {}
    return 0;
}

int
get_scsi_pt_resid(const struct sg_pt_base * vp)
{
    if (vp) {}
    return 0;
}

void
get_pt_req_lengths(const struct sg_pt_base * vp, int * req_dinp,
                   int * req_doutp)
{
    if (vp) {}
    if (req_dinp) {}
    if (req_doutp) {}
}

void
get_pt_actual_lengths(const struct sg_pt_base * vp, int * act_dinp,
                      int * act_doutp)
{
    if (vp) {}
    if (act_dinp) {}
    if (act_doutp) {}
}


int
get_scsi_pt_status_response(const struct sg_pt_base * vp)
{
    if (vp) {}
    return 0;
}

int
get_scsi_pt_sense_len(const struct sg_pt_base * vp)
{
    if (vp) {}
    return 0;
}

uint8_t *
get_scsi_pt_sense_buf(const struct sg_pt_base * vp)
{
    if (vp) {}
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
    if (vp) {}
    return 0;
}

int
get_scsi_pt_os_err(const struct sg_pt_base * vp)
{
    if (vp) {}
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
    if (vp) { }
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
    if (vp) { }
    return 0;
}

int
set_pt_file_handle(struct sg_pt_base * vp, int dev_han, int vb)
{
    if (vp) { }
    if (dev_han) { }
    if (vb) { }
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
    if (vp) { }
    if (err) { }
}

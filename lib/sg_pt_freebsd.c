/*
 * Copyright (c) 2005-2017 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

/* sg_pt_freebsd version 1.18 20171114 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <limits.h>
#include <libgen.h>     /* for basename */
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <camlib.h>
#include <cam/scsi/scsi_message.h>
// #include <sys/ata.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <glob.h>
#include <fcntl.h>
#include <stddef.h>

#include "sg_pt.h"
#include "sg_lib.h"
#include "freebsd_nvme_ioctl.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


#define FREEBSD_MAXDEV 64
#define FREEBSD_FDOFFSET 16;


struct freebsd_dev_channel {
    int unitnum;                  // the SCSI unit number
    bool is_nvme;
    bool is_char;
    uint32_t nsid;
    uint32_t nv_ctrlid;
    int dev_fd;                   // for NVMe, use -1 to indicate not provided
    char* devname;                // the device name
    struct cam_device* cam_dev;
};

// Private table of open devices: guaranteed zero on startup since
// part of static data.
static struct freebsd_dev_channel *devicetable[FREEBSD_MAXDEV];

#define DEF_TIMEOUT 60000       /* 60,000 milliseconds (60 seconds) */

struct sg_pt_freebsd_scsi {
    struct cam_device* cam_dev; // copy held for error processing
    union ccb *ccb;
    unsigned char * cdb;
    int cdb_len;
    unsigned char * sense;
    int sense_len;
    unsigned char * dxferp;
    int dxfer_len;
    int dxfer_dir;
    unsigned char * dxferip;
    unsigned char * dxferop;
    unsigned char * mdxferp;
    uint32_t dxfer_ilen;
    uint32_t dxfer_olen;
    uint32_t mdxfer_len;
    bool mdxfer_out;
    int scsi_status;
    int resid;
    int sense_resid;
    int in_err;
    int os_err;
    int transport_err;
    int dev_han;                // -1 if not provided
    uint32_t nvme_result;       // from completion
};

struct sg_pt_base {
    struct sg_pt_freebsd_scsi impl;
};

static const uint32_t broadcast_nsid = 0xffffffff;

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


/* Returns >= 0 if successful. If error in Unix returns negated errno. */
int
scsi_pt_open_device(const char * device_name, bool read_only, int verbose)
{
    int oflags = 0 /* O_NONBLOCK*/ ;

    oflags |= (read_only ? O_RDONLY : O_RDWR);
    return scsi_pt_open_flags(device_name, oflags, verbose);
}

/* Similar to scsi_pt_open_device() but takes Unix style open flags OR-ed
 * together. The 'flags' is only used on NVMe devices. It is ignored on
 * SCSI and ATA devices in FreeBSD.
 * Returns >= 0 if successful, otherwise returns negated errno. */
int
scsi_pt_open_flags(const char * device_name, int oflags, int verbose)
{
    bool is_char, is_block, possible_nvme;
    char tmp;
    int k, err, dev_fd, ret;
    uint32_t nsid, nv_ctrlid;
    ssize_t s;
    struct freebsd_dev_channel *fdchan = NULL;
    struct cam_device* cam_dev;
    struct stat a_stat;
    char b[PATH_MAX];
    char  full_path[64];

    // Search table for a free entry
    for (k = 0; k < FREEBSD_MAXDEV; k++)
        if (! devicetable[k])
            break;

    // If no free entry found, return error.  We have max allowed number
    // of "file descriptors" already allocated.
    if (k == FREEBSD_MAXDEV) {
        if (verbose)
            pr2ws("too many open file descriptors (%d)\n", FREEBSD_MAXDEV);
        ret = -EMFILE;
        goto err_out;
    }
    if (stat(device_name, &a_stat) < 0) {
        err = errno;
        pr2ws("%s: unable to stat(%s): %s\n", __func__, device_name,
              strerror(err));
        ret = -err;
        goto err_out;
    }
    is_block = S_ISBLK(a_stat.st_mode);
    is_char = S_ISCHR(a_stat.st_mode);
    if (! (is_block || is_char)) {
        if (verbose)
            pr2ws("%s: %s is not char nor block device\n", __func__,
                            device_name);
        ret = -ENODEV;
        goto err_out;
    }
    s = readlink(device_name,  b, sizeof(b));
    if (s <= 0) {
        strncpy(b, device_name, PATH_MAX - 1);
        b[PATH_MAX - 1] = '\0';
    }

    /* Some code borrowed from smartmontools, Christian Franke */
    nsid = broadcast_nsid;
    nv_ctrlid = broadcast_nsid;
    possible_nvme = false;
    while (true) {      /* dummy loop, so can 'break' out */
        if(sscanf(b, NVME_CTRLR_PREFIX"%u%c", &nv_ctrlid, &tmp) == 1) {
            if(nv_ctrlid == broadcast_nsid)
                break;
        } else if (sscanf(b, NVME_CTRLR_PREFIX"%d"NVME_NS_PREFIX"%d%c",
                          &nv_ctrlid, &nsid, &tmp) == 2) {
            if((nv_ctrlid == broadcast_nsid) || (nsid == broadcast_nsid))
                break;
        } else
            break;
        possible_nvme = true;
        break;
    }

    fdchan = (struct freebsd_dev_channel *)
                calloc(1,sizeof(struct freebsd_dev_channel));
    if (fdchan == NULL) {
        // errno already set by call to calloc()
        ret = -ENOMEM;
        goto err_out;
    }
    fdchan->dev_fd = -1;
    if (! (fdchan->devname = (char *)calloc(1, DEV_IDLEN+1))) {
         ret = -ENOMEM;
         goto err_out;
    }

    if (possible_nvme) {
        // we should always open controller, not namespace device
        snprintf(fdchan->devname, DEV_IDLEN, NVME_CTRLR_PREFIX"%d",
                 nv_ctrlid);
        dev_fd = open(fdchan->devname, oflags);
        if (dev_fd < 0) {
            err = errno;
            if (verbose)
                pr2ws("%s: open(%s) failed: %s (errno=%d), try SCSI/ATA\n",
                      __func__, full_path, strerror(err), err);
            goto scsi_ata_try;
        }
        fdchan->is_nvme = true;
        fdchan->is_char = is_char;
        fdchan->nsid = (broadcast_nsid == nsid) ? 0 : nsid;
        fdchan->nv_ctrlid = nv_ctrlid;
        fdchan->dev_fd = dev_fd;
        devicetable[k] = fdchan;
        return k + FREEBSD_FDOFFSET;
    }

scsi_ata_try:
    fdchan->is_char = is_char;
    if (cam_get_device(device_name, fdchan->devname, DEV_IDLEN,
                       &(fdchan->unitnum)) == -1) {
        if (verbose)
            pr2ws("bad device name structure\n");
        errno = EINVAL;
        ret = -errno;
        goto err_out;
    }
    if (verbose > 4)
        pr2ws("%s: cam_get_device, f->devname: %s, f->unitnum=%d\n", __func__,
              fdchan->devname, fdchan->unitnum);

    if (! (cam_dev = cam_open_spec_device(fdchan->devname,
                                          fdchan->unitnum, O_RDWR, NULL))) {
        if (verbose)
            pr2ws("cam_open_spec_device: %s\n", cam_errbuf);
        errno = EPERM; /* permissions or not CAM device (NVMe ?) */
        ret = -errno;
        goto err_out;
    }
    fdchan->cam_dev = cam_dev;
    // return pointer to "file descriptor" table entry, properly offset.
    devicetable[k] = fdchan;
    return k + FREEBSD_FDOFFSET;

err_out:                /* ret should be negative value (negated errno) */
    if (fdchan) {
        if (fdchan->devname)
            free(fdchan->devname);
        free(fdchan);
        fdchan = NULL;
    }
    return ret;
}

/* Returns 0 if successful. If error in Unix returns negated errno. */
int
scsi_pt_close_device(int device_han)
{
    struct freebsd_dev_channel *fdchan;
    int han = device_han - FREEBSD_FDOFFSET;

    if ((han < 0) || (han >= FREEBSD_MAXDEV)) {
        errno = ENODEV;
        return -errno;
    }
    fdchan = devicetable[han];
    if (NULL == fdchan) {
        errno = ENODEV;
        return -errno;
    }
    if (fdchan->devname)
        free(fdchan->devname);
    if (fdchan->cam_dev)
        cam_close_device(fdchan->cam_dev);
    if (fdchan->is_nvme) {
        if (fdchan->dev_fd >= 0)
            close(fdchan->dev_fd);
    }
    free(fdchan);
    devicetable[han] = NULL;
    errno = 0;
    return 0;
}

/* Assumes dev_fd is an "open" file handle associated with some device.
 * Returns 1 if SCSI generic pass-though device, returns 2 if secondary
 * SCSI pass-through device (in Linux a bsg device); returns 3 is char
 * NVMe device (i.e. no NSID); returns 4 if block NVMe device (includes
 * NSID), or 0 if something else (e.g. ATA block device) or dev_fd < 0.
 * If error, returns negated errno (operating system) value. */
int
check_pt_file_handle(int device_han, const char * device_name, int verbose)
{
    struct freebsd_dev_channel *fdchan;
    int han = device_han - FREEBSD_FDOFFSET;

    if ((han < 0) || (han >= FREEBSD_MAXDEV)) {
        errno = ENODEV;
        return -errno;
    }
    fdchan = devicetable[han];
    if (NULL == fdchan) {
        errno = ENODEV;
        return -errno;
    }
    if (fdchan->is_nvme)
        return 4 - (int)fdchan->is_char;
    else if (fdchan->cam_dev)
        return 2 - (int)fdchan->is_char;
    else {
        if (device_name) { }
        if (verbose) { }
        return 0;
    }
}

struct sg_pt_base *
construct_scsi_pt_obj_with_fd(int dev_han, int verbose)
{
    struct sg_pt_freebsd_scsi * ptp;

    /* The following 2 lines are temporary. It is to avoid a NULL pointer
     * crash when an old utility is used with a newer library built after
     * the sg_warnings_strm cleanup */
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;

    ptp = (struct sg_pt_freebsd_scsi *)
                calloc(1, sizeof(struct sg_pt_freebsd_scsi));
    if (ptp) {
        memset(ptp, 0, sizeof(struct sg_pt_freebsd_scsi));
        ptp->dxfer_dir = CAM_DIR_NONE;
        ptp->dev_han = (dev_han < 0) ? -1 : dev_han;
    } else if (verbose)
        pr2ws("%s: calloc() out of memory\n", __func__);
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
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp) {
        if (ptp->ccb)
            cam_freeccb(ptp->ccb);
        free(ptp);
    }
}

void
clear_scsi_pt_obj(struct sg_pt_base * vp)
{
    int dev_han;
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp) {
        if (ptp->ccb)
            cam_freeccb(ptp->ccb);
        dev_han = ptp->dev_han;
        memset(ptp, 0, sizeof(struct sg_pt_freebsd_scsi));
        ptp->dxfer_dir = CAM_DIR_NONE;
        ptp->dev_han = dev_han;
    }
}

/* Forget any previous dev_han and install the one given. May attempt to
 * find file type (e.g. if pass-though) from OS so there could be an error.
 * Returns 0 for success or the same value as get_scsi_pt_os_err()
 * will return. dev_han should be >= 0 for a valid file handle or -1 . */
int set_pt_file_handle(struct sg_pt_base * vp, int dev_han, int verbose)
{
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp)
        ptp->dev_han = dev_han;
    ptp->os_err = 0;
    if (verbose) { }
    return 0;

}

/* Valid file handles (which is the return value) are >= 0 . Returns -1
 * if there is no valid file handle. */
int get_pt_file_handle(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    return ptp ? ptp->dev_han : -1;
}

void
set_scsi_pt_cdb(struct sg_pt_base * vp, const unsigned char * cdb, int cdb_len)
{
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp->cdb)
        ++ptp->in_err;
    ptp->cdb = (unsigned char *)cdb;
    ptp->cdb_len = cdb_len;
}

void
set_scsi_pt_sense(struct sg_pt_base * vp, unsigned char * sense,
                  int max_sense_len)
{
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp->sense)
        ++ptp->in_err;
    memset(sense, 0, max_sense_len);
    ptp->sense = sense;
    ptp->sense_len = max_sense_len;
}

/* Setup for data transfer from device */
void
set_scsi_pt_data_in(struct sg_pt_base * vp, unsigned char * dxferp,
                    int dxfer_len)
{
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp->dxferip)
        ++ptp->in_err;
    if (dxfer_len > 0) {
        ptp->dxferp = dxferp;
        ptp->dxferip = dxferp;
        ptp->dxfer_len = dxfer_len;
        ptp->dxfer_ilen = dxfer_len;
        ptp->dxfer_dir = CAM_DIR_IN;
    }
}

/* Setup for data transfer toward device */
void
set_scsi_pt_data_out(struct sg_pt_base * vp, const unsigned char * dxferp,
                     int dxfer_len)
{
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp->dxferop)
        ++ptp->in_err;
    if (dxfer_len > 0) {
        ptp->dxferp = (unsigned char *)dxferp;
        ptp->dxferop = (unsigned char *)dxferp;
        ptp->dxfer_len = dxfer_len;
        ptp->dxfer_olen = dxfer_len;
        ptp->dxfer_dir = CAM_DIR_OUT;
    }
}

void
set_pt_metadata_xfer(struct sg_pt_base * vp, unsigned char * mdxferp,
                     uint32_t mdxfer_len, bool out_true)
{
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp->mdxferp)
        ++ptp->in_err;
    if (mdxfer_len > 0) {
        ptp->mdxferp = mdxferp;
        ptp->mdxfer_len = mdxfer_len;
        ptp->mdxfer_out = out_true;
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
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    ++ptp->in_err;
}

void
set_scsi_pt_task_management(struct sg_pt_base * vp,
                            int tmf_code __attribute__ ((unused)))
{
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    ++ptp->in_err;
}

void
set_scsi_pt_task_attr(struct sg_pt_base * vp,
                      int attrib __attribute__ ((unused)),
                      int priority __attribute__ ((unused)))
{
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    ++ptp->in_err;
}

void
set_scsi_pt_flags(struct sg_pt_base * objp, int flags)
{
    if (objp) { ; }     /* unused, suppress warning */
    if (flags) { ; }     /* unused, suppress warning */
}

/* Executes SCSI command (or at least forwards it to lower layers).
 * Clears os_err field prior to active call (whose result may set it
 * again). */
int
do_scsi_pt(struct sg_pt_base * vp, int dev_han, int time_secs, int verbose)
{
    int n, len, timout_ms;
    int han;
    struct sg_pt_freebsd_scsi * ptp = &vp->impl;
    struct freebsd_dev_channel *fdchan;
    union ccb *ccb;

    ptp->os_err = 0;
    if (ptp->in_err) {
        if (verbose)
            pr2ws("Replicated or unused set_scsi_pt...\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }
    if (dev_han < 0) {
        if (ptp->dev_han < 0) {
            if (verbose)
                pr2ws("%s: No device file handle given\n", __func__);
            return SCSI_PT_DO_BAD_PARAMS;
        }
    } else {
        if (ptp->dev_han >= 0) {
            if (dev_han != ptp->dev_han) {
                if (verbose)
                    pr2ws("%s: file handle given to create and this "
                          "differ\n", __func__);
                return SCSI_PT_DO_BAD_PARAMS;
            }
        } else
            ptp->dev_han = dev_han;
    }
    han = ptp->dev_han - FREEBSD_FDOFFSET;

    if (NULL == ptp->cdb) {
        if (verbose)
            pr2ws("No command (cdb) given\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }

    if ((han < 0) || (han >= FREEBSD_MAXDEV)) {
        if (verbose)
            pr2ws("Bad file handle\n");
        ptp->os_err = ENODEV;
        return -ptp->os_err;
    }
    fdchan = devicetable[han];
    if (NULL == fdchan) {
        if (verbose)
            pr2ws("File descriptor closed??\n");
        ptp->os_err = ENODEV;
        return -ptp->os_err;
    }
    if (fdchan->is_nvme) {
        int err;
        struct nvme_pt_command npc;

        if (fdchan->dev_fd < 0) {
            if (verbose)
                pr2ws("%s: is_nvme is true but dev_fd<0, inconsistent\n",
                      __func__);
            ptp->os_err = EINVAL;
            return -ptp->os_err;
        }
        memset(&npc, 0, sizeof(npc));
        n = ptp->cdb_len;
        len = (int)sizeof(npc.cmd);
        n = (len < n) ? len : n;
        if (n < 8) {
            if (verbose)
                pr2ws("%s: cdb_len=%d too short\n", __func__, n);
            return SCSI_PT_DO_BAD_PARAMS;
        }
        memcpy(&npc.cmd, ptp->cdb, ptp->cdb_len);
        npc.buf = ptp->dxferp;
        npc.len = ptp->dxfer_len;
        npc.is_read = (CAM_DIR_IN == ptp->dxfer_dir);
        if ((0 == npc.is_read) && (CAM_DIR_OUT == ptp->dxfer_dir))
            npc.len = 0;        /* don't want write by accident */
        err = ioctl(fdchan->dev_fd, NVME_PASSTHROUGH_CMD, &npc);
        if (err < 0) {
            ptp->os_err = errno;
            if (verbose > 3)
                pr2ws("%s: ioctl(NVME_PASSTHROUGH_CMD) failed: %s "
                      "(errno=%d)\n", __func__, strerror(ptp->os_err),
                      ptp->os_err);
            return -ptp->os_err;
        }
        ptp->nvme_result = npc.cpl.cdw0;
        if (ptp->sense_len > 0) {
            n = (int)sizeof(npc.cpl);
            n = ptp->sense_len <  n ? ptp->sense_len : n;
            memcpy(ptp->sense, &npc.cpl, n);
        }
        return 0;
    }
    if (NULL == fdchan->cam_dev) {
        if (verbose)
            pr2ws("No open CAM device\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }

    if (NULL == ptp->ccb) {     /* re-use if we have one already */
        if (! (ccb = cam_getccb(fdchan->cam_dev))) {
            if (verbose)
                pr2ws("cam_getccb: failed\n");
            ptp->os_err = ENOMEM;
            return -ptp->os_err;
        }
        ptp->ccb = ccb;
    } else
        ccb = ptp->ccb;

    // clear out structure, except for header that was filled in for us
    bzero(&(&ccb->ccb_h)[1],
            sizeof(struct ccb_scsiio) - sizeof(struct ccb_hdr));

    timout_ms = (time_secs > 0) ? (time_secs * 1000) : DEF_TIMEOUT;
    cam_fill_csio(&ccb->csio,
                  /* retries */ 1,
                  /* cbfcnp */ NULL,
                  /* flags */ ptp->dxfer_dir,
                  /* tagaction */ MSG_SIMPLE_Q_TAG,
                  /* dataptr */ ptp->dxferp,
                  /* datalen */ ptp->dxfer_len,
                  /* senselen */ ptp->sense_len,
                  /* cdblen */ ptp->cdb_len,
                  /* timeout (millisecs) */ timout_ms);
    memcpy(ccb->csio.cdb_io.cdb_bytes, ptp->cdb, ptp->cdb_len);

    if (cam_send_ccb(fdchan->cam_dev, ccb) < 0) {
        if (verbose) {
            warn("error sending SCSI ccb");
 #if __FreeBSD_version > 500000
            cam_error_print(fdchan->cam_dev, ccb, CAM_ESF_ALL,
                            CAM_EPF_ALL, stderr);
 #endif
        }
        cam_freeccb(ptp->ccb);
        ptp->ccb = NULL;
        ptp->os_err = EIO;
        return -ptp->os_err;
    }

    if (((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_REQ_CMP) ||
        ((ccb->ccb_h.status & CAM_STATUS_MASK) == CAM_SCSI_STATUS_ERROR)) {
        ptp->scsi_status = ccb->csio.scsi_status;
        ptp->resid = ccb->csio.resid;
        ptp->sense_resid = ccb->csio.sense_resid;

        if ((SAM_STAT_CHECK_CONDITION == ptp->scsi_status) ||
            (SAM_STAT_COMMAND_TERMINATED == ptp->scsi_status)) {
            if (ptp->sense_resid > ptp->sense_len)
                len = ptp->sense_len;   /* crazy; ignore sense_resid */
            else
                len = ptp->sense_len - ptp->sense_resid;
            if (len > 0)
                memcpy(ptp->sense, &(ccb->csio.sense_data), len);
        }
    } else
        ptp->transport_err = 1;

    ptp->cam_dev = fdchan->cam_dev;     // for error processing
    return 0;
}

int
get_scsi_pt_result_category(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp->os_err)
        return SCSI_PT_RESULT_OS_ERR;
    else if (ptp->transport_err)
        return SCSI_PT_RESULT_TRANSPORT_ERR;
    else if ((SAM_STAT_CHECK_CONDITION == ptp->scsi_status) ||
             (SAM_STAT_COMMAND_TERMINATED == ptp->scsi_status))
        return SCSI_PT_RESULT_SENSE;
    else if (ptp->scsi_status)
        return SCSI_PT_RESULT_STATUS;
    else
        return SCSI_PT_RESULT_GOOD;
}

int
get_scsi_pt_resid(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    return ptp->resid;
}

int
get_scsi_pt_status_response(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp) {
        int han = ptp->dev_han - FREEBSD_FDOFFSET;
        struct freebsd_dev_channel *fdchan;

        if ((han < 0) || (han >= FREEBSD_MAXDEV))
            return -1;
        fdchan = devicetable[han];
        if (NULL == fdchan)
            return -1;
        return fdchan->is_nvme ? (int)ptp->nvme_result : ptp->scsi_status;
    }
    return -1;
}

uint32_t
get_pt_result(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp) {
        int han = ptp->dev_han - FREEBSD_FDOFFSET;
        struct freebsd_dev_channel *fdchan;

        if ((han < 0) || (han >= FREEBSD_MAXDEV))
            return -1;
        fdchan = devicetable[han];
        if (NULL == fdchan)
            return -1;
        return fdchan->is_nvme ? ptp->nvme_result :
                                 (uint32_t)ptp->scsi_status;
    }
    return -1;
}

int
get_scsi_pt_sense_len(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp->sense_resid > ptp->sense_len)
        return ptp->sense_len;  /* strange; ignore ptp->sense_resid */
    else
        return ptp->sense_len - ptp->sense_resid;
}

int
get_scsi_pt_duration_ms(const struct sg_pt_base * vp __attribute__ ((unused)))
{
    // const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    return -1;
}

int
get_scsi_pt_transport_err(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    return ptp->transport_err;
}

int
get_scsi_pt_os_err(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    return ptp->os_err;
}

char *
get_scsi_pt_transport_err_str(const struct sg_pt_base * vp, int max_b_len,
                              char * b)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (0 == ptp->transport_err) {
        strncpy(b, "no transport error available", max_b_len);
        b[max_b_len - 1] = '\0';
        return b;
    }
#if __FreeBSD_version > 500000
    if (ptp->cam_dev)
        cam_error_string(ptp->cam_dev, ptp->ccb, b, max_b_len, CAM_ESF_ALL,
                         CAM_EPF_ALL);
    else {
        strncpy(b, "no transport error available", max_b_len);
        b[max_b_len - 1] = '\0';
   }
#else
    strncpy(b, "no transport error available", max_b_len);
    b[max_b_len - 1] = '\0';
#endif
    return b;
}

bool
pt_device_is_nvme(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp && (ptp->dev_han >= 0)) {
        int han = ptp->dev_han - FREEBSD_FDOFFSET;
        struct freebsd_dev_channel *fdchan;

        if ((han < 0) || (han >= FREEBSD_MAXDEV)) {
            errno = ENODEV;
            return false;
        }
        fdchan = devicetable[han];
        if (NULL == fdchan) {
            errno = ENODEV;
            return false;
        }
        return fdchan->is_nvme;
    }
    return false;
}

/* If a NVMe block device (which includes the NSID) handle is associated
 * with 'objp', then its NSID is returned (values range from 0x1 to
 * 0xffffffe). Otherwise 0 is returned. */
uint32_t
get_pt_nvme_nsid(const struct sg_pt_base * vp)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;

    if (ptp && (ptp->dev_han >= 0)) {
        int han = ptp->dev_han - FREEBSD_FDOFFSET;
        struct freebsd_dev_channel *fdchan;

        if ((han < 0) || (han >= FREEBSD_MAXDEV))
            return 0;
        fdchan = devicetable[han];
        if (NULL == fdchan)
            return 0;
        return fdchan->nsid ;
    }
    return 0;
}

char *
get_scsi_pt_os_err_str(const struct sg_pt_base * vp, int max_b_len, char * b)
{
    const struct sg_pt_freebsd_scsi * ptp = &vp->impl;
    const char * cp;

    cp = safe_strerror(ptp->os_err);
    strncpy(b, cp, max_b_len);
    if ((int)strlen(cp) >= max_b_len)
        b[max_b_len - 1] = '\0';
    return b;
}

/*
 * Copyright (c) 2006-2011 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

/* sg_pt_win32 version 1.13 20110207 */

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>

#include "sg_pt.h"
#include "sg_lib.h"
#include "sg_pt_win32.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

/* Use the Microsoft SCSI Pass Through (SPT) interface. It has two
 * variants: "SPT" where data is double buffered; and "SPTD" where data
 * pointers to the user space are passed to the OS. Only Windows
 * 2000 and later (i.e. not 95,98 or ME).
 * There is no ASPI interface which relies on a dll from adaptec.
 * This code uses cygwin facilities and is built in a cygwin
 * shell. It can be run in a normal DOS shell if the cygwin1.dll
 * file is put in an appropriate place.
 * This code can build in a MinGW environment.
 *
 * N.B. MSDN says that the "SPT" interface (i.e. double buffered)
 * should be used for small amounts of data (it says "< 16 KB").
 * The direct variant (i.e. IOCTL_SCSI_PASS_THROUGH_DIRECT) should
 * be used for larger amounts of data but the buffer needs to be
 * "cache aligned". Is that 16 byte alignment or greater?
 *
 * This code will default to indirect (i.e. double buffered) access
 * unless the WIN32_SPT_DIRECT preprocessor constant is defined in
 * config.h . In version 1.12 runtime selection of direct and indirect
 * access was added; the default is still determined by the
 * WIN32_SPT_DIRECT preprocessor constant.
 */

#define DEF_TIMEOUT 60       /* 60 seconds */
#define MAX_OPEN_SIMULT 8
#define WIN32_FDOFFSET 32

struct sg_pt_handle {
    int in_use;
    HANDLE fh;
    char adapter[32];
    int bus;
    int target;
    int lun;
};

struct sg_pt_handle handle_arr[MAX_OPEN_SIMULT];

struct sg_pt_win32_scsi {
    unsigned char * dxferp;
    int dxfer_len;
    unsigned char * sensep;
    int sense_len;
    int scsi_status;
    int resid;
    int sense_resid;
    int in_err;
    int os_err;                 /* pseudo unix error */
    int transport_err;          /* windows error number */
    union {
        SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER swb_d;
        /* Last entry in structure so data buffer can be extended */
        SCSI_PASS_THROUGH_WITH_BUFFERS swb_i;
    };
};

/* embed pointer so can change on fly if (non-direct) data buffer
 * is not big enough */
struct sg_pt_base {
    struct sg_pt_win32_scsi * implp;
};

#ifdef WIN32_SPT_DIRECT
static int spt_direct = 1;
#else
static int spt_direct = 0;
#endif


/* Request SPT direct interface when state_direct is 1, state_direct set
 * to 0 for the SPT indirect interface. */
void
scsi_pt_win32_direct(int state_direct)
{
    spt_direct = state_direct;
}

/* Returns current SPT interface state, 1 for direct, 0 for indirect */
int
scsi_pt_win32_spt_state(void)
{
    return spt_direct;
}


/* Returns >= 0 if successful. If error in Unix returns negated errno. */
int
scsi_pt_open_device(const char * device_name, int read_only, int verbose)
{
    int oflags = 0 /* O_NONBLOCK*/ ;

    oflags |= (read_only ? 0 : 0);      /* was ... ? O_RDONLY : O_RDWR) */
    return scsi_pt_open_flags(device_name, oflags, verbose);
}

/*
 * Similar to scsi_pt_open_device() but takes Unix style open flags OR-ed
 * together. The 'flags' argument is ignored in Windows.
 * Returns >= 0 if successful, otherwise returns negated errno.
 * Optionally accept leading "\\.\". If given something of the form
 * "SCSI<num>:<bus>,<target>,<lun>" where the values in angle brackets
 * are integers, then will attempt to open "\\.\SCSI<num>:" and save the
 * other three values for the DeviceIoControl call. The trailing ".<lun>"
 * is optionally and if not given 0 is assumed. Since "PhysicalDrive"
 * is a lot of keystrokes, "PD" is accepted and converted to the longer
 * form.
 */
int
scsi_pt_open_flags(const char * device_name,
                   int flags __attribute__ ((unused)),
                   int verbose)
{
    int len, k, adapter_num, bus, target, lun, off, got_scsi_name;
    int index, num, got_pd_name, pd_num;
    struct sg_pt_handle * shp;
    char buff[8];

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    /* lock */
    for (k = 0; k < MAX_OPEN_SIMULT; k++)
        if (0 == handle_arr[k].in_use)
            break;
    if (k == MAX_OPEN_SIMULT) {
        if (verbose)
            fprintf(sg_warnings_strm, "too many open handles "
                    "(%d)\n", MAX_OPEN_SIMULT);
        return -EMFILE;
    } else
        handle_arr[k].in_use = 1;
    /* unlock */
    index = k;
    shp = handle_arr + index;
    adapter_num = 0;
    bus = 0;    /* also known as 'PathId' in MS docs */
    target = 0;
    lun = 0;
    got_pd_name = 0;
    got_scsi_name = 0;
    len = strlen(device_name);
    if ((len > 4) && (0 == strncmp("\\\\.\\", device_name, 4)))
        off = 4;
    else
        off = 0;
    if (len > (off + 2)) {
        buff[0] = toupper((int)device_name[off + 0]);
        buff[1] = toupper((int)device_name[off + 1]);
        if (0 == strncmp("PD", buff, 2)) {
            num = sscanf(device_name + off + 2, "%d", &pd_num);
            if (1 == num)
                got_pd_name = 1;
        }
        if (0 == got_pd_name) {
            buff[2] = toupper((int)device_name[off + 2]);
            buff[3] = toupper((int)device_name[off + 3]);
            if (0 == strncmp("SCSI", buff, 4)) {
                num = sscanf(device_name + off + 4, "%d:%d,%d,%d",
                             &adapter_num, &bus, &target, &lun);
                if (num < 3) {
                    if (verbose)
                        fprintf(sg_warnings_strm, "expected format like: "
                                "'SCSI<port>:<bus>.<target>[.<lun>]'\n");
                    shp->in_use = 0;
                    return -EINVAL;
                }
                got_scsi_name = 1;
            }
        }
    }
    shp->bus = bus;
    shp->target = target;
    shp->lun = lun;
    memset(shp->adapter, 0, sizeof(shp->adapter));
    strncpy(shp->adapter, "\\\\.\\", 4);
    if (got_pd_name)
        snprintf(shp->adapter + 4, sizeof(shp->adapter) - 5,
                 "PhysicalDrive%d", pd_num);
    else if (got_scsi_name)
        snprintf(shp->adapter + 4, sizeof(shp->adapter) - 5, "SCSI%d:",
                 adapter_num);
    else
        snprintf(shp->adapter + 4, sizeof(shp->adapter) - 5, "%s",
                 device_name + off);
    shp->fh = CreateFile(shp->adapter, GENERIC_READ | GENERIC_WRITE,
                         FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                         OPEN_EXISTING, 0, NULL);
    if (shp->fh == INVALID_HANDLE_VALUE) {
        if (verbose)
            fprintf(sg_warnings_strm, "Windows CreateFile error=%ld\n",
                    GetLastError());
        shp->in_use = 0;
        return -ENODEV;
    }
    return index + WIN32_FDOFFSET;
}


/* Returns 0 if successful. If error in Unix returns negated errno. */
int
scsi_pt_close_device(int device_fd)
{
    struct sg_pt_handle * shp;
    int index;

    index = device_fd - WIN32_FDOFFSET;

    if ((index < 0) || (index >= WIN32_FDOFFSET))
        return -ENODEV;
    shp = handle_arr + index;
    CloseHandle(shp->fh);
    shp->bus = 0;
    shp->target = 0;
    shp->lun = 0;
    memset(shp->adapter, 0, sizeof(shp->adapter));
    shp->in_use = 0;
    return 0;
}

struct sg_pt_base *
construct_scsi_pt_obj()
{
    struct sg_pt_win32_scsi * psp;
    struct sg_pt_base * vp = NULL;

    psp = (struct sg_pt_win32_scsi *)calloc(sizeof(struct sg_pt_win32_scsi),
                                            1);
    if (psp) {
        if (spt_direct) {
            psp->swb_d.spt.DataIn = SCSI_IOCTL_DATA_UNSPECIFIED;
            psp->swb_d.spt.SenseInfoLength = SCSI_MAX_SENSE_LEN;
            psp->swb_d.spt.SenseInfoOffset =
                offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS, ucSenseBuf);
            psp->swb_d.spt.TimeOutValue = DEF_TIMEOUT;
        } else {
            psp->swb_i.spt.DataIn = SCSI_IOCTL_DATA_UNSPECIFIED;
            psp->swb_i.spt.SenseInfoLength = SCSI_MAX_SENSE_LEN;
            psp->swb_i.spt.SenseInfoOffset =
                offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS, ucSenseBuf);
            psp->swb_i.spt.TimeOutValue = DEF_TIMEOUT;
        }
        vp = malloc(sizeof(struct sg_pt_win32_scsi *)); // yes a pointer
        if (vp)
            vp->implp = psp;
        else
            free(psp);
    }
    return vp;
}

void
destruct_scsi_pt_obj(struct sg_pt_base * vp)
{
    if (vp) {
        struct sg_pt_win32_scsi * psp = vp->implp;

        if (psp) {
            free(psp);
        }
        free(vp);
    }
}

void
clear_scsi_pt_obj(struct sg_pt_base * vp)
{
    struct sg_pt_win32_scsi * psp = vp->implp;

    if (psp) {
        memset(psp, 0, sizeof(struct sg_pt_win32_scsi));
        if (spt_direct) {
            psp->swb_d.spt.DataIn = SCSI_IOCTL_DATA_UNSPECIFIED;
            psp->swb_d.spt.SenseInfoLength = SCSI_MAX_SENSE_LEN;
            psp->swb_d.spt.SenseInfoOffset =
                offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS, ucSenseBuf);
            psp->swb_d.spt.TimeOutValue = DEF_TIMEOUT;
        } else {
            psp->swb_i.spt.DataIn = SCSI_IOCTL_DATA_UNSPECIFIED;
            psp->swb_i.spt.SenseInfoLength = SCSI_MAX_SENSE_LEN;
            psp->swb_i.spt.SenseInfoOffset =
                offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS, ucSenseBuf);
            psp->swb_i.spt.TimeOutValue = DEF_TIMEOUT;
        }
    }
}

void
set_scsi_pt_cdb(struct sg_pt_base * vp, const unsigned char * cdb,
                int cdb_len)
{
    struct sg_pt_win32_scsi * psp = vp->implp;

    if (spt_direct) {
        if (psp->swb_d.spt.CdbLength > 0)
            ++psp->in_err;
        if (cdb_len > (int)sizeof(psp->swb_d.spt.Cdb)) {
            ++psp->in_err;
            return;
        }
        memcpy(psp->swb_d.spt.Cdb, cdb, cdb_len);
        psp->swb_d.spt.CdbLength = cdb_len;
    } else {
        if (psp->swb_i.spt.CdbLength > 0)
            ++psp->in_err;
        if (cdb_len > (int)sizeof(psp->swb_i.spt.Cdb)) {
            ++psp->in_err;
            return;
        }
        memcpy(psp->swb_i.spt.Cdb, cdb, cdb_len);
        psp->swb_i.spt.CdbLength = cdb_len;
    }
}

void
set_scsi_pt_sense(struct sg_pt_base * vp, unsigned char * sense,
                  int sense_len)
{
    struct sg_pt_win32_scsi * psp = vp->implp;

    if (psp->sensep)
        ++psp->in_err;
    memset(sense, 0, sense_len);
    psp->sensep = sense;
    psp->sense_len = sense_len;
}

/* from device */
void
set_scsi_pt_data_in(struct sg_pt_base * vp, unsigned char * dxferp,
                    int dxfer_len)
{
    struct sg_pt_win32_scsi * psp = vp->implp;

    if (psp->dxferp)
        ++psp->in_err;
    if (dxfer_len > 0) {
        psp->dxferp = dxferp;
        psp->dxfer_len = dxfer_len;
        if (spt_direct)
            psp->swb_d.spt.DataIn = SCSI_IOCTL_DATA_IN;
        else
            psp->swb_i.spt.DataIn = SCSI_IOCTL_DATA_IN;
    }
}

/* to device */
void
set_scsi_pt_data_out(struct sg_pt_base * vp, const unsigned char * dxferp,
                     int dxfer_len)
{
    struct sg_pt_win32_scsi * psp = vp->implp;

    if (psp->dxferp)
        ++psp->in_err;
    if (dxfer_len > 0) {
        psp->dxferp = (unsigned char *)dxferp;
        psp->dxfer_len = dxfer_len;
        if (spt_direct)
            psp->swb_d.spt.DataIn = SCSI_IOCTL_DATA_OUT;
        else
            psp->swb_i.spt.DataIn = SCSI_IOCTL_DATA_OUT;
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
    struct sg_pt_win32_scsi * psp = vp->implp;

    ++psp->in_err;
}

void
set_scsi_pt_task_management(struct sg_pt_base * vp,
                            int tmf_code __attribute__ ((unused)))
{
    struct sg_pt_win32_scsi * psp = vp->implp;

    ++psp->in_err;
}

void
set_scsi_pt_task_attr(struct sg_pt_base * vp,
                      int attrib __attribute__ ((unused)),
                      int priority __attribute__ ((unused)))
{
    struct sg_pt_win32_scsi * psp = vp->implp;

    ++psp->in_err;
}

void
set_scsi_pt_flags(struct sg_pt_base * objp, int flags)
{
    /* do nothing, suppress warnings */
    objp = objp;
    flags = flags;
}

/* Executes SCSI command (or at least forwards it to lower layers)
 * using direct interface. Clears os_err field prior to active call (whose
 * result may set it again). */
int
do_scsi_pt_direct(struct sg_pt_base * vp, int device_fd, int time_secs,
                  int verbose)
{
    int index = device_fd - WIN32_FDOFFSET;
    struct sg_pt_win32_scsi * psp = vp->implp;
    struct sg_pt_handle * shp;
    BOOL status;
    ULONG returned;

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    psp->os_err = 0;
    if (psp->in_err) {
        if (verbose)
            fprintf(sg_warnings_strm, "Replicated or unused set_scsi_pt...\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }
    if (0 == psp->swb_d.spt.CdbLength) {
        if (verbose)
            fprintf(sg_warnings_strm, "No command (cdb) given\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }

    index = device_fd - WIN32_FDOFFSET;
    if ((index < 0) || (index >= WIN32_FDOFFSET)) {
        if (verbose)
            fprintf(sg_warnings_strm, "Bad file descriptor\n");
        psp->os_err = ENODEV;
        return -psp->os_err;
    }
    shp = handle_arr + index;
    if (0 == shp->in_use) {
        if (verbose)
            fprintf(sg_warnings_strm, "File descriptor closed??\n");
        psp->os_err = ENODEV;
        return -psp->os_err;
    }
    psp->swb_d.spt.Length = sizeof (SCSI_PASS_THROUGH_DIRECT);
    psp->swb_d.spt.PathId = shp->bus;
    psp->swb_d.spt.TargetId = shp->target;
    psp->swb_d.spt.Lun = shp->lun;
    psp->swb_d.spt.TimeOutValue = time_secs;
    psp->swb_d.spt.DataTransferLength = psp->dxfer_len;
    if (verbose > 4) {
        fprintf(stderr, " spt_direct, adapter: %s  Length=%d ScsiStatus=%d "
                "PathId=%d TargetId=%d Lun=%d\n", shp->adapter,
                (int)psp->swb_d.spt.Length,
                (int)psp->swb_d.spt.ScsiStatus, (int)psp->swb_d.spt.PathId,
                (int)psp->swb_d.spt.TargetId, (int)psp->swb_d.spt.Lun);
        fprintf(stderr, "    CdbLength=%d SenseInfoLength=%d DataIn=%d "
                "DataTransferLength=%lu\n",
                (int)psp->swb_d.spt.CdbLength,
                (int)psp->swb_d.spt.SenseInfoLength,
                (int)psp->swb_d.spt.DataIn,
                psp->swb_d.spt.DataTransferLength);
        fprintf(stderr, "    TimeOutValue=%lu SenseInfoOffset=%lu\n",
                psp->swb_d.spt.TimeOutValue, psp->swb_d.spt.SenseInfoOffset);
    }
    psp->swb_d.spt.DataBuffer = psp->dxferp;
    status = DeviceIoControl(shp->fh, IOCTL_SCSI_PASS_THROUGH_DIRECT,
                            &psp->swb_d,
                            sizeof(psp->swb_d),
                            &psp->swb_d,
                            sizeof(psp->swb_d),
                            &returned,
                            NULL);
    if (! status) {
        psp->transport_err = GetLastError();
        if (verbose)
            fprintf(sg_warnings_strm, "Windows DeviceIoControl error=%d\n",
                    psp->transport_err);
        psp->os_err = EIO;
        return 0;       /* let app find transport error */
    }

    psp->scsi_status = psp->swb_d.spt.ScsiStatus;
    if ((SAM_STAT_CHECK_CONDITION == psp->scsi_status) ||
        (SAM_STAT_COMMAND_TERMINATED == psp->scsi_status))
        memcpy(psp->sensep, psp->swb_d.ucSenseBuf, psp->sense_len);
    else
        psp->sense_len = 0;
    psp->sense_resid = 0;
    if ((psp->dxfer_len > 0) && (psp->swb_d.spt.DataTransferLength > 0))
        psp->resid = psp->dxfer_len - psp->swb_d.spt.DataTransferLength;
    else
        psp->resid = 0;

    return 0;
}

/* Executes SCSI command (or at least forwards it to lower layers) using
 * indirect interface. Clears os_err field prior to active call (whose
 * result may set it again). */
static int
do_scsi_pt_indirect(struct sg_pt_base * vp, int device_fd, int time_secs,
                    int verbose)
{
    int index = device_fd - WIN32_FDOFFSET;
    struct sg_pt_win32_scsi * psp = vp->implp;
    struct sg_pt_handle * shp;
    BOOL status;
    ULONG returned;

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    psp->os_err = 0;
    if (psp->in_err) {
        if (verbose)
            fprintf(sg_warnings_strm, "Replicated or unused "
                    "set_scsi_pt...\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }
    if (0 == psp->swb_i.spt.CdbLength) {
        if (verbose)
            fprintf(sg_warnings_strm, "No command (cdb) given\n");
        return SCSI_PT_DO_BAD_PARAMS;
    }

    index = device_fd - WIN32_FDOFFSET;
    if ((index < 0) || (index >= WIN32_FDOFFSET)) {
        if (verbose)
            fprintf(sg_warnings_strm, "Bad file descriptor\n");
        psp->os_err = ENODEV;
        return -psp->os_err;
    }
    shp = handle_arr + index;
    if (0 == shp->in_use) {
        if (verbose)
            fprintf(sg_warnings_strm, "File descriptor closed??\n");
        psp->os_err = ENODEV;
        return -psp->os_err;
    }
    if (psp->dxfer_len > (int)sizeof(psp->swb_i.ucDataBuf)) {
        int extra = psp->dxfer_len - (int)sizeof(psp->swb_i.ucDataBuf);
        struct sg_pt_win32_scsi * epsp;

        if (verbose > 4)
            fprintf(sg_warnings_strm, "spt_indirect: dxfer_len (%d) too "
                    "large for initial data\n  buffer (%d bytes), try "
                    "enlarging\n", psp->dxfer_len,
                    sizeof(psp->swb_i.ucDataBuf));
        epsp = (struct sg_pt_win32_scsi *)
               calloc(sizeof(struct sg_pt_win32_scsi) + extra, 1);
        if (NULL == epsp) {
            fprintf(sg_warnings_strm, "do_scsi_pt: failed to enlarge data "
                    "buffer to %d bytes\n", psp->dxfer_len);
            psp->os_err = ENOMEM;
            return -psp->os_err;
        }
        memcpy(epsp, psp, sizeof(struct sg_pt_win32_scsi));
        free(psp);
        vp->implp = epsp;
        psp = epsp;
    }
    psp->swb_i.spt.Length = sizeof (SCSI_PASS_THROUGH);
    psp->swb_i.spt.DataBufferOffset =
                offsetof(SCSI_PASS_THROUGH_WITH_BUFFERS, ucDataBuf);
    psp->swb_i.spt.PathId = shp->bus;
    psp->swb_i.spt.TargetId = shp->target;
    psp->swb_i.spt.Lun = shp->lun;
    psp->swb_i.spt.TimeOutValue = time_secs;
    psp->swb_i.spt.DataTransferLength = psp->dxfer_len;
    if (verbose > 4) {
        fprintf(stderr, " spt_indirect, adapter: %s  Length=%d ScsiStatus=%d "
                "PathId=%d TargetId=%d Lun=%d\n", shp->adapter,
                (int)psp->swb_i.spt.Length,
                (int)psp->swb_i.spt.ScsiStatus, (int)psp->swb_i.spt.PathId,
                (int)psp->swb_i.spt.TargetId, (int)psp->swb_i.spt.Lun);
        fprintf(stderr, "    CdbLength=%d SenseInfoLength=%d DataIn=%d "
                "DataTransferLength=%lu\n",
                (int)psp->swb_i.spt.CdbLength,
                (int)psp->swb_i.spt.SenseInfoLength,
                (int)psp->swb_i.spt.DataIn,
                psp->swb_i.spt.DataTransferLength);
        fprintf(stderr, "    TimeOutValue=%lu DataBufferOffset=%lu "
                "SenseInfoOffset=%lu\n", psp->swb_i.spt.TimeOutValue,
                psp->swb_i.spt.DataBufferOffset,
                psp->swb_i.spt.SenseInfoOffset);
    }
    if ((psp->dxfer_len > 0) &&
        (SCSI_IOCTL_DATA_OUT == psp->swb_i.spt.DataIn))
        memcpy(psp->swb_i.ucDataBuf, psp->dxferp, psp->dxfer_len);
    status = DeviceIoControl(shp->fh, IOCTL_SCSI_PASS_THROUGH,
                            &psp->swb_i,
                            sizeof(psp->swb_i),
                            &psp->swb_i,
                            sizeof(psp->swb_i),
                            &returned,
                            NULL);
    if (! status) {
        psp->transport_err = GetLastError();
        if (verbose)
            fprintf(sg_warnings_strm, "Windows DeviceIoControl error=%d\n",
                    psp->transport_err);
        psp->os_err = EIO;
        return 0;       /* let app find transport error */
    }
    if ((psp->dxfer_len > 0) && (SCSI_IOCTL_DATA_IN == psp->swb_i.spt.DataIn))
        memcpy(psp->dxferp, psp->swb_i.ucDataBuf, psp->dxfer_len);

    psp->scsi_status = psp->swb_i.spt.ScsiStatus;
    if ((SAM_STAT_CHECK_CONDITION == psp->scsi_status) ||
        (SAM_STAT_COMMAND_TERMINATED == psp->scsi_status))
        memcpy(psp->sensep, psp->swb_i.ucSenseBuf, psp->sense_len);
    else
        psp->sense_len = 0;
    psp->sense_resid = 0;
    if ((psp->dxfer_len > 0) && (psp->swb_i.spt.DataTransferLength > 0))
        psp->resid = psp->dxfer_len - psp->swb_i.spt.DataTransferLength;
    else
        psp->resid = 0;

    return 0;
}

/* Executes SCSI command (or at least forwards it to lower layers).
 * Clears os_err field prior to active call (whose result may set it
 * again). */
int
do_scsi_pt(struct sg_pt_base * vp, int device_fd, int time_secs, int verbose)
{
    if (spt_direct)
        return do_scsi_pt_direct(vp, device_fd, time_secs, verbose);
    else
        return do_scsi_pt_indirect(vp, device_fd, time_secs, verbose);
}

int
get_scsi_pt_result_category(const struct sg_pt_base * vp)
{
    const struct sg_pt_win32_scsi * psp = vp->implp;

    if (psp->transport_err)     /* give transport error highest priority */
        return SCSI_PT_RESULT_TRANSPORT_ERR;
    else if (psp->os_err)
        return SCSI_PT_RESULT_OS_ERR;
    else if ((SAM_STAT_CHECK_CONDITION == psp->scsi_status) ||
             (SAM_STAT_COMMAND_TERMINATED == psp->scsi_status))
        return SCSI_PT_RESULT_SENSE;
    else if (psp->scsi_status)
        return SCSI_PT_RESULT_STATUS;
    else
        return SCSI_PT_RESULT_GOOD;
}

int
get_scsi_pt_resid(const struct sg_pt_base * vp)
{
    const struct sg_pt_win32_scsi * psp = vp->implp;

    return psp->resid;
}

int
get_scsi_pt_status_response(const struct sg_pt_base * vp)
{
    const struct sg_pt_win32_scsi * psp = vp->implp;

    return psp->scsi_status;
}

int
get_scsi_pt_sense_len(const struct sg_pt_base * vp)
{
    const struct sg_pt_win32_scsi * psp = vp->implp;
    int len;

    len = psp->sense_len - psp->sense_resid;
    return (len > 0) ? len : 0;
}

int
get_scsi_pt_duration_ms(const struct sg_pt_base * vp __attribute__ ((unused)))
{
    // const struct sg_pt_freebsd_scsi * psp = vp->implp;

    return -1;
}

int
get_scsi_pt_transport_err(const struct sg_pt_base * vp)
{
    const struct sg_pt_win32_scsi * psp = vp->implp;

    return psp->transport_err;
}

int
get_scsi_pt_os_err(const struct sg_pt_base * vp)
{
    const struct sg_pt_win32_scsi * psp = vp->implp;

    return psp->os_err;
}


char *
get_scsi_pt_transport_err_str(const struct sg_pt_base * vp, int max_b_len,
                              char * b)
{
    struct sg_pt_win32_scsi * psp = (struct sg_pt_win32_scsi *)vp->implp;
    LPVOID lpMsgBuf;
    int k, num, ch;

    if (max_b_len < 2) {
        if (1 == max_b_len)
            b[0] = '\0';
        return b;
    }
    memset(b, 0, max_b_len);
    FormatMessage(
        FORMAT_MESSAGE_ALLOCATE_BUFFER |
        FORMAT_MESSAGE_FROM_SYSTEM,
        NULL,
        psp->transport_err,
        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
        (LPTSTR) &lpMsgBuf,
        0, NULL );
    num = lstrlen((LPCTSTR)lpMsgBuf);
    if (num < 1)
        return b;
    num = (num < max_b_len) ? num : (max_b_len - 1);
    for (k = 0; k < num; ++k) {
        ch = *((LPCTSTR)lpMsgBuf + k);
        if ((ch >= 0x0) && (ch < 0x7f))
            b[k] = ch & 0x7f;
        else
            b[k] = '?';
    }
    return b;
}

char *
get_scsi_pt_os_err_str(const struct sg_pt_base * vp, int max_b_len, char * b)
{
    const struct sg_pt_win32_scsi * psp = vp->implp;
    const char * cp;

    cp = safe_strerror(psp->os_err);
    strncpy(b, cp, max_b_len);
    if ((int)strlen(cp) >= max_b_len)
        b[max_b_len - 1] = '\0';
    return b;
}

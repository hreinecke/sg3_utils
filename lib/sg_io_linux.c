/*
 * Copyright (c) 1999-2007 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

// need to include the file in the build when sg_scan is built for Win32.
// Hence the following guard ...
//
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#ifdef SG3_UTILS_LINUX

#include "sg_io_linux.h"


/* Version 1.02 20060714 */


void sg_print_masked_status(int masked_status)
{
    int scsi_status = (masked_status << 1) & 0x7e;

    sg_print_scsi_status(scsi_status);
}

static const char * linux_host_bytes[] = {
    "DID_OK", "DID_NO_CONNECT", "DID_BUS_BUSY", "DID_TIME_OUT",
    "DID_BAD_TARGET", "DID_ABORT", "DID_PARITY", "DID_ERROR",
    "DID_RESET", "DID_BAD_INTR", "DID_PASSTHROUGH", "DID_SOFT_ERROR",
    "DID_IMM_RETRY", "DID_REQUEUE"
};

#define LINUX_HOST_BYTES_SZ \
        (int)(sizeof(linux_host_bytes) / sizeof(linux_host_bytes[0]))

void sg_print_host_status(int host_status)
{
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    fprintf(sg_warnings_strm, "Host_status=0x%02x ", host_status);
    if ((host_status < 0) || (host_status >= LINUX_HOST_BYTES_SZ))
        fprintf(sg_warnings_strm, "is invalid ");
    else
        fprintf(sg_warnings_strm, "[%s] ", linux_host_bytes[host_status]);
}

static const char * linux_driver_bytes[] = {
    "DRIVER_OK", "DRIVER_BUSY", "DRIVER_SOFT", "DRIVER_MEDIA",
    "DRIVER_ERROR", "DRIVER_INVALID", "DRIVER_TIMEOUT", "DRIVER_HARD",
    "DRIVER_SENSE"
};

#define LINUX_DRIVER_BYTES_SZ \
    (int)(sizeof(linux_driver_bytes) / sizeof(linux_driver_bytes[0]))

static const char * linux_driver_suggests[] = {
    "SUGGEST_OK", "SUGGEST_RETRY", "SUGGEST_ABORT", "SUGGEST_REMAP",
    "SUGGEST_DIE", "UNKNOWN","UNKNOWN","UNKNOWN",
    "SUGGEST_SENSE"
};

#define LINUX_DRIVER_SUGGESTS_SZ \
    (int)(sizeof(linux_driver_suggests) / sizeof(linux_driver_suggests[0]))


void sg_print_driver_status(int driver_status)
{
    int driv, sugg;
    const char * driv_cp = "invalid";
    const char * sugg_cp = "invalid";

    driv = driver_status & SG_LIB_DRIVER_MASK;
    if (driv < LINUX_DRIVER_BYTES_SZ)
        driv_cp = linux_driver_bytes[driv];
    sugg = (driver_status & SG_LIB_SUGGEST_MASK) >> 4;
    if (sugg < LINUX_DRIVER_SUGGESTS_SZ)
        sugg_cp = linux_driver_suggests[sugg];
    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    fprintf(sg_warnings_strm, "Driver_status=0x%02x", driver_status);
    fprintf(sg_warnings_strm, " [%s, %s] ", driv_cp, sugg_cp);
}

/* Returns 1 if no errors found and thus nothing printed; otherwise
   prints error/warning (prefix by 'leadin') and returns 0. */
static int sg_linux_sense_print(const char * leadin, int scsi_status,
                                int host_status, int driver_status,
                                const unsigned char * sense_buffer,
                                int sb_len, int raw_sinfo)
{
    int done_leadin = 0;
    int done_sense = 0;

    if (NULL == sg_warnings_strm)
        sg_warnings_strm = stderr;
    scsi_status &= 0x7e; /*sanity */
    if ((0 == scsi_status) && (0 == host_status) && (0 == driver_status))
        return 1;       /* No problems */
    if (0 != scsi_status) {
        if (leadin)
            fprintf(sg_warnings_strm, "%s: ", leadin);
        done_leadin = 1;
        fprintf(sg_warnings_strm, "SCSI status: ");
        sg_print_scsi_status(scsi_status);
        fprintf(sg_warnings_strm, "\n");
        if (sense_buffer && ((scsi_status == SAM_STAT_CHECK_CONDITION) ||
                             (scsi_status == SAM_STAT_COMMAND_TERMINATED))) {
            /* SAM_STAT_COMMAND_TERMINATED is obsolete */
            sg_print_sense(0, sense_buffer, sb_len, raw_sinfo);
            done_sense = 1;
        }
    }
    if (0 != host_status) {
        if (leadin && (! done_leadin))
            fprintf(sg_warnings_strm, "%s: ", leadin);
        if (done_leadin)
            fprintf(sg_warnings_strm, "plus...: ");
        else
            done_leadin = 1;
        sg_print_host_status(host_status);
        fprintf(sg_warnings_strm, "\n");
    }
    if (0 != driver_status) {
        if (done_sense &&
            (SG_LIB_DRIVER_SENSE == (SG_LIB_DRIVER_MASK & driver_status)))
            return 0;
        if (leadin && (! done_leadin))
            fprintf(sg_warnings_strm, "%s: ", leadin);
        if (done_leadin)
            fprintf(sg_warnings_strm, "plus...: ");
        else
            done_leadin = 1;
        sg_print_driver_status(driver_status);
        fprintf(sg_warnings_strm, "\n");
        if (sense_buffer && (! done_sense) &&
            (SG_LIB_DRIVER_SENSE == (SG_LIB_DRIVER_MASK & driver_status)))
            sg_print_sense(0, sense_buffer, sb_len, raw_sinfo);
    }
    return 0;
}

#ifdef SG_IO

int sg_normalize_sense(const struct sg_io_hdr * hp,
                       struct sg_scsi_sense_hdr * sshp)
{
    if ((NULL == hp) || (0 == hp->sb_len_wr)) {
        if (sshp)
            memset(sshp, 0, sizeof(struct sg_scsi_sense_hdr));
        return 0;
    }
    return sg_scsi_normalize_sense(hp->sbp, hp->sb_len_wr, sshp);
}

/* Returns 1 if no errors found and thus nothing printed; otherwise
   returns 0. */
int sg_chk_n_print3(const char * leadin, struct sg_io_hdr * hp,
                    int raw_sinfo)
{
    return sg_linux_sense_print(leadin, hp->status, hp->host_status,
                                hp->driver_status, hp->sbp, hp->sb_len_wr,
                                raw_sinfo);
}
#endif

/* Returns 1 if no errors found and thus nothing printed; otherwise
   returns 0. */
int sg_chk_n_print(const char * leadin, int masked_status,
                   int host_status, int driver_status,
                   const unsigned char * sense_buffer, int sb_len,
                   int raw_sinfo)
{
    int scsi_status = (masked_status << 1) & 0x7e;

    return sg_linux_sense_print(leadin, scsi_status, host_status,
                                driver_status, sense_buffer, sb_len,
                                raw_sinfo);
}

#ifdef SG_IO
int sg_err_category3(struct sg_io_hdr * hp)
{
    return sg_err_category_new(hp->status, hp->host_status,
                               hp->driver_status, hp->sbp, hp->sb_len_wr);
}
#endif

int sg_err_category(int masked_status, int host_status,
                    int driver_status, const unsigned char * sense_buffer,
                    int sb_len)
{
    int scsi_status = (masked_status << 1) & 0x7e;

    return sg_err_category_new(scsi_status, host_status, driver_status,
                               sense_buffer, sb_len);
}

int sg_err_category_new(int scsi_status, int host_status, int driver_status,
                        const unsigned char * sense_buffer, int sb_len)
{
    int masked_driver_status = (SG_LIB_DRIVER_MASK & driver_status);

    scsi_status &= 0x7e;
    if ((0 == scsi_status) && (0 == host_status) &&
        (0 == masked_driver_status))
        return SG_LIB_CAT_CLEAN;
    if ((SAM_STAT_CHECK_CONDITION == scsi_status) ||
        (SAM_STAT_COMMAND_TERMINATED == scsi_status) ||
        (SG_LIB_DRIVER_SENSE == masked_driver_status))
        return sg_err_category_sense(sense_buffer, sb_len);
    if (0 != host_status) {
        if ((SG_LIB_DID_NO_CONNECT == host_status) ||
            (SG_LIB_DID_BUS_BUSY == host_status) ||
            (SG_LIB_DID_TIME_OUT == host_status))
            return SG_LIB_CAT_TIMEOUT;
    }
    if (SG_LIB_DRIVER_TIMEOUT == masked_driver_status)
        return SG_LIB_CAT_TIMEOUT;
    return SG_LIB_CAT_OTHER;
}

#endif

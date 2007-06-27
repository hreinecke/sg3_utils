/*
 * Copyright (c) 2006-2007 Douglas Gilbert.
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

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_lib.h"
#include "sg_io_linux.h"

/* This program performs a ATA PASS-THROUGH (16) SCSI command in order
   to perform an ATA CHECK POWER MODE command. See http://www.t10.org
   SAT draft at time of writing: sat-r09.pdf

   Invocation: sg_sat_chk_power [-v] [-V] <device>

*/

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */

#define ATA_CHECK_POWER_MODE 0xe5

#define EBUFF_SZ 256

static char * version_str = "1.03 20070129";

int main(int argc, char * argv[])
{
    int sg_fd, k;
    unsigned char aptCmdBlk[SAT_ATA_PASS_THROUGH16_LEN] =
                {SAT_ATA_PASS_THROUGH16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0};
    sg_io_hdr_t io_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char sense_buffer[64];
    int verbose = 0;
    int extend = 0;
    int chk_cond = 1;   /* set to 1 to read register(s) back */
    int protocol = 3;   /* non-dat data-in */
    int t_dir = 1;      /* 0 -> to device, 1 -> from device */
    int byte_block = 1; /* 0 -> bytes, 1 -> 512 byte blocks */
    int t_length = 0;   /* 0 -> no data transferred, 2 -> sector count */
    const unsigned char * ucp = NULL;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp(argv[k], "-v"))
            ++verbose;
        else if (0 == strcmp(argv[k], "-vv"))
            verbose += 2;
        else if (0 == strcmp(argv[k], "-vvv"))
            verbose += 3;
        else if (0 == strcmp(argv[k], "-V")) {
            fprintf(stderr, "version: %s\n", version_str);
            exit(0);
        } else if (*argv[k] == '-') {
            printf("Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else if (0 == file_name)
            file_name = argv[k];
        else {
            printf("too many arguments\n");
            file_name = 0;
            break;
        }
    }
    if (0 == file_name) {
        printf("Usage: 'sg_sat_chk_power [-v] [-V] <device>'\n");
        return 1;
    }

    if ((sg_fd = open(file_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "sg_sat_chk_power: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }

    /* Prepare ATA PASS-THROUGH COMMAND (16) command */
    aptCmdBlk[14] = ATA_CHECK_POWER_MODE;
    aptCmdBlk[1] = (protocol << 1) | extend;
    aptCmdBlk[2] = (chk_cond << 5) | (t_dir << 3) |
                   (byte_block << 2) | t_length;
    if (verbose) {
        fprintf(stderr, "    ata pass through(16) cdb: ");
        for (k = 0; k < SAT_ATA_PASS_THROUGH16_LEN; ++k)
            fprintf(stderr, "%02x ", aptCmdBlk[k]);
        fprintf(stderr, "\n");
    }

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(aptCmdBlk);
    /* io_hdr.iovec_count = 0; */  /* memset takes care of this */
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_NONE;
    io_hdr.dxfer_len = 0;
    io_hdr.dxferp = NULL;
    io_hdr.cmdp = aptCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    /* io_hdr.flags = 0; */     /* take defaults: indirect IO, etc */
    /* io_hdr.pack_id = 0; */
    /* io_hdr.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_sat_chk_power: SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }

    /* error processing: N.B. expect check condition, no sense ... !! */
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        break;
    case SG_LIB_CAT_RECOVERED:  /* sat-r09 (latest) uses this sk */
    case SG_LIB_CAT_NO_SENSE:   /* earlier SAT drafts used this */
        /* XXX: Until the spec decides which one to go with. 20060607 */
        ucp = sg_scsi_sense_desc_find(sense_buffer, sizeof(sense_buffer),
                                      SAT_ATA_RETURN_DESC);
        if (NULL == ucp) {
            if (verbose > 1)
                printf("ATA Return Descriptor expected in sense but not "
                       "found\n");
            sg_chk_n_print3("ATA_16 command error", &io_hdr, 1);
        } else if (verbose)
            sg_chk_n_print3("ATA Return Descriptor, as expected",
                             &io_hdr, 1);
        if (ucp && ucp[3]) {
            if (ucp[3] & 0x4)
                printf("error in returned FIS: aborted command\n");
            else
                printf("error=0x%x, status=0x%x\n", ucp[3], ucp[13]);
        }
        break;
    default:
        fprintf(stderr, "unexpected SCSI sense category\n");
        ucp = sg_scsi_sense_desc_find(sense_buffer, sizeof(sense_buffer),
                                      SAT_ATA_RETURN_DESC);
        if (NULL == ucp)
            sg_chk_n_print3("ATA_16 command error", &io_hdr, 1);
        else if (verbose)
            sg_chk_n_print3("ATA Return Descriptor, as expected",
                             &io_hdr, 1);
        if (ucp && ucp[3]) {
            if (ucp[3] & 0x4)
                printf("error in returned FIS: aborted command\n");
            else
                printf("error=0x%x, status=0x%x\n", ucp[3], ucp[13]);
        }
        break;
    }

    if (ucp) {
        switch (ucp[5]) {       /* sector_count (7:0) */
        case 0xff:
            printf("In active mode or idle mode\n");
            break;
        case 0x80:
            printf("In idle mode\n");
            break;
        case 0x41:
            printf("In NV power mode and spindle is spun or spinning up\n");
            break;
        case 0x40:
            printf("In NV power mode and spindle is spun or spinning down\n");
            break;
        case 0x0:
            printf("In standby mode\n");
            break;
        default:
            printf("unknown power mode (sector count) value=0x%x\n", ucp[5]);
            break;
        }
    } else
        fprintf(stderr, "Expecting a ATA Return Descriptor in sense and "
                "didn't receive it\n");

    close(sg_fd);
    return 0;
}

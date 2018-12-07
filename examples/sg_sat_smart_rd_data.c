/*
 * Copyright (c) 2006-2018 Douglas Gilbert.
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
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_lib.h"
#include "sg_io_linux.h"

/* This program performs a ATA PASS-THROUGH (16) SCSI command in order
   to perform an ATA SMART/READ DATA command. See http://www.t10.org
   SAT draft at time of writing: sat-r08.pdf

   Invocation: sg_sat_smart_rd_data [-v] [-V] <device>

*/

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */

#define ATA_SMART 0xb0
#define ATA_SMART_READ_DATA 0xd0
#define SMART_READ_DATA_RESPONSE_LEN 512

#define EBUFF_SZ 256

static char * version_str = "1.05 20181207";

int main(int argc, char * argv[])
{
    int sg_fd, k, ok;
    uint8_t apt_cdb[SAT_ATA_PASS_THROUGH16_LEN] =
                {SAT_ATA_PASS_THROUGH16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0};
    sg_io_hdr_t io_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    uint8_t inBuff[SMART_READ_DATA_RESPONSE_LEN];
    uint8_t sense_buffer[32];
    int verbose = 0;
    int extend = 0;
    int chk_cond = 0;   /* set to 1 to read register(s) back */
    int protocol = 4;   /* PIO data-in */
    int t_dir = 1;      /* 0 -> to device, 1 -> from device */
    int byte_block = 1; /* 0 -> bytes, 1 -> 512 byte blocks */
    int t_length = 2;   /* 0 -> no data transferred, 2 -> sector count */
    const uint8_t * bp = NULL;

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
        printf("Usage: 'sg_sat_smart_rd_data [-v] [-V] <device>'\n");
        return 1;
    }

    if ((sg_fd = open(file_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "sg_sat_smart_rd_data: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }

    /* Prepare ATA PASS-THROUGH COMMAND (16) command */
    apt_cdb[4] = ATA_SMART_READ_DATA;   /* feature (7:0) */
    apt_cdb[6] = 1;   /* number of block (sector count) */
    apt_cdb[10] = 0x4f;    /* lba_mid (7:0) */
    apt_cdb[12] = 0xc2;    /* lba_high (7:0) */
    apt_cdb[14] = ATA_SMART;
    apt_cdb[1] = (protocol << 1) | extend;
    apt_cdb[2] = (chk_cond << 5) | (t_dir << 3) | (byte_block << 2) |
                 t_length;
    if (verbose) {
        fprintf(stderr, "    ata pass through(16) cdb: ");
        for (k = 0; k < SAT_ATA_PASS_THROUGH16_LEN; ++k)
            fprintf(stderr, "%02x ", apt_cdb[k]);
        fprintf(stderr, "\n");
    }

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(apt_cdb);
    /* io_hdr.iovec_count = 0; */  /* memset takes care of this */
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = SMART_READ_DATA_RESPONSE_LEN;
    io_hdr.dxferp = inBuff;
    io_hdr.cmdp = apt_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    /* io_hdr.flags = 0; */     /* take defaults: indirect IO, etc */
    /* io_hdr.pack_id = 0; */
    /* io_hdr.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_sat_smart_rd_data: SG_IO ioctl error");
        close(sg_fd);
        return 1;
    }

    /* now for the error processing */
    ok = 0;
    switch (sg_err_category3(&io_hdr)) {
    case SG_LIB_CAT_CLEAN:
        ok = 1;
        break;
    case SG_LIB_CAT_RECOVERED:
        bp = sg_scsi_sense_desc_find(sense_buffer, sizeof(sense_buffer),
                                     SAT_ATA_RETURN_DESC);
        if (NULL == bp) {
            if (verbose > 1)
                printf("ATA Return Descriptor expected in sense but not "
                       "found\n");
            sg_chk_n_print3("ATA_16 command error", &io_hdr, 1);
        } else if (verbose)
            sg_chk_n_print3("ATA Return Descriptor", &io_hdr, 1);
        if (bp && bp[3])
            printf("error=0x%x, status=0x%x\n", bp[3], bp[13]);
        else
            ok = 1;
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("ATA_16 command error", &io_hdr, 1);
        break;
    }

    if (ok) { /* output result if it is available */
        printf("Response:\n");
        dWordHex((const unsigned short *)inBuff, 256, 0,
                 sg_is_big_endian());
    }

    close(sg_fd);
    return 0;
}

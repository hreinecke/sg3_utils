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
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_lib.h"
#include "sg_io_linux.h"

/* This program uses a ATA PASS-THROUGH (16) SCSI command to package
   an ATA IDENTIFY DEVICE (A1h) command. If the '-p' option is given,
   it will package an ATA IDENTIFY PACKET DEVICE (Ech) instead (for
   ATAPI device like cd/dvd drives) See http://www.t10.org
   SAT draft at time of writing: sat-r08a.pdf

   Invocation: sg__sat_identify [-p] [-v] [-V] <device>

   With SAT, the user can find out whether a device is an ATA disk or
   an ATAPI device. The ATA Information VPD page contains a "command
   code" field in byte 56. Its values are either ECh for a (s/p)ATA
   disk, A1h for a (s/p)ATAPI device, or 0 for unknown.

*/

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_RETURN_DESC 9  /* ATA Return (sense) Descriptor */

#define ATA_IDENTIFY_DEVICE 0xec
#define ATA_IDENTIFY_PACKET_DEVICE 0xa1
#define ID_RESPONSE_LEN 512

#define EBUFF_SZ 256

static char * version_str = "1.04 20180220";

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg__sat_identify [-p] [-v] [-V] <device>\n"
          "  where: -p    do IDENTIFY PACKET DEVICE (def: IDENTIFY "
          "DEVICE) command\n"
          "         -v    increase verbosity\n"
          "         -V    print version string and exit\n\n"
          "Performs a IDENTIFY (PACKET) DEVICE ATA command via a SAT "
          "pass through\n");
}

int main(int argc, char * argv[])
{
    int sg_fd, k, ok;
    uint8_t apt_cdb[SAT_ATA_PASS_THROUGH16_LEN] =
                {SAT_ATA_PASS_THROUGH16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0};
    sg_io_hdr_t io_hdr;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    uint8_t inBuff[ID_RESPONSE_LEN];
    uint8_t sense_buffer[32];
    int do_packet = 0;
    int verbose = 0;
    int extend = 0;
    int chk_cond = 0;   /* set to 1 to read register(s) back */
    int protocol = 4;   /* PIO data-in */
    int t_dir = 1;      /* 0 -> to device, 1 -> from device */
    int byte_block = 1; /* 0 -> bytes, 1 -> 512 byte blocks */
    int t_length = 2;   /* 0 -> no data transferred, 2 -> sector count */
    const uint8_t * cucp;

    memset(inBuff, 0, sizeof(inBuff));
    for (k = 1; k < argc; ++k) {
        if (0 == strcmp(argv[k], "-p"))
            ++do_packet;
        else if (0 == strcmp(argv[k], "-v"))
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
        usage();
        return 1;
    }

    if ((sg_fd = open(file_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "sg__sat_identify: error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }

    /* Prepare ATA PASS-THROUGH COMMAND (16) command */
    apt_cdb[6] = 1;   /* sector count */
    apt_cdb[14] = (do_packet ? ATA_IDENTIFY_PACKET_DEVICE :
                                 ATA_IDENTIFY_DEVICE);
    apt_cdb[1] = (protocol << 1) | extend;
    apt_cdb[2] = (chk_cond << 5) | (t_dir << 3) |
                 (byte_block << 2) | t_length;
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
    io_hdr.dxfer_len = ID_RESPONSE_LEN;
    io_hdr.dxferp = inBuff;
    io_hdr.cmdp = apt_cdb;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    /* io_hdr.flags = 0; */     /* take defaults: indirect IO, etc */
    /* io_hdr.pack_id = 0; */
    /* io_hdr.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg__sat_identify: SG_IO ioctl error");
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
        if (verbose)
            sg_chk_n_print3(">>> ATA_16 command", &io_hdr, 1);
        /* check for ATA Return Descriptor */
        cucp = sg_scsi_sense_desc_find(io_hdr.sbp, io_hdr.sb_len_wr,
                                       SAT_ATA_RETURN_DESC);
        if (cucp && (cucp[3])) {
            if (cucp[3] & 0x4) {
                printf("error in returned FIS: aborted command\n");
                printf("    try again with%s '-p' option\n",
                       (do_packet ? "out" : ""));
                break;
            }
        }
        ok = 1;         /* not sure what is happening so output response */
        if (0 == verbose) {
            printf(">>> Recovered error on ATA_16, may have failed\n");
            printf("    Add '-v' for more information\n");
        }
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("ATA_16 command error", &io_hdr, 1);
        break;
    }

    if (ok) { /* output result if it is available */
        printf("Response for IDENTIFY %sDEVICE ATA command:\n",
               (do_packet ? "PACKET " : ""));
        dWordHex((const unsigned short *)inBuff, 256, 0,
                 sg_is_big_endian());
    }

    close(sg_fd);
    return 0;
}

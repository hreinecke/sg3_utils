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
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "sg_lib.h"
#include "sg_io_linux.h"

/* This program uses a ATA PASS-THROUGH (16) SCSI command defined
   by SAT to package an ATA READ LOG EXT (2Fh) command to fetch
   log page 11h. That page contains SATA phy event counters.
   For SAT see http://www.t10.org [draft prior to standard: sat-r09.pdf]
   For ATA READ LOG EXT command see ATA-8/ACS at www.t13.org .
   For SATA phy counter definitions see SATA 2.5 .

   Invocation: sg_sat_phy_event [-v] [-V] <device>

*/

#define SAT_ATA_PASS_THROUGH16 0x85
#define SAT_ATA_PASS_THROUGH16_LEN 16
#define SAT_ATA_RETURN_DESC 9  /* ATA Return Descriptor */

#define ATA_READ_LOG_EXT 0x2f
#define SATA_PHY_EVENT_LPAGE 0x11
#define READ_LOG_EXT_RESPONSE_LEN 512

#define EBUFF_SZ 256

static char * version_str = "1.00 20070507";

static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"ignore", no_argument, 0, 'i'},
        {"raw", no_argument, 0, 'r'},
        {"reset", no_argument, 0, 'R'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_sat_phy_event [--help] [--hex] [--raw] [--reset] [--verbose]\n"
          "                        [--version] DEVICE\n"
          "  where:\n"
          "    --help|-h       print this usage message then exit\n"
          "    --hex|-H        output response in hex bytes, use twice for\n"
          "                    hex words\n"
          "    --ignore|-i     ignore identifier names, output id value "
          "instead\n"
          "    --raw|-r        output response in binary to stdout\n"
          "    --reset|-R      reset counters (after read)\n"
          "    --verbose|-v    increase verbosity\n"
          "    --version|-V    print version string then exit\n\n"
          "Sends an ATA READ LOG EXT command via a SAT pass through to "
          "fetch\nlog page 11h which contains SATA phy event counters\n");
}

struct phy_event_t {
    int id;
    char * desc;
};

static struct phy_event_t phy_event_arr[] = {
    {0x1, "Command failed and ICRC error bit set in Error register"},
    {0x2, "R_ERR(p) response for data FIS"},
    {0x3, "R_ERR(p) response for device-to-host data FIS"},
    {0x4, "R_ERR(p) response for host-to-device data FIS"},
    {0x5, "R_ERR(p) response for non-data FIS"},
    {0x6, "R_ERR(p) response for device-to-host non-data FIS"},
    {0x7, "R_ERR(p) response for host-to-device non-data FIS"},
    {0x8, "Device-to-host non-data FIS retries"},
    {0x9, "Transition from drive PHYRDY to drive PHYRDYn"},
    {0xa, "Signature device-to-host register FISes due to COMRESET"},
    {0xb, "CRC errors within host-to-device FIS"},
    {0xd, "non CRC errors within host-to-device FIS"},
    {0xf, "R_ERR(p) response for host-to-device data FIS, CRC"},
    {0x10, "R_ERR(p) response for host-to-device data FIS, non-CRC"},
    {0x12, "R_ERR(p) response for host-to-device non-data FIS, CRC"},
    {0x13, "R_ERR(p) response for host-to-device non-data FIS, non-CRC"},
    {0xc00, "PM: host-to-device non-data FIS, R_ERR(p) due to collision"},
    {0xc01, "PM: signature register - device-to-host FISes"},
    {0xc02, "PM: corrupts CRC propagation of device-to-host FISes"},
    {0x0, NULL},
};

static const char * find_phy_desc(int id)
{
    const struct phy_event_t * pep;

    for (pep = phy_event_arr; pep->desc; ++pep) {
        if ((id & 0xfff) == pep->id)
            return pep->desc;
    }
    return NULL;
}

static void dStrRaw(const char* str, int len)
{
    int k;

    for (k = 0 ; k < len; ++k)
        printf("%c", str[k]);
}

int main(int argc, char * argv[])
{
    int sg_fd, c, k, j, ok, res, id, len, vendor;
    unsigned char aptCmdBlk[SAT_ATA_PASS_THROUGH16_LEN] =
                {SAT_ATA_PASS_THROUGH16, 0, 0, 0, 0, 0, 0, 0,
                 0, 0, 0, 0, 0, 0, 0, 0};
    sg_io_hdr_t io_hdr;
    char * device_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char inBuff[READ_LOG_EXT_RESPONSE_LEN];
    unsigned char sense_buffer[64];
    int hex = 0;
    int ignore = 0;
    int raw = 0;
    int reset = 0;
    int verbose = 0;
    int extend = 0;
    int chk_cond = 0;   /* set to 1 to read register(s) back */
    int protocol = 4;   /* PIO data-in */
    int t_dir = 1;      /* 0 -> to device, 1 -> from device */
    int byte_block = 1; /* 0 -> bytes, 1 -> 512 byte blocks */
    int t_length = 2;   /* 0 -> no data transferred, 2 -> sector count */
    const unsigned char * cucp;
    int ret = 0;
    uint64_t ull;
    const char * cp;

    memset(inBuff, 0, sizeof(inBuff));
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hHirRvV",
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            usage();
            exit(0);
        case 'H':
            ++hex;
            break;
        case 'i':
            ++ignore;
            break;
        case 'r':
            ++raw;
            break;
        case 'R':
            ++reset;
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            exit(0);
        default:
            fprintf(stderr, "unrecognised option code %c [0x%x]\n", c, c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (0 == device_name) {
        fprintf(stderr, "no DEVICE name detected\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((sg_fd = open(device_name, O_RDWR)) < 0) {
        snprintf(ebuff, EBUFF_SZ,
                 "sg_sat_phy_event: error opening file: %s", device_name);
        perror(ebuff);
        return SG_LIB_FILE_ERROR;
    }

    /* Prepare SCSI ATA PASS-THROUGH COMMAND (16) command */
    if (reset > 0)
        aptCmdBlk[4] = 1;                       /* features (7:0) */
    aptCmdBlk[6] = 1;                           /* sector count */
    aptCmdBlk[8] = SATA_PHY_EVENT_LPAGE;        /* lba_low (7:0) */
    aptCmdBlk[14] = ATA_READ_LOG_EXT;           /* command */
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
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = READ_LOG_EXT_RESPONSE_LEN;
    io_hdr.dxferp = inBuff;
    io_hdr.cmdp = aptCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    /* io_hdr.flags = 0; */     /* take defaults: indirect IO, etc */
    /* io_hdr.pack_id = 0; */
    /* io_hdr.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_sat_phy_event: SG_IO ioctl error");
        close(sg_fd);
        return SG_LIB_CAT_OTHER;
    }

    /* now for the error processing */
    ok = 0;
    ret = sg_err_category3(&io_hdr);
    switch (ret) {
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
                fprintf(stderr, "error in returned FIS: aborted command\n");
                break;
            }
        }
        ret = 0;
        ok = 1;         /* not sure what is happening so output response */
        if (0 == verbose) {
            fprintf(stderr, ">>> Recovered error on ATA_16, may have "
                    "failed\n");
            fprintf(stderr, "    Add '-v' for more information\n");
        }
        break;
    default: /* won't bother decoding other categories */
        sg_chk_n_print3("ATA_16 command error", &io_hdr, 1);
        break;
    }

    if (ok) { /* output result if it is available */
        if (raw > 0)
            dStrRaw((const char *)inBuff, 512);
        else {
            if (verbose && hex)
                fprintf(stderr, "Response to READ LOG EXT (page=11h):\n");
            if (1 == hex)
                dStrHex((const char *)inBuff, 512, 0);
            else if (hex > 1)
                dWordHex((const unsigned short *)inBuff, 256, 0,
                         sg_is_big_endian());
            else {
                printf("SATA phy event counters:\n");
                for (k = 4; k < 512; k += (len + 2)) {
                    id = (inBuff[k + 1] << 8) + inBuff[k];
                    if (0 == id)
                        break;
                    len = ((id >> 12) & 0x7) * 2;
                    vendor = !!(id & 0x8000);
                    id = id & 0xfff;
                    ull = 0;
                    for (j = len - 1; j >= 0; --j) {
                        if (j < (len - 1))
                            ull <<= 8;
                        ull |= inBuff[k + 2 + j];
                    }
                    cp = NULL;
                    if ((0 == vendor) && (0 == ignore))
                        cp = find_phy_desc(id);
                    if (cp)
                        printf("  %s: %" PRIu64 "\n", cp, ull);
                    else
                        printf("  id=0x%x, vendor=%d, data_len=%d, "
                               "val=%" PRIu64 "\n", id, vendor, len, ull);
                }
            }
        }
    }
    res = close(sg_fd);
    if (res < 0) {
        fprintf(stderr, "close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

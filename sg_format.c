/*
** sg_format : format a SCSI disk (potentially with a different block size)
**
** formerly called blk512-linux.c (v0.4)
**
** Copyright (C) 2003  Grant Grundler    grundler at parisc-linux dot org
** Copyright (C) 2003  James Bottomley       jejb at parisc-linux dot org
** Copyright (C) 2005  Douglas Gilbert   dgilbert at interlog dot com
**
**   This program is free software; you can redistribute it and/or modify
**   it under the terms of the GNU General Public License as published by
**   the Free Software Foundation; either version 2, or (at your option)
**   any later version.
**
** http://www.t10.org/scsi-3.htm
** http://www.tldp.org/HOWTO/SCSI-Generic-HOWTO
**
**
**  List of some (older) disk manufacturers' block counts.
**  These are not needed in newer disks which will automatically use
**  the manufacturers' recommended block count if a count of -1 is given.
**      Inquiry         Block Count (@512 byte blocks)
**      ST150150N       8388315
**      IBM_DCHS04F     8888543
**      IBM_DGHS09Y     17916240
**      ST336704FC      71132960
**      ST318304FC      35145034  (Factory spec is 35885167 sectors)
**      ST336605FC      ???
**      ST336753FC      71132960  (Factory spec is 71687372 sectors) 
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <scsi/scsi.h>
#include <scsi/scsi_ioctl.h>
#include <scsi/sg.h>
#include <sys/errno.h>

#include "sg_lib.h"
#include "sg_cmds.h"

#define RW_ERROR_RECOVERY_PAGE 1  /* every disk should have one */
#define FORMAT_DEV_PAGE 3         /* Format Device Mode Page [now obsolete] */
#define CONTROL_MODE_PAGE 0xa     /* alternative page all devices have?? */

#define CDB_SIZE                6       /* SCSI Command Block */
#define MODE_HDR_SIZE           4       /* Mode Sense Header */
#define BLOCK_DESCR_SIZE        8       /* Block Descriptor Header */

#define LOGICAL_UNIT_NOT_READY  4 /* ASC */
#define FORMAT_IN_PROGRESS      4 /* ASCQ */

#define SHORT_TIMEOUT           20000   /* 20 seconds unless immed=0 ... */
#define FORMAT_TIMEOUT          (4 * 3600 * 1000)       /* 4 hours ! */

#define POLL_DURATION_SECS 30
 

#define MAX_SENSE_SZ    32
static unsigned char sbuff[MAX_SENSE_SZ];

#define MAX_BUFF_SZ     252
static unsigned char dbuff[MAX_BUFF_SZ];

static char * version_str = "1.03 20050405";

static struct option long_options[] = {
        {"count", 1, 0, 'c'},
        {"early", 0, 0, 'e'},
        {"format", 0, 0, 'F'},
        {"help", 0, 0, 'h'},
        {"long", 0, 0, 'l'},
        {"pinfo", 0, 0, 'p'},
        {"resize", 0, 0, 'r'},
        {"rto_req", 0, 0, 'R'},
        {"size", 1, 0, 's'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {"wait", 0, 0, 'w'},
        {0, 0, 0, 0},
};

static const char * scsi_ptype_strs[] = {
        "disk",                             /* 0x0 */
        "tape",
        "printer",
        "processor",
        "write once optical disk",
        "cd/dvd",
        "scanner",
        "optical memory device",
        "medium changer",                   /* 0x8 */
        "communications",
        "graphics [0xa]",
        "graphics [0xb]",
        "storage array controller",
        "enclosure services device",
        "simplified direct access device",
        "optical card reader/writer device",
        "bridge controller commands",       /* 0x10 */
        "object storage device",
        "automation/drive interface",
        "0x13", "0x14", "0x15", "0x16", "0x17", "0x18",
        "0x19", "0x1a", "0x1b", "0x1c", "0x1d",
        "well known logical unit",
        "no physical device on this lu",
};

static const char * get_ptype_str(int scsi_ptype)
{
        int num = sizeof(scsi_ptype_strs) / sizeof(scsi_ptype_strs[0]);

        return (scsi_ptype < num) ? scsi_ptype_strs[scsi_ptype] : "";
}


/* Return 0 on success, else -1 */
static int
scsi_format(int fd, int pinfo, int rto_req, int immed, int early, int verbose)
{
        int k, res;
        const char FORMAT_HEADER_SIZE = 4;
        unsigned char cdb[CDB_SIZE], fmt_hdr[FORMAT_HEADER_SIZE];
        sg_io_hdr_t io_hdr;

        cdb[0] = FORMAT_UNIT;
        cdb[1] = (pinfo ? 0x80 : 0) | (rto_req ? 0x40 : 0) |
                 (immed ? 0x10 : 0);
        cdb[2] = 0;             /* vendor specific */
        cdb[3] = 0;             /* interleave MSB */
        cdb[4] = 0;             /* interleave LSB */
        cdb[5] = 0;             /* control */

        /* fmt_hdr is a short format header, only used when 'immed' is set */
        fmt_hdr[0] = 0;         /* reserved */
        fmt_hdr[1] = 0x02;      /* use device defaults, IMMED return */
        fmt_hdr[2] = 0;         /* defect list length MSB */
        fmt_hdr[3] = 0;         /* defect list length LSB */

        memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
        memset(sbuff, 0, MAX_SENSE_SZ);
        io_hdr.interface_id = 'S';
        io_hdr.dxfer_direction = immed ? SG_DXFER_TO_DEV : SG_DXFER_NONE;
        io_hdr.cmd_len = CDB_SIZE;
        io_hdr.mx_sb_len = MAX_SENSE_SZ;
        io_hdr.iovec_count = 0;         /* no scatter gather */
        if (immed) {
                io_hdr.dxfer_len = FORMAT_HEADER_SIZE;
                io_hdr.dxferp = fmt_hdr;
        }
        io_hdr.cmdp = cdb;
        io_hdr.sbp = sbuff;
        io_hdr.timeout = immed ? SHORT_TIMEOUT : FORMAT_TIMEOUT;

        if (verbose) {
                fprintf(stderr, "    format cdb: ");
                for (k = 0; k < 6; ++k)
                        fprintf(stderr, "%02x ", cdb[k]);
                fprintf(stderr, "\n");
        }
        if ((verbose > 1) && immed) {
                fprintf(stderr, "    format parameter block\n");
                dStrHex((const char *)fmt_hdr, FORMAT_HEADER_SIZE, -1);
        }

        if (ioctl(fd, SG_IO, &io_hdr) < 0) {
                perror("FORMAT UNIT ioctl error");
                return -1;
        }
        if (verbose > 2)
                fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
        res = sg_err_category3(&io_hdr);
        switch (res) {
        case SG_LIB_CAT_RECOVERED:
            sg_chk_n_print3("Format, continuing", &io_hdr);
            /* fall through */
        case SG_LIB_CAT_CLEAN:
                break;
        case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, "Format command not supported\n");
                if (verbose > 1)
                        sg_chk_n_print3("Format", &io_hdr);
                return -1;
        case SG_LIB_CAT_ILLEGAL_REQ:
                fprintf(stderr, "Format command illegal parameter\n");
                if (verbose > 1)
                        sg_chk_n_print3("Format", &io_hdr);
                return -1;
        default:
                if (verbose > 1)
                        sg_chk_n_print3("Format", &io_hdr);
                return -1;
        }
        if (! immed)
                return 0;

        printf("\nFormat has started\n");
        if (early) {
                if (immed)
                        printf("Format continuing, use request sense or "
                               "test unit ready to monitor progress\n");
                return 0;
        }

        for(;;) {
                int progress;
                struct sg_scsi_sense_hdr sshdr;

                sleep(POLL_DURATION_SECS);
                cdb[0] = TEST_UNIT_READY;       /* draft say REQUEST SENSE */
                cdb[1] = 0;
                cdb[2] = 0;
                cdb[3] = 0;
                cdb[4] = 0;
                cdb[5] = 0;

                memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
                memset(sbuff, 0, MAX_SENSE_SZ);

                io_hdr.interface_id = 'S';
                io_hdr.dxfer_direction = SG_DXFER_NONE;
                io_hdr.cmd_len = CDB_SIZE;
                io_hdr.mx_sb_len = MAX_SENSE_SZ;
                io_hdr.iovec_count = 0;         /* no scatter gather */
                io_hdr.dxfer_len = 0;
                io_hdr.dxferp = NULL;
                io_hdr.cmdp = cdb;
                io_hdr.sbp = sbuff;
                io_hdr.timeout = SHORT_TIMEOUT;

                if (verbose) {
                        fprintf(stderr, "    test unit ready cdb: ");
                        for (k = 0; k < 6; ++k)
                                fprintf(stderr, "%02x ", cdb[k]);
                        fprintf(stderr, "\n");
                }
        
                if (ioctl(fd, SG_IO, &io_hdr) < 0) {
                        perror("Test Unit Ready SG_IO ioctl error");
                        return -1;
                }
                if (sg_normalize_sense(&io_hdr, &sshdr)) {
                        if (sg_get_sense_progress_fld(sbuff,
                                        io_hdr.sb_len_wr, &progress)) {
                                printf("Format in progress, %d%% done\n",
                                        progress * 100 / 65536);
                                if (verbose > 1)
                                        sg_print_sense("tur", sbuff,
                                                       io_hdr.sb_len_wr);
                                continue;
                        } else {
                                sg_print_sense("tur: unexpected sense", sbuff,
                                               io_hdr.sb_len_wr);
                                continue;
                        }
                } else
                        break;
        }
        printf("FORMAT Complete\n");
        return 0;
}

#define RCAP_REPLY_LEN 32

static int
print_read_cap(int fd, int do_16, int verbose)
{
        int res, k;
        unsigned char resp_buff[RCAP_REPLY_LEN];
        unsigned int last_blk_addr, block_size;
        unsigned long long llast_blk_addr;

        if (do_16) {
                res = sg_ll_readcap_16(fd, 0 /* pmi */, 0 /* llba */,
                                       resp_buff, 32, verbose);
                if (0 == res) {
                        for (k = 0, llast_blk_addr = 0; k < 8; ++k) {
                                llast_blk_addr <<= 8;
                                llast_blk_addr |= resp_buff[k];
                        }
                        block_size = ((resp_buff[8] << 24) |
                                      (resp_buff[9] << 16) |
                                      (resp_buff[10] << 8) |
                                      resp_buff[11]);
                        printf("Read Capacity (16) results:\n");
                        printf("   Protection: prot_en=%d, rto_en=%d\n",
                               !!(resp_buff[12] & 0x1),
                               !!(resp_buff[12] & 0x2));
                        printf("   Number of blocks=%llu\n",
                               llast_blk_addr + 1);
                        printf("   Block size=%u bytes\n", block_size);
                        return (int)block_size;
                }
        } else {
                res = sg_ll_readcap_10(fd, 0 /* pmi */, 0 /* lba */,
                                       resp_buff, 8, verbose);
                if (0 == res) {
                        last_blk_addr = ((resp_buff[0] << 24) |
                                         (resp_buff[1] << 16) |
                                         (resp_buff[2] << 8) |
                                         resp_buff[3]);
                        block_size = ((resp_buff[4] << 24) |
                                      (resp_buff[5] << 16) |
                                      (resp_buff[6] << 8) |
                                      resp_buff[7]);
                        printf("Read Capacity (10) results:\n");
                        printf("   Number of blocks=%u\n", 
                               last_blk_addr + 1);
                        printf("   Block size=%u bytes\n", block_size);
                        return (int)block_size;
                }
        }
        if (SG_LIB_CAT_INVALID_OP == res) 
                fprintf(stderr, "READ CAPACITY (%d) not supported\n",
                        (do_16 ? 16 : 10));
        if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "bad field in READ CAPACITY (%d) "
                        "cdb\n", (do_16 ? 16 : 10));
        if (verbose)
                fprintf(stderr, "READ CAPACITY (%d) failed "
                        "[res=%d]\n", (do_16 ? 16 : 10), res);
        return -1;
}

static void usage()
{
        printf("usage: sg_format [--count=<block count>] [--early] [--format]"
                " [--help]\n"
                "                 [--long] [--pinfo] [--resize] [--rto_req]\n"
                "                 [--size=<block size>] [--verbose]"
                " [--version] [--wait]\n"
                "                 <scsi_disk>\n"
                "  where:\n"
                "    --count=<block count> | -c <block count>\n"
                "                   best left alone during format (defaults "
                "to max allowable)\n"
                "    --early | -e   exit once format started (user can "
                "monitor progress)\n"
                "    --format | -F  format unit (default report current count"
                " and size)\n"
                "    --help | -h    prints out this usage message\n"
                "    --long | -l    allow for 64 bit lbas (default: assume "
                "32 bit lbas)\n"
                "    --pinfo | -p   set the FMTPINFO bit to format with "
                "protection\n");
        printf( "                   information (defaults to no protection "
                "information)\n"
                "    --resize | -r  resize (rather than format) to '--count' "
                "value\n"
                "    --rto_req | -R  set the RTO_REQ bit in format (only valid "
                "with '--pinfo')\n"
                "    --size=<block size> | -s <block size>\n"
                "                   only needed to change block size"
                " (default to\n"
                "                   current device's block size)\n"
                "    --verbose | -v verbosity (show commands + parameters "
                "sent)\n"
                "                   use multiple time for more verbosity\n"
                "    --version | -V print version details and exit\n"
                "    --wait | -w    format command waits till complete (def: "
                "poll)\n\n"
                "\tExample: sg_format --format /dev/sdc\n");
        printf("\nWARNING: This program will destroy all the data on the "
                "target device when\n\t '--format' is given. Check that you "
                "have the correct device.\n");
}


int main(int argc, char **argv)
{
        const int mode_page = RW_ERROR_RECOVERY_PAGE;
        int fd, res, calc_len, bd_len, dev_specific_param;
        int offset, j, bd_blk_len, prob, len;
        unsigned long long ull;
        long long blk_count = 0;  /* -c value */
        int blk_size = 0;     /* -s value */
        int format = 0;         /* -F */
        int resize = 0;         /* -r */
        int verbose = 0;        /* -v */
        int fwait = 0;          /* -w */
        int mode6 = 0;
        int pinfo = 0;
        int rto_req = 0;
        int do_rcap16 = 0;
        int long_lba = 0;
        int early = 0;
        char device_name[256];
        struct sg_simple_inquiry_resp inq_out;
        int ret = 1;

        device_name[0] = '\0';
        while (1) {
                int option_index = 0;
                char c;

                c = getopt_long(argc, argv, "c:eFhlprRs:vVw",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'c':
                        if (0 == strcmp("-1", optarg))
                                blk_count = -1;
                        else {
                                blk_count = sg_get_llnum(optarg);
                                if (-1 == blk_count) {
                                        fprintf(stderr, "bad argument to "
                                                "'--count'\n");
                                        return 1;
                                }
                        }
                        break;
                case 'e':
                        early = 1;
                        break;
                case 'F':
                        format = 1;
                        break;
                case 'h':
                        usage();
                        return 0;
                case 'l':
                        long_lba = 1;
                        do_rcap16 = 1;
                        break;
                case 'p':
                        pinfo = 1;
                        break;
                case 'r':
                        resize = 1;
                        break;
                case 'R':
                        rto_req = 1;
                        break;
                case 's':
                        blk_size = sg_get_num(optarg);
                        if (blk_size <= 0) {
                                fprintf(stderr, "bad argument to '--size', "
                                        "want arg > 0)\n");
                                return 1;
                        }
                        break;
                case 'v':
                        verbose++;
                        break;
                case 'V':
                        fprintf(stderr, "sg_format version: %s\n",
                                version_str);
                        return 0;
                case 'w':
                        fwait = 1;
                        break;
                default:
                        usage();
                        return 1;
                }
        }
        if (optind < argc) {
                if ('\0' == device_name[0]) {
                        strncpy(device_name, argv[optind],
                                sizeof(device_name) - 1);
                        device_name[sizeof(device_name) - 1] = '\0';
                        ++optind;
                }
        }
        if (optind < argc) {
                for (; optind < argc; ++optind)
                        fprintf(stderr, "Unexpected extra argument: %s\n",
                                argv[optind]);
                usage();
                return 1;
        }
        if ('\0' == device_name[0]) {
                fprintf(stderr, "no device name given\n");
                usage();
                return 1;
        }
        if (resize) {
                if (format) {
                        fprintf(stderr, "both '--format' and '--resize'"
                                "not permitted\n");
                        usage();
                        return 1;
                } else if (0 == blk_count) {
                        fprintf(stderr, "'--resize' needs a '--count' (other"
                                " than 0)\n");
                        usage();
                        return 1;
                } else if (0 != blk_size) {
                        fprintf(stderr, "'--resize' not compatible with "
                                "'--size')\n");
                        usage();
                        return 1;
                }
        }

        /* FIXME: add more sanity checks:
        ** o block size/count might already be set...don't repeat
        ** o verify SCSI device is a disk (get inquiry data first)
        */

        if ((fd = open(device_name, O_RDWR)) < 0) {
                char ebuff[128];
                sprintf(ebuff, "error opening device file: %s", device_name);
                perror(ebuff);
                return 1;
        }

        if (sg_simple_inquiry(fd, &inq_out, 1, verbose)) {
                fprintf(stderr, "%s doesn't respond to a SCSI INQUIRY\n",
                        device_name);
                goto out;
        }
        printf("    %.8s  %.16s  %.4s   peripheral_type: %s [0x%x]\n",
               inq_out.vendor, inq_out.product, inq_out.revision,
               get_ptype_str(inq_out.peripheral_type),
               inq_out.peripheral_type);
        if (verbose)
                printf("      PROTECT=%d\n", !!(inq_out.byte_5 & 1));
        if (inq_out.byte_5 & 1)
                printf("      << supports 'protection information'>>\n");

        if ((0 != inq_out.peripheral_type) &&
            (0xe != inq_out.peripheral_type)) {
                fprintf(stderr, "This format is only defined for disks "
                        "(using SBC-2 or RBC)\n");
                goto out;
        }

        memset(dbuff, 0, MAX_BUFF_SZ);
        if (mode6)
                res = sg_ll_mode_sense6(fd, 0 /* DBD */, 0 /* current */,
                                        mode_page, 0 /* subpage */, dbuff,
                                        MAX_BUFF_SZ, 1, verbose);
        else
                res = sg_ll_mode_sense10(fd, long_lba, 0 /* DBD */,
                                         0 /* current */, mode_page,
                                         0 /* subpage */, dbuff,
                                         MAX_BUFF_SZ, 1, verbose);
        if (res) {
                if (SG_LIB_CAT_INVALID_OP == res)
                        fprintf(stderr, "MODE SENSE (%d) command is not "
                                "supported\n", (mode6 ? 6 : 10));
                else if (SG_LIB_CAT_ILLEGAL_REQ == res) {
                        if (long_lba && (! mode6)) 
                                fprintf(stderr, "bad field in MODE SENSE "
                                        "(%d) [longlba flag not supported?]"
                                        "\n", (mode6 ? 6 : 10));
                        else
                                fprintf(stderr, "bad field in MODE SENSE "
                                        "(%d) [mode_page %d not supported?]"
                                        "\n", (mode6 ? 6 : 10), mode_page);
                } else
                        fprintf(stderr, "MODE SENSE (%d) command failed\n",
                                (mode6 ? 6 : 10));
                goto out;
        }
        if (mode6) {
                calc_len = dbuff[0] + 1;
                dev_specific_param = dbuff[2];
                bd_len = dbuff[3];
                long_lba = 0;
                offset = 4;
                /* prepare for mode select */
                dbuff[0] = 0;
                dbuff[1] = 0;
                dbuff[2] = 0;
        } else {
                calc_len = (dbuff[0] << 8) + dbuff[1] + 2;
                dev_specific_param = dbuff[3];
                bd_len = (dbuff[6] << 8) + dbuff[7];
                long_lba = (dbuff[4] & 1);
                offset = 8;
                /* prepare for mode select */
                dbuff[0] = 0;
                dbuff[1] = 0;
                dbuff[2] = 0;
                dbuff[3] = 0;
        }
        if ((offset + bd_len) < calc_len)
                dbuff[offset + bd_len] &= 0x7f;  /* clear PS bit in mpage */
        prob = 0;
        bd_blk_len = 0;
        printf("Mode sense (block descriptor) data, prior to changes:\n");
        if (dev_specific_param & 0x40)
                printf("  <<< Write Protect (WP) bit set >>>\n");
        if (bd_len > 0) {
                ull = 0;
                for (j = 0; j < (long_lba ? 8 : 4); ++j) {
                        if (j > 0)
                                ull <<= 8;
                        ull |= dbuff[offset + j];
                }
                if (long_lba)
                        bd_blk_len = (dbuff[offset + 12] << 24) +
                                     (dbuff[offset + 13] << 16) +
                                     (dbuff[offset + 14] << 8) +
                                     dbuff[offset + 15];
                else
                        bd_blk_len = (dbuff[offset + 5] << 16) +
                                     (dbuff[offset + 6] << 8) +
                                     dbuff[offset + 7];
                if (long_lba) {
                        printf("  <<< longlba flag set (64 bit lba) >>>\n");
                        if (bd_len != 16)
                                prob = 1;
                } else if (bd_len != 8)
                        prob = 1;
                printf("  Number of blocks=%llu [0x%llx]\n", ull, ull);
                printf("  Block size=%d [0x%x]\n", bd_blk_len, bd_blk_len);
        } else {
                printf("  No block descriptors present\n");
                prob = 1;
        }
        if (resize ||
            (format && ((blk_count != 0) ||
                        ((blk_size > 0) && (blk_size != bd_blk_len))))) {
                /* want to run MODE SELECT */

/* Working Draft SCSI Primary Commands - 3 (SPC-3)    pg 255
**
** If the SCSI device doesn't support changing its capacity by changing
** the NUMBER OF BLOCKS field using the MODE SELECT command, the value
** in the NUMBER OF BLOCKS field is ignored. If the device supports changing
** its capacity by changing the NUMBER OF BLOCKS field, then the
** NUMBER OF BLOCKS field is interpreted as follows:
**      a) If the number of blocks is set to zero, the device shall retain
**         its current capacity if the block size has not changed. If the
**         number of blocks is set to zero and the block size has changed,
**         the device shall be set to its maximum capacity when the new
**         block size takes effect;
**
**      b) If the number of blocks is greater than zero and less than or
**         equal to its maximum capacity, the device shall be set to that
**         number of blocks. If the block size has not changed, the device
**         shall not become format corrupted. This capacity setting shall be
**         retained through power cycles, hard resets, logical unit resets,
**         and I_T nexus losses;
**
**      c) If the number of blocks field is set to a value greater than the
**         maximum capacity of the device and less than FFFF FFFFh, then the
**         command is terminated with a CHECK CONDITION status. The sense key
**         is set to ILLEGAL REQUEST. The device shall retain its previous
**         block descriptor settings; or
**
**      d) If the number of blocks is set to FFFF FFFFh, the device shall be
**         set to its maximum capacity. If the block size has not changed,
**         the device shall not become format corrupted. This capacity setting
**         shall be retained through power cycles, hard resets, logical unit
**         resets, and I_T nexus losses.
*/

                if (prob) {
                        fprintf(stderr, "Need to perform MODE SELECT (to "
                                "change number or blocks or block length)\n");
                        fprintf(stderr, "but (single) block descriptor not "
                                "found in earlier MODE SENSE\n");
                        goto out;
                }
                if (blk_count != 0)  {
                        len = (long_lba ? 8 : 4);
                        for (j = 0; j < len; ++j)
                                dbuff[offset + j] =
                                    (blk_count >> ((len - j - 1) * 8)) & 0xff;
                } else if ((blk_size > 0) && (blk_size != bd_blk_len)) {
                        len = (long_lba ? 8 : 4);
                        for (j = 0; j < len; ++j)
                                dbuff[offset + j] = 0;
                }
                if ((blk_size > 0) && (blk_size != bd_blk_len)) {
                        if (long_lba) {
                                dbuff[offset + 12] = (blk_size >> 24) & 0xff;
                                dbuff[offset + 13] = (blk_size >> 16) & 0xff;
                                dbuff[offset + 14] = (blk_size >> 8) & 0xff;
                                dbuff[offset + 15] = blk_size & 0xff;
                        } else {
                                dbuff[offset + 5] = (blk_size >> 16) & 0xff;
                                dbuff[offset + 6] = (blk_size >> 8) & 0xff;
                                dbuff[offset + 7] = blk_size & 0xff;
                        }
                }
                if (mode6)
                        res = sg_ll_mode_select6(fd, 1 /* PF */, 1 /* SP */,
                                                 dbuff, calc_len, 1, verbose);
                else
                        res = sg_ll_mode_select10(fd, 1 /* PF */, 1 /* SP */,
                                                  dbuff, calc_len, 1, verbose);
                if (res) {
                        if (SG_LIB_CAT_INVALID_OP == res)
                                fprintf(stderr, "MODE SELECT (%d) command is "
                                        "not supported\n", (mode6 ? 6 : 10));
                        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                                fprintf(stderr, "bad field in MODE SELECT "
                                        "(%d)\n", (mode6 ? 6 : 10));
                        else
                                fprintf(stderr, "MODE SELECT (%d) command "
                                        "failed\n", (mode6 ? 6 : 10));
                        goto out;
                }
        }
        if (resize) {
                ret = 0;
                printf("Resize operation seems to have been successful\n");
                goto out;
        }
        else if (! format) {
                res = print_read_cap(fd, do_rcap16, verbose);
                if ((res > 0) && (bd_blk_len > 0) &&
                    (res != (int)bd_blk_len)) {
                        printf("  Warning: mode sense and read capacity "
                               "report different block sizes [%d,%d]\n",
                               bd_blk_len, res);
                        printf("           Probably needs format\n");
                }
                printf("No changes made. To format use '--format'. To "
                       "resize use '--resize'\n");
                ret = 0;
                goto out;
        }

        if(format)
#if 1
                printf("\nA FORMAT will commence in 10 seconds\n");
                printf("    ALL data on %s will be DESTROYED\n", device_name);
                printf("        Press control-C to abort\n");
                sleep(5);
                printf("A FORMAT will commence in 5 seconds\n");
                printf("    ALL data on %s will be DESTROYED\n", device_name);
                printf("        Press control-C to abort\n");
                sleep(5);
                scsi_format(fd, pinfo, rto_req, ! fwait, early, verbose);
#else
                fprintf(stderr, "FORMAT ignored, testing\n");
#endif
        ret = 0;

out:
        close(fd);
        return ret;
}

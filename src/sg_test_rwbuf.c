/* sg_test_rwbuf.c */
/*
 * Program to test the SCSI host adapter by issueing
 * write and read operations on a device's buffer
 * and calculating checksums.
 * NOTE: If you can not reserve the buffer of the device
 * for this purpose (SG_GET_RESERVED_SIZE), you risk
 * serious data corruption, if the device is accessed by
 * somebody else in the meantime.
 * (c) 2000 Kurt Garloff <garloff at suse dot de>
 * heavily based on Doug Gilbert's sg_rbuf program.
 * (c) 1999-2008 Doug Gilbert
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * $Id: sg_test_rwbuf.c,v 1.1 2000/03/02 13:50:03 garloff Exp $
 *
 *   2003/11/11  switch sg3_utils version to use SG_IO ioctl [dpg]
 *   2004/06/08  remove SG_GET_VERSION_NUM check [dpg]
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <time.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_io_linux.h"


static char * version_str = "1.07 20100423";

#define BPI (signed)(sizeof(int))

#define RB_MODE_DESC 3
#define RWB_MODE_DATA 2
#define RB_DESC_LEN 4

/*  The microcode in a SCSI device is _not_ modified by doing a WRITE BUFFER
 *  with mode set to "data" (0x2) as done by this utility. Therefore this
 *  utility is safe in that respect. [Mode values 0x4, 0x5, 0x6 and 0x7 are
 *  the dangerous ones :-)]
 */

#define ME "sg_test_rwbuf: "

static int base = 0x12345678;
static int buf_capacity = 0;
static int buf_granul = 255;
static unsigned char *cmpbuf = NULL;


/* Options */
static int size = -1;
static char do_quick = 0;
static int addwrite  = 0;
static int addread   = 0;
static int verbose   = 0;

static struct option long_options[] = {
        {"help", 0, 0, 'h'},
        {"quick", 0, 0, 'q'},
        {"addrd", 1, 0, 'r'},
        {"size", 1, 0, 's'},
        {"times", 1, 0, 't'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {"addwr", 1, 0, 'w'},
        {0, 0, 0, 0},
};

int find_out_about_buffer (int sg_fd)
{
        unsigned char rbCmdBlk[] = {READ_BUFFER, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        unsigned char rbBuff[RB_DESC_LEN];
        unsigned char sense_buffer[32];
        struct sg_io_hdr io_hdr;
        int k, res;

        rbCmdBlk[1] = RB_MODE_DESC;
        rbCmdBlk[8] = RB_DESC_LEN;
        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(rbCmdBlk);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = RB_DESC_LEN;
        io_hdr.dxferp = rbBuff;
        io_hdr.cmdp = rbCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */

        if (verbose) {
                fprintf(stderr, "    read buffer [mode desc] cdb: ");
                for (k = 0; k < (int)sizeof(rbCmdBlk); ++k)
                        fprintf(stderr, "%02x ", rbCmdBlk[k]);
                fprintf(stderr, "\n");
        }
        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
                perror(ME "SG_IO READ BUFFER descriptor error");
                return -1;
        }
        /* now for the error processing */
        res = sg_err_category3(&io_hdr);
        switch (res) {
        case SG_LIB_CAT_RECOVERED:
                sg_chk_n_print3("READ BUFFER descriptor, continuing",
                                &io_hdr, 1);
                /* fall through */
        case SG_LIB_CAT_CLEAN:
                break;
        default: /* won't bother decoding other categories */
                sg_chk_n_print3("READ BUFFER descriptor error", &io_hdr, 1);
                return res;
        }

        buf_capacity = ((rbBuff[1] << 16) | (rbBuff[2] << 8) | rbBuff[3]);
        buf_granul = (unsigned char)rbBuff[0];
#if 0
        printf("READ BUFFER reports: %02x %02x %02x %02x\n",
               rbBuff[0], rbBuff[1], rbBuff[2], rbBuff[3]);
#endif
        if (verbose)
                printf("READ BUFFER reports: buffer capacity=%d, offset "
                       "boundary=%d\n", buf_capacity, buf_granul);
        return 0;
}

int mymemcmp (unsigned char *bf1, unsigned char *bf2, int len)
{
        int df;
        for (df = 0; df < len; df++)
                if (bf1[df] != bf2[df]) return df;
        return 0;
}

/* return 0 if good, else 2222 */
int do_checksum (int *buf, int len, int quiet)
{
        int sum = base;
        int i; int rln = len;
        for (i = 0; i < len/BPI; i++)
                sum += buf[i];
        while (rln%BPI) sum += ((char*)buf)[--rln];
        if (sum != 0x12345678) {
                if (!quiet) printf ("sg_test_rwbuf: Checksum error (sz=%i):"
                                    " %08x\n", len, sum);
                if (cmpbuf && !quiet) {
                        int diff = mymemcmp (cmpbuf, (unsigned char*)buf,
                                             len);
                        printf ("Differ at pos %i/%i:\n", diff, len);
                        for (i = 0; i < 24 && i+diff < len; i++)
                                printf (" %02x", cmpbuf[i+diff]);
                        printf ("\n");
                        for (i = 0; i < 24 && i+diff < len; i++)
                                printf (" %02x",
                                        ((unsigned char*)buf)[i+diff]);
                        printf ("\n");
                }
                return 2222;
        }
        else {
                if (verbose > 1)
                        printf("Checksum value: 0x%x\n", sum);
                return 0;
        }
}

void do_fill_buffer (int *buf, int len)
{
        int sum;
        int i; int rln = len;
        srand (time (0));
    retry:
        if (len >= BPI)
                base = 0x12345678 + rand ();
        else
                base = 0x12345678 + (char) rand ();
        sum = base;
        for (i = 0; i < len/BPI - 1; i++)
        {
                /* we rely on rand() giving full range of int */
                buf[i] = rand ();
                sum += buf[i];
        }
        while (rln%BPI)
        {
                ((char*)buf)[--rln] = rand ();
                sum += ((char*)buf)[rln];
        }
        if (len >= BPI) buf[len/BPI - 1] = 0x12345678 - sum;
        else ((char*)buf)[0] = 0x12345678 + ((char*)buf)[0] - sum;
        if (do_checksum (buf, len, 1)) {
                if (len < BPI) goto retry;
                printf ("sg_test_rwbuf: Memory corruption?\n");
                exit (1);
        }
        if (cmpbuf) memcpy (cmpbuf, (char*)buf, len);
}


int read_buffer (int sg_fd, unsigned size)
{
        int res, k;
        unsigned char rbCmdBlk[] = {READ_BUFFER, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        int bufSize = size + addread;
        unsigned char * rbBuff = (unsigned char *)malloc(bufSize);
        unsigned char sense_buffer[32];
        struct sg_io_hdr io_hdr;

        if (NULL == rbBuff)
                return -1;
        rbCmdBlk[1] = RWB_MODE_DATA;
        rbCmdBlk[6] = 0xff & (bufSize >> 16);
        rbCmdBlk[7] = 0xff & (bufSize >> 8);
        rbCmdBlk[8] = 0xff & bufSize;
        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(rbCmdBlk);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
        io_hdr.dxfer_len = bufSize;
        io_hdr.dxferp = rbBuff;
        io_hdr.cmdp = rbCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.pack_id = 2;
        io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */
        if (verbose) {
                fprintf(stderr, "    read buffer [mode data] cdb: ");
                for (k = 0; k < (int)sizeof(rbCmdBlk); ++k)
                        fprintf(stderr, "%02x ", rbCmdBlk[k]);
                fprintf(stderr, "\n");
        }

        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
                perror(ME "SG_IO READ BUFFER data error");
                free(rbBuff);
                return -1;
        }
        /* now for the error processing */
        res = sg_err_category3(&io_hdr);
        switch (res) {
        case SG_LIB_CAT_RECOVERED:
            sg_chk_n_print3("READ BUFFER data, continuing", &io_hdr, 1);
            /* fall through */
        case SG_LIB_CAT_CLEAN:
                break;
        default: /* won't bother decoding other categories */
                sg_chk_n_print3("READ BUFFER data error", &io_hdr, 1);
                free(rbBuff);
                return res;
        }

        res = do_checksum ((int*)rbBuff, size, 0);
        free(rbBuff);
        return res;
}

int write_buffer (int sg_fd, unsigned size)
{
        unsigned char wbCmdBlk[] = {WRITE_BUFFER, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        int bufSize = size + addwrite;
        unsigned char * wbBuff = (unsigned char *)malloc(bufSize);
        unsigned char sense_buffer[32];
        struct sg_io_hdr io_hdr;
        int k, res;

        if (NULL == wbBuff)
                return -1;
        memset(wbBuff, 0, bufSize);
        do_fill_buffer ((int*)wbBuff, size);
        wbCmdBlk[1] = RWB_MODE_DATA;
        wbCmdBlk[6] = 0xff & (bufSize >> 16);
        wbCmdBlk[7] = 0xff & (bufSize >> 8);
        wbCmdBlk[8] = 0xff & bufSize;
        memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
        io_hdr.interface_id = 'S';
        io_hdr.cmd_len = sizeof(wbCmdBlk);
        io_hdr.mx_sb_len = sizeof(sense_buffer);
        io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
        io_hdr.dxfer_len = bufSize;
        io_hdr.dxferp = wbBuff;
        io_hdr.cmdp = wbCmdBlk;
        io_hdr.sbp = sense_buffer;
        io_hdr.pack_id = 1;
        io_hdr.timeout = 60000;     /* 60000 millisecs == 60 seconds */
        if (verbose) {
                fprintf(stderr, "    write buffer [mode data] cdb: ");
                for (k = 0; k < (int)sizeof(wbCmdBlk); ++k)
                        fprintf(stderr, "%02x ", wbCmdBlk[k]);
                fprintf(stderr, "\n");
        }

        if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
                perror(ME "SG_IO WRITE BUFFER data error");
                free(wbBuff);
                return -1;
        }
        /* now for the error processing */
        res = sg_err_category3(&io_hdr);
        switch (res) {
        case SG_LIB_CAT_RECOVERED:
            sg_chk_n_print3("WRITE BUFFER data, continuing", &io_hdr, 1);
            /* fall through */
        case SG_LIB_CAT_CLEAN:
                break;
        default: /* won't bother decoding other categories */
                sg_chk_n_print3("WRITE BUFFER data error", &io_hdr, 1);
                free(wbBuff);
                return res;
        }
        free(wbBuff);
        return res;
}

void usage ()
{
        printf ("Usage: sg_test_rwbuf [--addrd=AR] [--addwr=AW] [--help] "
                "[--quick]\n");
        printf ("                     --size=SZ [--times=NUM] [--verbose] "
                "[--version]\n"
                "                     DEVICE\n"
                " or\n"
                "       sg_test_rwbuf DEVICE SZ [AW] [AR]\n");
        printf ("  where:\n"
                "    --addrd=AR       extra bytes to fetch during READ "
                "BUFFER\n"
                "    --addwr=AW       extra bytes to send to WRITE BUFFER\n"
                "    --help           output this usage message then exit\n"
                "    --quick          output read buffer size then exit\n"
                "    --size=SZ        size of buffer (in bytes) to write "
                "then read back\n"
                "    --times=NUM      number of times to run test "
                "(default 1)\n"
                "    --verbose        increase verbosity of output\n"
                "    --version        output version then exit\n");
        printf ("\nWARNING: If you access the device at the same time, e.g. "
                "because it's a\n");
        printf (" mounted hard disk, the device's buffer may be used by the "
                "device itself\n");
        printf (" for other data at the same time, and overwriting it may or "
                "may not\n");
        printf (" cause data corruption!\n");
        printf ("(c) Douglas Gilbert, Kurt Garloff, 2000-2007, GNU GPL\n");
}


int main (int argc, char * argv[])
{
        int sg_fd, res;
        const char * device_name = NULL;
        int times = 1;
        int ret = 0;
        int k = 0;

        while (1) {
                int option_index = 0;
                int c;

                c = getopt_long(argc, argv, "hqr:s:t:w:vV",
                                long_options, &option_index);
                if (c == -1)
                        break;

                switch (c) {
                case 'h':
                        usage();
                        return 0;
                case 'q':
                        do_quick = 1;
                        break;
                case 'r':
                        addread = sg_get_num(optarg);
                        if (-1 == addread) {
                                fprintf(stderr, "bad argument to '--addrd'\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 's':
                        size = sg_get_num(optarg);
                        if (-1 == size) {
                                fprintf(stderr, "bad argument to '--size'\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 't':
                        times = sg_get_num(optarg);
                        if (-1 == times) {
                                fprintf(stderr, "bad argument to '--times'\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                case 'v':
                        verbose++;
                        break;
                case 'V':
                        fprintf(stderr, ME "version: %s\n",
                                version_str);
                        return 0;
                case 'w':
                        addwrite = sg_get_num(optarg);
                        if (-1 == addwrite) {
                                fprintf(stderr, "bad argument to '--addwr'\n");
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        break;
                default:
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
        }
        if (optind < argc) {
                if (NULL == device_name) {
                        device_name = argv[optind];
                        ++optind;
                }
        }
        if (optind < argc) {
                if (-1 == size) {
                        size = sg_get_num(argv[optind]);
                        if (-1 == size) {
                                fprintf(stderr, "bad <sz>\n");
                                usage();
                                return SG_LIB_SYNTAX_ERROR;
                        }
                        if (++optind < argc) {
                                addwrite = sg_get_num(argv[optind]);
                                if (-1 == addwrite) {
                                        fprintf(stderr, "bad [addwr]\n");
                                        usage();
                                        return SG_LIB_SYNTAX_ERROR;
                                }
                                if (++optind < argc) {
                                        addread = sg_get_num(argv[optind]);
                                        if (-1 == addread) {
                                                fprintf(stderr,
                                                        "bad [addrd]\n");
                                                usage();
                                                return SG_LIB_SYNTAX_ERROR;
                                        }
                                }
                        }

                }
                if (optind < argc) {
                        for (; optind < argc; ++optind)
                                fprintf(stderr, "Unexpected extra argument"
                                        ": %s\n", argv[optind]);
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                }
        }
        if (NULL == device_name) {
                fprintf(stderr, "no device name given\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }
        if ((size <= 0) && (! do_quick)) {
                fprintf(stderr, "must give '--size' or '--quick' options "
                        "or <sz> argument\n");
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }

        sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
        if (sg_fd < 0) {
                perror("sg_test_rwbuf: open error");
                return SG_LIB_FILE_ERROR;
        }
        ret = find_out_about_buffer(sg_fd);
        if (ret)
                goto err_out;
        if (do_quick) {
                printf ("READ BUFFER read descriptor reports a buffer "
                        "of %d bytes [%d KiB]\n", buf_capacity,
                        buf_capacity / 1024);
                goto err_out;
        }
        if (size > buf_capacity) {
                fprintf (stderr, ME "sz=%i > buf_capacity=%i\n",
                        size, buf_capacity);
                ret = SG_LIB_CAT_OTHER;
                goto err_out;
        }

        cmpbuf = (unsigned char *)malloc(size);
        for (k = 0; k < times; ++k) {
                ret = write_buffer (sg_fd, size);
                if (ret) {
                        goto err_out;
                }
                ret = read_buffer (sg_fd, size);
                if (ret) {
                        if (2222 == ret)
                                ret = SG_LIB_CAT_MALFORMED;
                        goto err_out;
                }
        }

err_out:
        if (cmpbuf)
                free(cmpbuf);
        res = close(sg_fd);
        if (res < 0) {
                perror(ME "close error");
                if (0 == ret)
                        ret = SG_LIB_FILE_ERROR;
        }
        if ((0 == ret) && (! do_quick))
                printf ("Success\n");
        else if (times > 1)
                printf ("Failed after %d successful cycles\n", k);
        return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

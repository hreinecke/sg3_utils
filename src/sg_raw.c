/*
 * A utility program originally written for the Linux OS SCSI subsystem.
 *
 * Copyright (C) 2000-2016 Ingo van Lil <inguin@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program can be used to send raw SCSI commands (with an optional
 * data phase) through a Generic SCSI interface.
 */

#define _XOPEN_SOURCE 600       /* clear up posix_memalign() warning */

#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_pr2serr.h"
#include "sg_unaligned.h"

#define SG_RAW_VERSION "0.4.17 (2016-04-23)"

#ifdef SG_LIB_WIN32
#ifndef HAVE_SYSCONF
#include <windows.h>

static size_t
win_pagesize(void)
{
    SYSTEM_INFO sys_info;

    GetSystemInfo(&sys_info);
    return sys_info.dwPageSize;
}
#endif
#endif

#define DEFAULT_TIMEOUT 20
#define MIN_SCSI_CDBSZ 6
#define MAX_SCSI_CDBSZ 256
#define MAX_SCSI_DXLEN (64 * 1024)

static struct option long_options[] = {
    { "binary",  no_argument,       NULL, 'b' },
    { "enumerate", no_argument,     NULL, 'e' },
    { "help",    no_argument,       NULL, 'h' },
    { "infile",  required_argument, NULL, 'i' },
    { "skip",    required_argument, NULL, 'k' },
    { "nosense", no_argument,       NULL, 'n' },
    { "outfile", required_argument, NULL, 'o' },
    { "request", required_argument, NULL, 'r' },
    { "readonly", no_argument,      NULL, 'R' },
    { "send",    required_argument, NULL, 's' },
    { "timeout", required_argument, NULL, 't' },
    { "verbose", no_argument,       NULL, 'v' },
    { "version", no_argument,       NULL, 'V' },
    { 0, 0, 0, 0 }
};

struct opts_t {
    char *device_name;
    unsigned char cdb[MAX_SCSI_CDBSZ];
    int cdb_length;
    bool do_datain;
    int datain_len;
    const char *datain_file;
    bool datain_binary;
    bool do_dataout;
    int dataout_len;
    const char *dataout_file;
    off_t dataout_offset;
    bool do_enumerate;
    int timeout;
    bool no_sense;
    int readonly;
    bool do_help;
    int verbose;
    bool do_version;
};


static void
version()
{
    pr2serr("sg_raw " SG_RAW_VERSION "\n"
            "Copyright (C) 2007-2012 Ingo van Lil <inguin@gmx.de>\n"
            "This is free software.  You may redistribute copies of it "
            "under the terms of\n"
            "the GNU General Public License "
            "<http://www.gnu.org/licenses/gpl.html>.\n"
            "There is NO WARRANTY, to the extent permitted by law.\n");
}

static void
usage()
{
    pr2serr("Usage: sg_raw [OPTION]* DEVICE CDB0 CDB1 ...\n"
            "\n"
            "Options:\n"
            "  --binary|-b            Dump data in binary form, even when "
            "writing to\n"
            "                         stdout\n"
            "  --enumerate|-e         Decodes cdb name then exits; requires "
            "DEVICE but\n"
            "                         ignores it\n"
            "  --help|-h              Show this message and exit\n"
            "  --infile=IFILE|-i IFILE    Read data to send from IFILE "
            "(default:\n"
            "                             stdin)\n"
            "  --nosense|-n           Don't display sense information\n"
            "  --outfile=OFILE|-o OFILE    Write binary data to OFILE (def: "
            "hexdump\n"
            "                              to stdout)\n"
            "  --readonly|-R          Open DEVICE read-only (default: "
            "read-write)\n"
            "  --request=RLEN|-r RLEN    Request up to RLEN bytes of data "
            "(data-in)\n"
            "  --send=SLEN|-s SLEN    Send SLEN bytes of data (data-out)\n"
            "  --skip=KLEN|-k KLEN    Skip the first KLEN bytes when "
            "reading\n"
            "                         data to send (default: 0)\n"
            "  --timeout=SEC|-t SEC    Timeout in seconds (default: 20)\n"
            "  --verbose|-v           Increase verbosity\n"
            "  --version|-V           Show version information and exit\n"
            "\n"
            "Between 6 and 256 command bytes (two hex digits each) can be "
            "specified\nand will be sent to DEVICE. Lengths RLEN and SLEN "
            "are decimal by\ndefault. Bidirectional commands accepted.\n\n"
            "Simple example: Perform INQUIRY on /dev/sg0:\n"
            "  sg_raw -r 1k /dev/sg0 12 00 00 00 60 00\n");
}

static int
process_cl(struct opts_t * op, int argc, char *argv[])
{
    while (1) {
        int c, n;

        c = getopt_long(argc, argv, "behi:k:no:r:Rs:t:vV", long_options, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            op->datain_binary = true;
            break;
        case 'e':
            op->do_enumerate = true;
            break;
        case 'h':
        case '?':
            op->do_help = true;
            return 0;
        case 'i':
            if (op->dataout_file) {
                pr2serr("Too many '--infile=' options\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->dataout_file = optarg;
            break;
        case 'k':
            n = sg_get_num(optarg);
            if (n < 0) {
                pr2serr("Invalid argument to '--skip'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->dataout_offset = n;
            break;
        case 'n':
            op->no_sense = true;
            break;
        case 'o':
            if (op->datain_file) {
                pr2serr("Too many '--outfile=' options\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->datain_file = optarg;
            break;
        case 'r':
            op->do_datain = true;
            n = sg_get_num(optarg);
            if (n < 0 || n > MAX_SCSI_DXLEN) {
                pr2serr("Invalid argument to '--request'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->datain_len = n;
            break;
        case 'R':
            ++op->readonly;
            break;
        case 's':
            op->do_dataout = true;
            n = sg_get_num(optarg);
            if (n < 0 || n > MAX_SCSI_DXLEN) {
                pr2serr("Invalid argument to '--send'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->dataout_len = n;
            break;
        case 't':
            n = sg_get_num(optarg);
            if (n < 0) {
                pr2serr("Invalid argument to '--timeout'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->timeout = n;
            break;
        case 'v':
            ++op->verbose;
            break;
        case 'V':
            op->do_version = true;
            return 0;
        default:
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (optind >= argc) {
        pr2serr("No device specified\n");
        return SG_LIB_SYNTAX_ERROR;
    }
    op->device_name = argv[optind];
    ++optind;

    while (optind < argc) {
        char *opt = argv[optind++];
        char *endptr;
        int cmd = strtol(opt, &endptr, 16);
        if (*opt == '\0' || *endptr != '\0' || cmd < 0x00 || cmd > 0xff) {
            pr2serr("Invalid command byte '%s'\n", opt);
            return SG_LIB_SYNTAX_ERROR;
        }

        if (op->cdb_length > MAX_SCSI_CDBSZ) {
            pr2serr("CDB too long (max. %d bytes)\n", MAX_SCSI_CDBSZ);
            return SG_LIB_SYNTAX_ERROR;
        }
        op->cdb[op->cdb_length] = cmd;
        ++op->cdb_length;
    }

    if (op->cdb_length < MIN_SCSI_CDBSZ) {
        pr2serr("CDB too short (min. %d bytes)\n", MIN_SCSI_CDBSZ);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->do_enumerate || (op->verbose > 1)) {
        int sa;
        char b[80];

        if (op->cdb_length > 16) {
            sa = sg_get_unaligned_be16(op->cdb + 8);
            if ((0x7f != op->cdb[0]) && (0x7e != op->cdb[0]))
                printf(">>> Unlikely to be SCSI CDB since all over 16 "
                       "bytes long should\n>>> start with 0x7f or 0x7e\n");
        } else
            sa = op->cdb[1] & 0x1f;
        sg_get_opcode_sa_name(op->cdb[0], sa, 0, sizeof(b), b);
        printf("Attempt to decode cdb name: %s\n", b);
    }
    return 0;
}

/* Allocate aligned memory (heap) starting on page boundary */
static unsigned char *
my_memalign(int length, unsigned char ** wrkBuffp, const struct opts_t * op)
{
    size_t psz;
    unsigned char * res;

#if defined(HAVE_SYSCONF) && defined(_SC_PAGESIZE)
    psz = sysconf(_SC_PAGESIZE); /* POSIX.1 (was getpagesize()) */
#elif defined(SG_LIB_WIN32)
    psz = win_pagesize();
#else
    psz = 4096;     /* give up, pick likely figure */
#endif

#ifdef HAVE_POSIX_MEMALIGN
    {
        int err;
        void * wp = NULL;

        err = posix_memalign(&wp, psz, length);
        if (err || (NULL == wp)) {
            pr2serr("posix_memalign: error [%d], out of memory?\n", err);
            return NULL;
        }
        memset(wp, 0, length);
        if (wrkBuffp)
            *wrkBuffp = (unsigned char *)wp;
        res = (unsigned char *)wp;
        if (op->verbose > 3)
            pr2serr("%s: posix, len=%d, wrkBuffp=%p, psz=%d, rp=%p\n",
                    __func__, length, (void *)*wrkBuffp, (int)psz,
                    (void *)res);
        return res;
    }
#else
    {
        unsigned char * wrkBuff;

        wrkBuff = (unsigned char*)calloc(length + psz, 1);
        if (NULL == wrkBuff) {
            if (wrkBuffp)
                *wrkBuffp = NULL;
            return NULL;
        } else if (wrkBuffp)
            *wrkBuffp = wrkBuff;
        res = (unsigned char *)(((uintptr_t)wrkBuff + psz - 1) &
                                (~(psz - 1)));
        if (op->verbose > 3)
            pr2serr("%s: hack, len=%d, wrkBuffp=%p, psz=%d, rp=%p\n",
                    __func__, length, (void *)*wrkBuffp, (int)psz,
                    (void *)res);
        return res;
    }
#endif
}

static int
skip(int fd, off_t offset)
{
    off_t remain;
    char buffer[512];

    if (lseek(fd, offset, SEEK_SET) >= 0) {
        return 0;
    }

    // lseek failed; fall back to reading and discarding data
    remain = offset;
    while (remain > 0) {
        ssize_t amount, done;
        amount = (remain < (off_t)sizeof(buffer)) ? remain
                                         : (off_t)sizeof(buffer);
        done = read(fd, buffer, amount);
        if (done < 0) {
            perror("Error reading input data");
            return SG_LIB_FILE_ERROR;
        } else if (done == 0) {
            pr2serr("EOF on input file/stream\n");
            return SG_LIB_FILE_ERROR;
        } else {
            remain -= done;
        }
    }

    return 0;
}

static unsigned char *
fetch_dataout(struct opts_t * op)
{
    unsigned char *buf = NULL;
    unsigned char *wrkBuf = NULL;
    int fd, len;
    int ok = 0;

    if (op->dataout_file) {
        fd = open(op->dataout_file, O_RDONLY);
        if (fd < 0) {
            perror(op->dataout_file);
            goto bail;
        }

    } else {
        fd = STDIN_FILENO;
    }
    if (sg_set_binary_mode(fd) < 0) {
        perror("sg_set_binary_mode");
        goto bail;
    }

    if (op->dataout_offset > 0) {
        if (skip(fd, op->dataout_offset) != 0) {
            goto bail;
        }
    }

    buf = my_memalign(op->dataout_len, &wrkBuf, op);
    if (buf == NULL) {
        perror("malloc");
        goto bail;
    }

    len = read(fd, buf, op->dataout_len);
    if (len < 0) {
        perror("Failed to read input data");
        goto bail;
    } else if (len < op->dataout_len) {
        pr2serr("EOF on input file/stream\n");
        goto bail;
    }

    ok = 1;

bail:
    if (fd >= 0 && fd != STDIN_FILENO)
        close(fd);
    if (!ok) {
        if (wrkBuf)
            free(wrkBuf);
        return NULL;
    }
    return buf;
}

static int
write_dataout(const char *filename, unsigned char *buf, int len)
{
    int ret = SG_LIB_FILE_ERROR;
    int fd;

    if ((filename == NULL) ||
        ((1 == strlen(filename)) && ('-' == filename[0])))
        fd = STDOUT_FILENO;
    else {
        fd = creat(filename, 0666);
        if (fd < 0) {
            perror(filename);
            goto bail;
        }
    }
    if (sg_set_binary_mode(fd) < 0) {
        perror("sg_set_binary_mode");
        goto bail;
    }

    if (write(fd, buf, len) != len) {
        perror(filename ? filename : "stdout");
        goto bail;
    }

    ret = 0;

bail:
    if (fd >= 0 && fd != STDOUT_FILENO)
        close(fd);
    return ret;
}

int
main(int argc, char *argv[])
{
    int ret = 0;
    int res_cat, status, slen, k, ret2;
    int sg_fd = -1;
    struct sg_pt_base *ptvp = NULL;
    unsigned char sense_buffer[32];
    unsigned char * dxfer_buffer_in = NULL;
    unsigned char * dxfer_buffer_out = NULL;
    unsigned char * wrkBuf = NULL;
    struct opts_t opts;
    struct opts_t * op;
    char b[128];

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->timeout = DEFAULT_TIMEOUT;
    ret = process_cl(op, argc, argv);
    if (ret != 0) {
        usage();
        goto done;
    } else if (op->do_help) {
        usage();
        goto done;
    } else if (op->do_version) {
        version();
        goto done;
    } else if (op->do_enumerate)
        goto done;

    sg_fd = scsi_pt_open_device(op->device_name, op->readonly,
                                op->verbose);
    if (sg_fd < 0) {
        pr2serr("%s: %s\n", op->device_name, safe_strerror(-sg_fd));
        ret = SG_LIB_FILE_ERROR;
        goto done;
    }

    ptvp = construct_scsi_pt_obj();
    if (ptvp == NULL) {
        pr2serr("out of memory\n");
        ret = SG_LIB_CAT_OTHER;
        goto done;
    }
    if (op->verbose) {
        pr2serr("    cdb to send: ");
        for (k = 0; k < op->cdb_length; ++k)
            pr2serr("%02x ", op->cdb[k]);
        pr2serr("\n");
        if (op->verbose > 1) {
            sg_get_command_name(op->cdb, 0, sizeof(b) - 1, b);
            b[sizeof(b) - 1] = '\0';
            pr2serr("    Command name: %s\n", b);
        }
    }
    set_scsi_pt_cdb(ptvp, op->cdb, op->cdb_length);
    if (op->verbose > 2)
        pr2serr("sense_buffer=%p, length=%d\n", (void *)sense_buffer,
                (int)sizeof(sense_buffer));
    set_scsi_pt_sense(ptvp, sense_buffer, sizeof(sense_buffer));

    if (op->do_dataout) {
        dxfer_buffer_out = fetch_dataout(op);
        if (dxfer_buffer_out == NULL) {
            ret = SG_LIB_CAT_OTHER;
            goto done;
        }
        if (op->verbose > 2)
            pr2serr("dxfer_buffer_out=%p, length=%d\n",
                    (void *)dxfer_buffer_out, op->dataout_len);
        set_scsi_pt_data_out(ptvp, dxfer_buffer_out, op->dataout_len);
    }
    if (op->do_datain) {
        dxfer_buffer_in = my_memalign(op->datain_len, &wrkBuf, op);
        if (dxfer_buffer_in == NULL) {
            perror("malloc");
            ret = SG_LIB_CAT_OTHER;
            goto done;
        }
        if (op->verbose > 2)
            pr2serr("dxfer_buffer_in=%p, length=%d\n",
                    (void *)dxfer_buffer_in, op->datain_len);
        set_scsi_pt_data_in(ptvp, dxfer_buffer_in, op->datain_len);
    }

    ret = do_scsi_pt(ptvp, sg_fd, op->timeout, op->verbose);
    if (ret > 0) {
        if (SCSI_PT_DO_BAD_PARAMS == ret) {
            pr2serr("do_scsi_pt: bad pass through setup\n");
            ret = SG_LIB_CAT_OTHER;
        } else if (SCSI_PT_DO_TIMEOUT == ret) {
            pr2serr("do_scsi_pt: timeout\n");
            ret = SG_LIB_CAT_TIMEOUT;
        } else
            ret = SG_LIB_CAT_OTHER;
        goto done;
    } else if (ret < 0) {
        pr2serr("do_scsi_pt: %s\n", safe_strerror(-ret));
        ret = SG_LIB_CAT_OTHER;
        goto done;
    }

    slen = 0;
    res_cat = get_scsi_pt_result_category(ptvp);
    switch (res_cat) {
    case SCSI_PT_RESULT_GOOD:
        ret = 0;
        break;
    case SCSI_PT_RESULT_SENSE:
        slen = get_scsi_pt_sense_len(ptvp);
        ret = sg_err_category_sense(sense_buffer, slen);
        break;
    case SCSI_PT_RESULT_TRANSPORT_ERR:
        get_scsi_pt_transport_err_str(ptvp, sizeof(b), b);
        pr2serr(">>> transport error: %s\n", b);
        ret = SG_LIB_CAT_OTHER;
        break;
    case SCSI_PT_RESULT_OS_ERR:
        get_scsi_pt_os_err_str(ptvp, sizeof(b), b);
        pr2serr(">>> os error: %s\n", b);
        ret = SG_LIB_CAT_OTHER;
        break;
    default:
        pr2serr(">>> unknown pass through result category (%d)\n", res_cat);
        ret = SG_LIB_CAT_OTHER;
        break;
    }

    status = get_scsi_pt_status_response(ptvp);
    pr2serr("SCSI Status: ");
    sg_print_scsi_status(status);
    pr2serr("\n\n");
    if ((SAM_STAT_CHECK_CONDITION == status) && (! op->no_sense)) {
        if (SCSI_PT_RESULT_SENSE != res_cat)
            slen = get_scsi_pt_sense_len(ptvp);
        if (0 == slen)
            pr2serr(">>> Strange: status is CHECK CONDITION but no Sense "
                    "Information\n");
        else {
            pr2serr("Sense Information:\n");
            sg_print_sense(NULL, sense_buffer, slen, (op->verbose > 0));
            pr2serr("\n");
        }
    }
    if (SAM_STAT_RESERVATION_CONFLICT == status)
        ret = SG_LIB_CAT_RES_CONFLICT;

    if (op->do_datain) {
        int data_len = op->datain_len - get_scsi_pt_resid(ptvp);

        if (ret && !(SG_LIB_CAT_RECOVERED == ret ||
                     SG_LIB_CAT_NO_SENSE == ret))
            pr2serr("Error %d occurred, no data received\n", ret);
        else if (data_len == 0) {
            pr2serr("No data received\n");
        } else {
            if (op->datain_file == NULL && !op->datain_binary) {
                pr2serr("Received %d bytes of data:\n", data_len);
                dStrHexErr((const char *)dxfer_buffer_in, data_len, 0);
            } else {
                const char * cp = "stdout";

                if (op->datain_file &&
                    ! ((1 == strlen(op->datain_file)) &&
                       ('-' == op->datain_file[0])))
                    cp = op->datain_file;
                pr2serr("Writing %d bytes of data to %s\n", data_len, cp);
                ret2 = write_dataout(op->datain_file, dxfer_buffer_in,
                                     data_len);
                if (0 != ret2) {
                    if (0 == ret)
                        ret = ret2;
                    goto done;
                }
            }
        }
    }

done:
    if (op->verbose) {
        sg_get_category_sense_str(ret, sizeof(b), b, op->verbose - 1);
        pr2serr("%s\n", b);
    }
    if (wrkBuf)
        free(wrkBuf);
    if (ptvp)
        destruct_scsi_pt_obj(ptvp);
    if (sg_fd >= 0)
        scsi_pt_close_device(sg_fd);
    return ret;
}

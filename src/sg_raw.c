/*
 * A utility program originally written for the Linux OS SCSI subsystem.
 *
 * Copyright (C) 2000-2019 Ingo van Lil <inguin@gmx.de>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program can be used to send raw SCSI commands (with an optional
 * data phase) through a Generic SCSI interface.
 */

#define _XOPEN_SOURCE 600       /* clear up posix_memalign() warning */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <ctype.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <getopt.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_pt_nvme.h"
#include "sg_pr2serr.h"
#include "sg_unaligned.h"

#define SG_RAW_VERSION "0.4.32 (2019-12-26)"

#define DEFAULT_TIMEOUT 20
#define MIN_SCSI_CDBSZ 6
#define MAX_SCSI_CDBSZ 260
#define MAX_SCSI_DXLEN (64 * 1024)

#define NVME_ADDR_DATA_IN  0xfffffffffffffffe
#define NVME_ADDR_DATA_OUT 0xfffffffffffffffd
#define NVME_DATA_LEN_DATA_IN  0xfffffffe
#define NVME_DATA_LEN_DATA_OUT 0xfffffffd

static struct option long_options[] = {
    { "binary",  no_argument,       NULL, 'b' },
    { "cmdfile", required_argument, NULL, 'c' },
    { "enumerate", no_argument,     NULL, 'e' },
    { "help",    no_argument,       NULL, 'h' },
    { "infile",  required_argument, NULL, 'i' },
    { "skip",    required_argument, NULL, 'k' },
    { "nosense", no_argument,       NULL, 'n' },
    { "outfile", required_argument, NULL, 'o' },
    { "raw",     no_argument,       NULL, 'w' },
    { "request", required_argument, NULL, 'r' },
    { "readonly", no_argument,      NULL, 'R' },
    { "send",    required_argument, NULL, 's' },
    { "timeout", required_argument, NULL, 't' },
    { "verbose", no_argument,       NULL, 'v' },
    { "version", no_argument,       NULL, 'V' },
    { 0, 0, 0, 0 }
};

struct opts_t {
    bool cmdfile_given;
    bool do_datain;
    bool datain_binary;
    bool do_dataout;
    bool do_enumerate;
    bool no_sense;
    bool do_help;
    bool verbose_given;
    bool version_given;
    int cdb_length;
    int datain_len;
    int dataout_len;
    int timeout;
    int raw;
    int readonly;
    int verbose;
    off_t dataout_offset;
    uint8_t cdb[MAX_SCSI_CDBSZ];        /* might be NVMe command (64 byte) */
    const char *cmd_file;
    const char *datain_file;
    const char *dataout_file;
    char *device_name;
};


static void
pr_version()
{
    pr2serr("sg_raw " SG_RAW_VERSION "\n"
            "Copyright (C) 2007-2018 Ingo van Lil <inguin@gmx.de>\n"
            "This is free software.  You may redistribute copies of it "
            "under the terms of\n"
            "the GNU General Public License "
            "<http://www.gnu.org/licenses/gpl.html>.\n"
            "There is NO WARRANTY, to the extent permitted by law.\n");
}

static void
usage()
{
    pr2serr("Usage: sg_raw [OPTION]* DEVICE [CDB0 CDB1 ...]\n"
            "\n"
            "Options:\n"
            "  --binary|-b            Dump data in binary form, even when "
            "writing to\n"
            "                         stdout\n"
            "  --cmdfile=CF|-c CF     CF is file containing command in hex "
            "bytes\n"
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
            "  --raw|-w               interpret CF (command file) as "
            "binary (def:\n"
            "                         interpret as ASCII hex)\n"
            "  --readonly|-R          Open DEVICE read-only (default: "
            "read-write)\n"
            "  --request=RLEN|-r RLEN    Request up to RLEN bytes of data "
            "(data-in)\n"
            "  --send=SLEN|-s SLEN    Send SLEN bytes of data (data-out)\n"
            "  --skip=KLEN|-k KLEN    Skip the first KLEN bytes when "
            "reading\n"
            "                         data to send (default: 0)\n"
            "  --timeout=SECS|-t SECS    Timeout in seconds (default: 20)\n"
            "  --verbose|-v           Increase verbosity\n"
            "  --version|-V           Show version information and exit\n"
            "\n"
            "Between 6 and 260 command bytes (two hex digits each) can be "
            "specified\nand will be sent to DEVICE. Lengths RLEN, SLEN and "
            "KLEN are decimal by\ndefault. Bidirectional commands "
            "accepted.\n\nSimple example: Perform INQUIRY on /dev/sg0:\n"
            "  sg_raw -r 1k /dev/sg0 12 00 00 00 60 00\n");
}

static int
parse_cmd_line(struct opts_t * op, int argc, char *argv[])
{
    while (1) {
        int c, n;

        c = getopt_long(argc, argv, "bc:ehi:k:no:r:Rs:t:vVw", long_options,
                        NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            op->datain_binary = true;
            break;
        case 'c':
            op->cmd_file = optarg;
            op->cmdfile_given = true;
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
                return SG_LIB_CONTRADICT;
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
                return SG_LIB_CONTRADICT;
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
            op->verbose_given = true;
            ++op->verbose;
            break;
        case 'V':
            op->version_given = true;
            break;
        case 'w':       /* -r and -R already in use, this is --raw */
            ++op->raw;
            break;
        default:
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (optind >= argc) {
        pr2serr("No device specified\n\n");
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

    if (op->cmdfile_given) {
        bool ok;

        ok = sg_f2hex_arr(op->cmd_file, (op->raw > 0) /* as_binary */,
                          false /* no_space */, op->cdb, &op->cdb_length,
                          MAX_SCSI_CDBSZ);
        if (! ok)
            return SG_LIB_SYNTAX_ERROR;
        if (op->verbose > 2) {
            pr2serr("Read %d from %s . They are in hex:\n", op->cdb_length,
                    op->cmd_file);
            hex2stderr(op->cdb, op->cdb_length, -1);
        }
    }
    if (op->cdb_length < MIN_SCSI_CDBSZ) {
        pr2serr("CDB too short (min. %d bytes)\n", MIN_SCSI_CDBSZ);
        return SG_LIB_SYNTAX_ERROR;
    }
    if (op->do_enumerate || (op->verbose > 1)) {
        bool is_scsi_cdb = sg_is_scsi_cdb(op->cdb, op->cdb_length);
        int sa;
        char b[80];

        if (is_scsi_cdb) {
            if (op->cdb_length > 16) {
                sa = sg_get_unaligned_be16(op->cdb + 8);
                if ((0x7f != op->cdb[0]) && (0x7e != op->cdb[0]))
                    printf(">>> Unlikely to be SCSI CDB since all over 16 "
                           "bytes long should\n>>> start with 0x7f or "
                           "0x7e\n");
            } else
                sa = op->cdb[1] & 0x1f;
            sg_get_opcode_sa_name(op->cdb[0], sa, 0, sizeof(b), b);
            printf("Attempt to decode cdb name: %s\n", b);
        } else
            printf(">>> Seems to be NVMe %s command\n",
                   sg_get_nvme_opcode_name(op->cdb[0], true /* admin */,
                                           sizeof(b), b));
    }
    return 0;
}

static int
skip(int fd, off_t offset)
{
    int err;
    off_t remain;
    char buffer[512];

    if (lseek(fd, offset, SEEK_SET) >= 0)
        return 0;

    // lseek failed; fall back to reading and discarding data
    remain = offset;
    while (remain > 0) {
        ssize_t amount, done;
        amount = (remain < (off_t)sizeof(buffer)) ? remain
                                         : (off_t)sizeof(buffer);
        done = read(fd, buffer, amount);
        if (done < 0) {
            err = errno;
            perror("Error reading input data to skip");
            return sg_convert_errno(err);
        } else if (done == 0) {
            pr2serr("EOF on input file/stream\n");
            return SG_LIB_FILE_ERROR;
        } else
            remain -= done;
    }
    return 0;
}

static uint8_t *
fetch_dataout(struct opts_t * op, uint8_t ** free_buf, int * errp)
{
    bool ok = false;
    int fd, len, tot_len, boff, err;
    uint8_t *buf = NULL;

    *free_buf = NULL;
    if (errp)
        *errp = 0;
    if (op->dataout_file) {
        fd = open(op->dataout_file, O_RDONLY);
        if (fd < 0) {
            err = errno;
            if (errp)
                *errp = sg_convert_errno(err);
            perror(op->dataout_file);
            goto bail;
        }
    } else
        fd = STDIN_FILENO;
    if (sg_set_binary_mode(fd) < 0) {
        err = errno;
        if (errp)
            *errp = err;
        perror("sg_set_binary_mode");
        goto bail;
    }

    if (op->dataout_offset > 0) {
        err = skip(fd, op->dataout_offset);
        if (err != 0) {
            if (errp)
                *errp = err;
            goto bail;
        }
    }

    tot_len = op->dataout_len;
    buf = sg_memalign(tot_len, 0 /* page_size */, free_buf, false);
    if (buf == NULL) {
        pr2serr("sg_memalign: failed to get %d bytes of memory\n", tot_len);
        if (errp)
            *errp = sg_convert_errno(ENOMEM);
        goto bail;
    }

    for (boff = 0; boff < tot_len; boff += len) {
        len = read(fd, buf + boff , tot_len - boff);
        if (len < 0) {
            err = errno;
            if (errp)
                *errp = sg_convert_errno(err);
            perror("Failed to read input data");
            goto bail;
        } else if (0 == len) {
            if (errp)
                *errp = SG_LIB_FILE_ERROR;
            pr2serr("EOF on input file/stream at buffer offset %d\n", boff);
            goto bail;
        }
    }
    ok = true;

bail:
    if (fd >= 0 && fd != STDIN_FILENO)
        close(fd);
    if (! ok) {
        if (*free_buf) {
            free(*free_buf);
            *free_buf = NULL;
        }
        return NULL;
    }
    return buf;
}

static int
write_dataout(const char *filename, uint8_t *buf, int len)
{
    int ret = SG_LIB_FILE_ERROR;
    int fd;

    if ((filename == NULL) ||
        ((1 == strlen(filename)) && ('-' == filename[0])))
        fd = STDOUT_FILENO;
    else {
        fd = creat(filename, 0666);
        if (fd < 0) {
            ret = sg_convert_errno(errno);
            perror(filename);
            goto bail;
        }
    }
    if (sg_set_binary_mode(fd) < 0) {
        perror("sg_set_binary_mode");
        goto bail;
    }

    if (write(fd, buf, len) != len) {
        ret = sg_convert_errno(errno);
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
    bool is_scsi_cdb = true;
    int ret = 0;
    int err = 0;
    int res_cat, status, s_len, k, ret2;
    int sg_fd = -1;
    uint16_t sct_sc;
    uint32_t result;
    struct sg_pt_base *ptvp = NULL;
    uint8_t sense_buffer[32];
    uint8_t * dinp = NULL;
    uint8_t * doutp = NULL;
    uint8_t * free_buf_out = NULL;
    uint8_t * wrkBuf = NULL;
    struct opts_t opts;
    struct opts_t * op;
    char b[128];
    const int b_len = sizeof(b);

    op = &opts;
    memset(op, 0, sizeof(opts));
    op->timeout = DEFAULT_TIMEOUT;
    ret = parse_cmd_line(op, argc, argv);
#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (op->verbose_given && op->version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        op->verbose_given = false;
        op->version_given = false;
        op->verbose = 0;
    } else if (! op->verbose_given) {
        pr2serr("set '-vv'\n");
        op->verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", op->verbose);
#else
    if (op->verbose_given && op->version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (op->version_given) {
        pr_version();
        goto done;
    }

    if (ret != 0) {
        usage();
        goto done;
    } else if (op->do_help) {
        usage();
        goto done;
    } else if (op->do_enumerate)
        goto done;

    sg_fd = scsi_pt_open_device(op->device_name, op->readonly,
                                op->verbose);
    if (sg_fd < 0) {
        pr2serr("%s: %s\n", op->device_name, safe_strerror(-sg_fd));
        ret = sg_convert_errno(-sg_fd);
        goto done;
    }

    ptvp = construct_scsi_pt_obj();
    if (ptvp == NULL) {
        pr2serr("out of memory\n");
        ret = SG_LIB_CAT_OTHER;
        goto done;
    }

    is_scsi_cdb = sg_is_scsi_cdb(op->cdb, op->cdb_length);
    if (op->do_dataout) {
        uint32_t dout_len;

        doutp = fetch_dataout(op, &free_buf_out, &err);
        if (doutp == NULL) {
            ret = err;
            goto done;
        }
        dout_len = op->dataout_len;
        if (op->verbose > 2)
            pr2serr("dxfer_buffer_out=%p, length=%d\n",
                    (void *)doutp, dout_len);
        set_scsi_pt_data_out(ptvp, doutp, dout_len);
        if (op->cmdfile_given) {
            if (NVME_ADDR_DATA_OUT ==
                sg_get_unaligned_le64(op->cdb + SG_NVME_PT_ADDR))
                sg_put_unaligned_le64((uint64_t)(sg_uintptr_t)doutp,
                                      op->cdb + SG_NVME_PT_ADDR);
            if (NVME_DATA_LEN_DATA_OUT ==
                sg_get_unaligned_le32(op->cdb + SG_NVME_PT_DATA_LEN))
                sg_put_unaligned_le32(dout_len,
                                      op->cdb + SG_NVME_PT_DATA_LEN);
        }
    }
    if (op->do_datain) {
        uint32_t din_len = op->datain_len;

        dinp = sg_memalign(din_len, 0 /* page_size */, &wrkBuf, false);
        if (dinp == NULL) {
            pr2serr("sg_memalign: failed to get %d bytes of memory\n",
                    din_len);
            ret = sg_convert_errno(ENOMEM);
            goto done;
        }
        if (op->verbose > 2)
            pr2serr("dxfer_buffer_in=%p, length=%d\n", (void *)dinp, din_len);
        set_scsi_pt_data_in(ptvp, dinp, din_len);
        if (op->cmdfile_given) {
            if (NVME_ADDR_DATA_IN ==
                sg_get_unaligned_le64(op->cdb + SG_NVME_PT_ADDR))
                sg_put_unaligned_le64((uint64_t)(sg_uintptr_t)dinp,
                                      op->cdb + SG_NVME_PT_ADDR);
            if (NVME_DATA_LEN_DATA_IN ==
                sg_get_unaligned_le32(op->cdb + SG_NVME_PT_DATA_LEN))
                sg_put_unaligned_le32(din_len,
                                      op->cdb + SG_NVME_PT_DATA_LEN);
        }
    }
    if (op->verbose) {
        char d[128];

        pr2serr("    %s to send: ", is_scsi_cdb ? "cdb" : "cmd");
        if (is_scsi_cdb) {
            pr2serr("%s\n", sg_get_command_str(op->cdb, op->cdb_length,
                                               op->verbose > 1,
                                               sizeof(d), d));
        } else {        /* If not SCSI cdb then treat as NVMe command */
            pr2serr("\n");
            hex2stderr(op->cdb, op->cdb_length, -1);
            if (op->verbose > 1)
                pr2serr("  Command name: %s\n",
                        sg_get_nvme_opcode_name(op->cdb[0], true /* admin */,
                                                b_len, b));
        }
    }
    set_scsi_pt_cdb(ptvp, op->cdb, op->cdb_length);
    if (op->verbose > 2)
        pr2serr("sense_buffer=%p, length=%d\n", (void *)sense_buffer,
                (int)sizeof(sense_buffer));
    set_scsi_pt_sense(ptvp, sense_buffer, sizeof(sense_buffer));

    ret = do_scsi_pt(ptvp, sg_fd, op->timeout, op->verbose);
    if (ret > 0) {
        switch (ret) {
        case SCSI_PT_DO_BAD_PARAMS:
            pr2serr("do_scsi_pt: bad pass through setup\n");
            ret = SG_LIB_CAT_OTHER;
            break;
        case SCSI_PT_DO_TIMEOUT:
            pr2serr("do_scsi_pt: timeout\n");
            ret = SG_LIB_CAT_TIMEOUT;
            break;
        case SCSI_PT_DO_NVME_STATUS:
            sct_sc = (uint16_t)get_scsi_pt_status_response(ptvp);
            pr2serr("NVMe Status: %s [0x%x]\n",
                    sg_get_nvme_cmd_status_str(sct_sc, b_len, b), sct_sc);
            if (op->verbose) {
                result = get_pt_result(ptvp);
                pr2serr("NVMe Result=0x%x\n", result);
                s_len = get_scsi_pt_sense_len(ptvp);
                if ((op->verbose > 1) && (s_len > 0)) {
                    pr2serr("NVMe completion queue 4 DWords (as byte "
                            "string):\n");
                    hex2stderr(sense_buffer, s_len, -1);
                }
            }
            break;
        default:
            pr2serr("do_scsi_pt: unknown error: %d\n", ret);
            ret = SG_LIB_CAT_OTHER;
            break;
        }
        goto done;
    } else if (ret < 0) {
        k = -ret;
        pr2serr("do_scsi_pt: %s\n", safe_strerror(k));
        err = get_scsi_pt_os_err(ptvp);
        if (err != k)
            pr2serr("    ... or perhaps: %s\n", safe_strerror(err));
        ret = sg_convert_errno(err);
        goto done;
    }

    s_len = get_scsi_pt_sense_len(ptvp);
    if (is_scsi_cdb) {
        res_cat = get_scsi_pt_result_category(ptvp);
        switch (res_cat) {
        case SCSI_PT_RESULT_GOOD:
            ret = 0;
            break;
        case SCSI_PT_RESULT_SENSE:
            ret = sg_err_category_sense(sense_buffer, s_len);
            break;
        case SCSI_PT_RESULT_TRANSPORT_ERR:
            get_scsi_pt_transport_err_str(ptvp, b_len, b);
            pr2serr(">>> transport error: %s\n", b);
            ret = SG_LIB_CAT_OTHER;
            break;
        case SCSI_PT_RESULT_OS_ERR:
            get_scsi_pt_os_err_str(ptvp, b_len, b);
            pr2serr(">>> os error: %s\n", b);
            ret = SG_LIB_CAT_OTHER;
            break;
        default:
            pr2serr(">>> unknown pass through result category (%d)\n",
                    res_cat);
            ret = SG_LIB_CAT_OTHER;
            break;
        }

        status = get_scsi_pt_status_response(ptvp);
        pr2serr("SCSI Status: ");
        sg_print_scsi_status(status);
        pr2serr("\n\n");
        if ((SAM_STAT_CHECK_CONDITION == status) && (! op->no_sense)) {
            if (0 == s_len)
                pr2serr(">>> Strange: status is CHECK CONDITION but no Sense "
                        "Information\n");
            else {
                pr2serr("Sense Information:\n");
                sg_print_sense(NULL, sense_buffer, s_len, (op->verbose > 0));
                pr2serr("\n");
            }
        }
        if (SAM_STAT_RESERVATION_CONFLICT == status)
            ret = SG_LIB_CAT_RES_CONFLICT;
    } else {    /* NVMe command */
        result = get_pt_result(ptvp);
        pr2serr("NVMe Result=0x%x\n", result);
        if (op->verbose && (s_len > 0)) {
            pr2serr("NVMe completion queue 4 DWords (as byte string):\n");
            hex2stderr(sense_buffer, s_len, -1);
        }
    }

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
                hex2stderr(dinp, data_len, 0);
            } else {
                const char * cp = "stdout";

                if (op->datain_file &&
                    ! ((1 == strlen(op->datain_file)) &&
                       ('-' == op->datain_file[0])))
                    cp = op->datain_file;
                pr2serr("Writing %d bytes of data to %s\n", data_len, cp);
                ret2 = write_dataout(op->datain_file, dinp,
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
    if (op->verbose && is_scsi_cdb) {
        sg_get_category_sense_str(ret, b_len, b, op->verbose - 1);
        pr2serr("%s\n", b);
    }
    if (wrkBuf)
        free(wrkBuf);
    if (free_buf_out)
        free(free_buf_out);
    if (ptvp)
        destruct_scsi_pt_obj(ptvp);
    if (sg_fd >= 0)
        scsi_pt_close_device(sg_fd);
    return ret >= 0 ? ret : SG_LIB_CAT_OTHER;
}

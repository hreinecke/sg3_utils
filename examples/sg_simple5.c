#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sg_lib.h"
#include "sg_pt.h"

/* This is a simple program executing a SCSI INQUIRY command and a
   TEST UNIT READY command using the SCSI generic pass through
   interface. This allows this example program to be ported to
   OSes other than linux.

*  Copyright (C) 2006-20018 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   Invocation: sg_simple5 [-x] <scsi_device>

   Version 1.03 (20180220)

*/

#define INQ_REPLY_LEN 96
#define INQ_CMD_LEN 6
#define TUR_CMD_LEN 6

#define CMD_TIMEOUT_SECS 60


int main(int argc, char * argv[])
{
    int sg_fd, k, ok, dsize, res, duration, resid, cat, got, slen;
    uint8_t inq_cdb [INQ_CMD_LEN] =
                                {0x12, 0, 0, 0, INQ_REPLY_LEN, 0};
    uint8_t tur_cdb [TUR_CMD_LEN] =
                                {0x00, 0, 0, 0, 0, 0};
    uint8_t inqBuff[INQ_REPLY_LEN];
    char * file_name = 0;
    char b[512];
    uint8_t sense_b[32];
    int verbose = 0;
    struct sg_pt_base * ptvp;

    for (k = 1; k < argc; ++k) {
        if (0 == strcmp("-v", argv[k]))
            verbose = 1;
        else if (0 == strcmp("-vv", argv[k]))
            verbose = 2;
        else if (0 == strcmp("-vvv", argv[k]))
            verbose = 3;
        else if (*argv[k] == '-') {
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
        printf("Usage: 'sg_simple5 [-v|-vv|-vvv] <device>'\n");
        return 1;
    }

    sg_fd = scsi_pt_open_device(file_name, 1 /* ro */, 0);
    /* N.B. An access mode of O_RDWR is required for some SCSI commands */
    if (sg_fd < 0) {
        fprintf(stderr, "error opening file: %s: %s\n",
                file_name, safe_strerror(-sg_fd));
        return 1;
    }

    dsize = sizeof(inqBuff);
    ok = 0;

    ptvp = construct_scsi_pt_obj();     /* one object per command */
    if (NULL == ptvp) {
        fprintf(stderr, "sg_simple5: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, inq_cdb, sizeof(inq_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, inqBuff, dsize);
    res = do_scsi_pt(ptvp, sg_fd, CMD_TIMEOUT_SECS, verbose);
    if (res < 0) {
        fprintf(stderr, "  pass through os error: %s\n",
                safe_strerror(-res));
        goto finish_inq;
    } else if (SCSI_PT_DO_BAD_PARAMS == res) {
        fprintf(stderr, "  bad pass through setup\n");
        goto finish_inq;
    } else if (SCSI_PT_DO_TIMEOUT == res) {
        fprintf(stderr, "  pass through timeout\n");
        goto finish_inq;
    }
    if ((verbose > 1) && ((duration = get_scsi_pt_duration_ms(ptvp)) >= 0))
        fprintf(stderr, "      duration=%d ms\n", duration);
    resid = get_scsi_pt_resid(ptvp);
    switch ((cat = get_scsi_pt_result_category(ptvp))) {
    case SCSI_PT_RESULT_GOOD:
        got = dsize - resid;
        if (verbose && (resid > 0))
            fprintf(stderr, "    requested %d bytes but "
                    "got %d bytes)\n", dsize, got);
        break;
    case SCSI_PT_RESULT_STATUS: /* other than GOOD and CHECK CONDITION */
        if (verbose) {
            sg_get_scsi_status_str(get_scsi_pt_status_response(ptvp),
                                   sizeof(b), b);
            fprintf(stderr, "  scsi status: %s\n", b);
        }
        goto finish_inq;
    case SCSI_PT_RESULT_SENSE:
        slen = get_scsi_pt_sense_len(ptvp);
        if (verbose) {
            sg_get_sense_str("", sense_b, slen, (verbose > 1),
                             sizeof(b), b);
            fprintf(stderr, "%s", b);
        }
        if (verbose && (resid > 0)) {
            got = dsize - resid;
            if ((verbose) || (got > 0))
                fprintf(stderr, "    requested %d bytes but "
                        "got %d bytes\n", dsize, got);
        }
        goto finish_inq;
    case SCSI_PT_RESULT_TRANSPORT_ERR:
        if (verbose) {
            get_scsi_pt_transport_err_str(ptvp, sizeof(b), b);
            fprintf(stderr, "  transport: %s", b);
        }
        goto finish_inq;
    case SCSI_PT_RESULT_OS_ERR:
        if (verbose) {
            get_scsi_pt_os_err_str(ptvp, sizeof(b), b);
            fprintf(stderr, "  os: %s", b);
        }
        goto finish_inq;
    default:
        fprintf(stderr, "  unknown pass through result "
                "category (%d)\n", cat);
        goto finish_inq;
    }

    ok = 1;
finish_inq:
    destruct_scsi_pt_obj(ptvp);

    if (ok) { /* output result if it is available */
        char * p = (char *)inqBuff;

        printf("Some of the INQUIRY command's results:\n");
        printf("    %.8s  %.16s  %.4s\n", p + 8, p + 16, p + 32);
    }
    ok = 0;


    /* Now prepare TEST UNIT READY command */
    ptvp = construct_scsi_pt_obj();     /* one object per command */
    if (NULL == ptvp) {
        fprintf(stderr, "sg_simple5: out of memory\n");
        return -1;
    }
    set_scsi_pt_cdb(ptvp, tur_cdb, sizeof(tur_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    /* no data in or out */
    res = do_scsi_pt(ptvp, sg_fd, CMD_TIMEOUT_SECS, verbose);
    if (res < 0) {
        fprintf(stderr, "  pass through os error: %s\n",
                safe_strerror(-res));
        goto finish_inq;
    } else if (SCSI_PT_DO_BAD_PARAMS == res) {
        fprintf(stderr, "  bad pass through setup\n");
        goto finish_inq;
    } else if (SCSI_PT_DO_TIMEOUT == res) {
        fprintf(stderr, "  pass through timeout\n");
        goto finish_inq;
    }
    if ((verbose > 1) && ((duration = get_scsi_pt_duration_ms(ptvp)) >= 0))
        fprintf(stderr, "      duration=%d ms\n", duration);
    resid = get_scsi_pt_resid(ptvp);
    switch ((cat = get_scsi_pt_result_category(ptvp))) {
    case SCSI_PT_RESULT_GOOD:
        break;
    case SCSI_PT_RESULT_STATUS: /* other than GOOD and CHECK CONDITION */
        if (verbose) {
            sg_get_scsi_status_str(get_scsi_pt_status_response(ptvp),
                                   sizeof(b), b);
            fprintf(stderr, "  scsi status: %s\n", b);
        }
        goto finish_tur;
    case SCSI_PT_RESULT_SENSE:
        slen = get_scsi_pt_sense_len(ptvp);
        if (verbose) {
            sg_get_sense_str("", sense_b, slen, (verbose > 1),
                             sizeof(b), b);
            fprintf(stderr, "%s", b);
        }
        goto finish_tur;
    case SCSI_PT_RESULT_TRANSPORT_ERR:
        if (verbose) {
            get_scsi_pt_transport_err_str(ptvp, sizeof(b), b);
            fprintf(stderr, "  transport: %s", b);
        }
        goto finish_tur;
    case SCSI_PT_RESULT_OS_ERR:
        if (verbose) {
            get_scsi_pt_os_err_str(ptvp, sizeof(b), b);
            fprintf(stderr, "  os: %s", b);
        }
        goto finish_tur;
    default:
        fprintf(stderr, "  unknown pass through result "
                "category (%d)\n", cat);
        goto finish_tur;
    }

    ok = 1;
finish_tur:
    destruct_scsi_pt_obj(ptvp);

    if (ok)
        printf("Test Unit Ready successful so unit is ready!\n");
    else
        printf("Test Unit Ready failed so unit may _not_ be ready!\n");

    scsi_pt_close_device(sg_fd);
    return 0;
}

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_err.h"

/* A utility program for the Linux OS SCSI subsystem.
*  Copyright (C) 2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI "Report supported
   operation codes" command [0xa3/0xc].

*/

static char * version_str = "0.11 20040708";


#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define SG_MAINTENANCE_IN 0xa3
#define RSOC_SA     0xc
#define RSOC_CMD_LEN 12
#define MX_ALLOC_LEN 8192

#define INQUIRY_CMD 0x12
#define INQUIRY_CMDLEN 6

#define EBUFF_SZ 256

// <<<<<<<<<<<<<<< start of test code
// #define TEST_CODE

#ifdef TEST_CODE

#warning "<<<< TEST_CODE response compiled in >>>>"

#define DUMMY_CMDS 8

struct cmd_descript_t {
    unsigned char d[8];
};

struct dummy_resp_t {
    unsigned char cdl[4];
    struct cmd_descript_t descript[DUMMY_CMDS];
};

static struct dummy_resp_t dummy_resp = { {0, 0, 0, 8 * DUMMY_CMDS},
     {{{0, 0, 0, 0, 0, 0, 0, 6}},
      {{0xa3, 0, 0, 0xc, 0, 1, 0, 12}},
      {{1, 0, 0, 0, 0, 0, 0, 6}},
      {{2, 0, 0, 0, 0, 0, 0, 6}},
      {{3, 0, 0, 0, 0, 0, 2, 0}},
      {{4, 0, 0, 0, 0, 0, 0, 6}},
      {{5, 0, 0, 0, 0, 0, 0, 6}},
      {{0x7f, 0, 0, 0x1, 0, 1, 0, 32}},
}};

static unsigned char dummy_1_cmd[] = {
    0, 3, 0, 6, 0x12, 0x3, 0xff, 0x0, 0xff, 0x1
};

#endif
// <<<<<<<<<<<<<<< end of test code



/* Returns 0 when successful, else -1 */
static int do_rsoc(int sg_fd, int rep_opts, int rq_opcode, int rq_servact, 
                  void * resp, int mx_resp_len, int noisy, int verbose)
{
    int res, k;
    unsigned char rsocCmdBlk[RSOC_CMD_LEN] = {SG_MAINTENANCE_IN, RSOC_SA, 0, 
                                              0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (rep_opts)
        rsocCmdBlk[2] = (rep_opts & 0x7);
    if (rq_opcode > 0)
        rsocCmdBlk[3] = (rq_opcode & 0xff);
    if (rq_servact > 0) {
        rsocCmdBlk[4] = (unsigned char)((rq_servact >> 8) & 0xff);
        rsocCmdBlk[5] = (unsigned char)(rq_servact & 0xff);

    }
    rsocCmdBlk[6] = (unsigned char)((mx_resp_len >> 24) & 0xff);
    rsocCmdBlk[7] = (unsigned char)((mx_resp_len >> 16) & 0xff);
    rsocCmdBlk[8] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    rsocCmdBlk[9] = (unsigned char)(mx_resp_len & 0xff);

    if (verbose) {
        fprintf(stderr, "    Report Supported Operation Codes cmd: ");
        for (k = 0; k < RSOC_CMD_LEN; ++k)
            fprintf(stderr, "%02x ", rsocCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rsocCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = rsocCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (rsoc) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        return 0;
    default:
        if (noisy) {
            char ebuff[EBUFF_SZ];
            snprintf(ebuff, EBUFF_SZ, "RSOC error, rep_opts=%d, "
                     "rq_opc=%d, rq_sa=%x ", rep_opts, 
                     ((rq_opcode > 0) ? rq_opcode : 0), 
                     ((rq_servact > 0) ? rq_servact : 0));
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

/* Returns 0 when successful, else -1 */
static int do_simple_inq(int sg_fd, int noisy, 
                         char * resp_data, int verbose)
{
    int res, k;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    const int resp_sz = 36;

    if (! resp_data)
        return -1;
    memset(resp_data, 0, resp_sz);
    resp_data[0] = 0x7f;    /* peri_qual=3, peri_type=1f */
    inqCmdBlk[4] = resp_sz;
    if (verbose) {
        fprintf(stderr, "        inquiry cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            fprintf(stderr, "%02x ", inqCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inqCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = resp_sz;
    io_hdr.dxferp = resp_data;
    io_hdr.cmdp = inqCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (inquiry) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        return 0;
    default:
        if (noisy) {
            char ebuff[EBUFF_SZ];
            snprintf(ebuff, EBUFF_SZ, "Inquiry error ");
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

static void usage()
{
    fprintf(stderr,
            "Usage: 'sg_opcodes [-o=<opcode> [-s=<service_action>] ]"
            " [-v] [-V] <scsi_device>'\n"
            " where -o=<opcode>  first byte of command to be queried\n"
            "       -s=<service_action>  in addition to opcode\n"
            "       -v   verbose\n"
            "       -V   output version string\n"
            "       -?   output this usage message\n");
}

static const char * scsi_ptype_strs[] = {
    /* 0 */ "disk",
    "tape",
    "printer",
    "processor",
    "write once optical disk",
    /* 5 */ "cd/dvd",
    "scanner",
    "optical memory device",
    "medium changer",
    "communications",
    /* 0xa */ "graphics",
    "graphics",
    "storage array controller",
    "enclosure services device",
    "simplified direct access device",
    "optical card reader/writer device",
    /* 0x10 */ "bridging expander",
    "object based storage",
    "automation/driver interface",
};


int main(int argc, char * argv[])
{
    int sg_fd, k, num, cd_len, serv_act;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    char inq_buff[36];
    unsigned char rsoc_buff[MX_ALLOC_LEN];
    unsigned char * ucp;
    char name_buff[64];
    char sa_buff[8];
    int do_opcode = -1;
    int do_servact = -1;
    int do_verbose = 0;
    int rep_opts = 0;
    int peri_type = 0;
    int ret = 0;

    for (k = 1; k < argc; ++k) {
        if (0 == strncmp("-o=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &do_opcode);
            if ((1 != num) || (do_opcode > 255)) {
                fprintf(stderr, "Bad number after '-o' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strncmp("-s=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &do_servact);
            if (1 != num) {
                fprintf(stderr, "Bad number after '-s' switch\n");
                file_name = 0;
                break;
            }
        }
        else if (0 == strcmp("-v", argv[k]))
            ++do_verbose;
        else if (0 == strcmp("-?", argv[k])) {
            file_name = 0;
            break;
        }
        else if (0 == strcmp("-V", argv[k])) {
            fprintf(stderr, "Version string: %s\n", version_str);
            exit(0);
        }
        else if (*argv[k] == '-') {
            fprintf(stderr, "Unrecognized switch: %s\n", argv[k]);
            file_name = 0;
            break;
        }
        else if (0 == file_name)
            file_name = argv[k];
        else {
            fprintf(stderr, "too many arguments\n");
            file_name = 0;
            break;
        }
    }
    
    if (0 == file_name) {
        usage();
        return 1;
    }

    if ((sg_fd = open(file_name, O_RDONLY | O_NONBLOCK)) < 0) {
        snprintf(ebuff, EBUFF_SZ, "sg_opcodes: error opening file: %s (ro)",
                 file_name);
        perror(ebuff);
        return 1;
    }
    if (0 == do_simple_inq(sg_fd, 1, inq_buff, do_verbose)) {
        printf("  %.8s  %.16s  %.4s\n", inq_buff + 8, inq_buff + 16,
               inq_buff + 32);
        peri_type = inq_buff[0] & 0x1f;
        if (peri_type >= 
                (int)(sizeof(scsi_ptype_strs) / sizeof(scsi_ptype_strs[0])))
            printf("  Peripheral device type: 0x%x\n", peri_type);
        else
            printf("  Peripheral device type: %s\n", 
                   scsi_ptype_strs[peri_type]);
    } else {
        printf("sg_opcodes: %s doesn't respond to a SCSI INQUIRY\n", file_name);
        return 1;
    }
    close(sg_fd);
#ifndef TEST_CODE
    if (5 == peri_type) {
        printf("'Report supported operation codes' command not supported "
               "for CD/DVD devices\n");
        return 1;
    }
#endif

    if ((sg_fd = open(file_name, O_RDWR | O_NONBLOCK)) < 0) {
        snprintf(ebuff, EBUFF_SZ, "sg_opcodes: error opening file: %s (rw)",
                 file_name);
        perror(ebuff);
        return 1;
    }
    if (do_opcode >= 0)
        rep_opts = ((do_servact >= 0) ? 2 : 1);
    memset(rsoc_buff, 0, sizeof(rsoc_buff));
#ifndef TEST_CODE
    if (0 != do_rsoc(sg_fd, rep_opts, do_opcode, do_servact, rsoc_buff, 
                     sizeof(rsoc_buff), 1, do_verbose)) {
        return 1;
    }
#else
    memcpy(rsoc_buff, (unsigned char *)&dummy_resp, sizeof(dummy_resp));
#endif
    if (0 == rep_opts) {  /* list all supported operation codes */
        cd_len = ((rsoc_buff[0] << 24) | (rsoc_buff[1] << 16) | 
                  (rsoc_buff[2] << 8) | rsoc_buff[3]); 
        if (cd_len > ((int)sizeof(rsoc_buff) - 4)) {
            printf("sg_opcodes: command data length=%d, allocation=%d; "
                   "truncate\n", cd_len, (int)sizeof(rsoc_buff) - 4);
            cd_len = (((int)sizeof(rsoc_buff) - 4) / 8) * 8;
        }
        if (0 == cd_len) {
            printf("sg_opcodes: no commands to display\n");
            return 0;
        }
        ucp = rsoc_buff + 4;
        printf("\nOpcode  Service    CDB    Name\n");
        printf(  "(hex)   action(h)  size       \n");
        printf("-----------------------------------------------\n");
        /* N.B. SPC-3 does _not_ requiring any ordering of response */
        for (k = 0; k < cd_len; k += 8, ucp += 8) {
            if (ucp[5] & 1) {
                serv_act = ((ucp[2] << 8) | ucp[3]);
                sg_get_opcode_sa_name(ucp[0], serv_act, peri_type,
                                      sizeof(name_buff), name_buff);
                snprintf(sa_buff, sizeof(sa_buff), "%.4x", serv_act);
            } else {
                sg_get_opcode_name(ucp[0], peri_type, 
                                   sizeof(name_buff), name_buff);
                memset(sa_buff, ' ', sizeof(sa_buff));
            }
            printf(" %.2x     %.4s       %3d    %s\n",
                   ucp[0], sa_buff, ((ucp[6] << 8) | ucp[7]), name_buff);
        }
    } else {    /* asked about specific command */
        const char * cp;
        int v = 0;

#ifdef TEST_CODE
        memcpy(rsoc_buff, dummy_1_cmd, sizeof(dummy_1_cmd));
#endif
        printf("  Opcode=0x%.2x", do_opcode);
        if (rep_opts > 1)
            printf("  Service_action=0x%.4x", do_servact);
        printf("\n");
        sg_get_opcode_sa_name(((do_opcode > 0) ? do_opcode : 0),
                              ((do_servact > 0) ? do_servact : 0),
                              peri_type, sizeof(name_buff), name_buff);
        printf("  Command_name: %s\n", name_buff);
        switch((int)(rsoc_buff[1] & 7)) {
        case 0: cp = "not currently available"; break;
        case 1: cp = "NOT supported"; break;
        case 3: cp = "supported (conforming to SCSI standard)"; v = 1; break;
        case 5: cp = "supported (in a vendor specific manner)"; v = 1; break;
        default:
            snprintf(name_buff, sizeof(name_buff), "support reserved [0x%x]",
                     rsoc_buff[1] & 7); 
            cp = name_buff;
            break;
        }
        printf("  Command %s\n", cp);
        if (v) {
            printf("  Usage data: ");
            cd_len = ((rsoc_buff[2] << 8) | rsoc_buff[3]);
            ucp = rsoc_buff + 4;
            for (k = 0; k < cd_len; ++k)
                printf("%.2x ", ucp[k]);
            printf("\n");
        }
    }
    close(sg_fd);
    return ret;
}

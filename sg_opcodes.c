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
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
*  Copyright (C) 2004-2005 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI "Report supported
   operation codes" command [0xa3/0xc].

*/

static char * version_str = "0.21 20050904";


#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define SG_MAINTENANCE_IN 0xa3
#define RSOC_SA     0xc
#define RSTMF_SA    0xd
#define RSOC_CMD_LEN 12
#define RSTMF_CMD_LEN 12
#define MX_ALLOC_LEN 8192

#define NAME_BUFF_SZ 64

#define EBUFF_SZ 256

static int peri_type = 0; /* ugly but not easy to pass to alpha compare */

/* <<<<<<<<<<<<<<< start of test code */
/* #define TEST_CODE */

#ifdef TEST_CODE

#warning "<<<< TEST_CODE response compiled in >>>>"

#define DUMMY_CMDS 17

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
      {{0x12, 0, 0, 0, 0, 0, 0, 6}},
      {{0x1d, 0, 0, 0, 0, 0, 0, 6}},
      {{0x25, 0, 0, 0, 0, 0, 0, 10}},
      {{0x28, 0, 0, 0, 0, 0, 0, 10}},
      {{0x2a, 0, 0, 0, 0, 0, 0, 10}},
      {{0x1a, 0, 0, 0, 0, 0, 0, 6}},
      {{0x15, 0, 0, 0, 0, 0, 0, 6}},
      {{0xa3, 0, 0, 0x5, 0, 1, 0, 12}},
      {{0x5a, 0, 0, 0, 0, 0, 0, 10}},
      {{0x55, 0, 0, 0, 0, 0, 0, 10}},
      {{2, 0, 0, 0, 0, 0, 0, 6}},
      {{3, 0, 0, 0, 0, 0, 0, 6}},
      {{4, 0, 0, 0, 0, 0, 0, 6}},
      {{0xa0, 0, 0, 0, 0, 0, 0, 12}},
      {{0x7f, 0, 0, 0x1, 0, 1, 0, 32}},
}};

static unsigned char dummy_1_cmd[] = {
    0, 3, 0, 6, 0x12, 0x3, 0xff, 0x0, 0xff, 0x1
};

static unsigned char dummy_rsmft_r0 = 0xff;

#endif
/* <<<<<<<<<<<<<<< end of test code */


/* Report Supported Operation Codes */
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
    if (verbose > 2)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("Report supported operation codes", &io_hdr,
                        verbose);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        return 0;
    default:
        if (noisy | verbose) {
            char ebuff[EBUFF_SZ];

            if (0 == rep_opts)
                snprintf(ebuff, EBUFF_SZ, "RSOC error, rep_opts=0 (all) ");
            else if (1 == rep_opts)
                snprintf(ebuff, EBUFF_SZ, "RSOC error, rq_opcode=0x%x ",
                         rq_opcode);
            else
                snprintf(ebuff, EBUFF_SZ, "RSOC error, rq_opcode=0x%x, "
                         "rq_sa=0x%x ", rq_opcode, rq_servact);
            sg_chk_n_print3(ebuff, &io_hdr, verbose);
        }
        return -1;
    }
}

/* Report Supported Task Management Function */
/* Returns 0 when successful, else -1 */
static int do_rstmf(int sg_fd, void * resp, int mx_resp_len, int noisy,
                    int verbose)
{
    int res, k;
    unsigned char rstmfCmdBlk[RSTMF_CMD_LEN] = {SG_MAINTENANCE_IN, RSTMF_SA,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    rstmfCmdBlk[6] = (unsigned char)((mx_resp_len >> 24) & 0xff);
    rstmfCmdBlk[7] = (unsigned char)((mx_resp_len >> 16) & 0xff);
    rstmfCmdBlk[8] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    rstmfCmdBlk[9] = (unsigned char)(mx_resp_len & 0xff);

    if (verbose) {
        fprintf(stderr, "    Report Supported Task Management Functions cmd: ");
        for (k = 0; k < RSTMF_CMD_LEN; ++k)
            fprintf(stderr, "%02x ", rstmfCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(rstmfCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = rstmfCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (rstmf) error");
        return -1;
    }
    if (verbose > 2)
        fprintf(stderr, "      duration=%u ms\n", io_hdr.duration);
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("Report supported task management fns", &io_hdr,
                        verbose);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        return 0;
    default:
        if (noisy | verbose) {
            char ebuff[EBUFF_SZ];
            snprintf(ebuff, EBUFF_SZ, "RSTMF error ");
            sg_chk_n_print3(ebuff, &io_hdr, verbose);
        }
        return -1;
    }
}

static void usage()
{
    fprintf(stderr,
            "Usage:  sg_opcodes [-a] [-o=<opcode> [-s=<service_action>] ]"
            " [-t] [-u] [-v]\n"
            "                   [-V] <scsi_device>\n"
            " where -a   output list of operation codes sorted "
            "alphabetically\n"
            "       -o=<opcode>  first byte of command to query (in hex)\n"
            "       -s=<service_action>  in addition to opcode (in hex)\n"
            "       -t   output list of supported task management functions\n"
            "       -u   output list of operation codes as is (unsorted)\n"
            "       -v   verbose\n"
            "       -V   output version string\n"
            "       -?   output this usage message\n\n"
            "Performs a REPORT SUPPORTED OPERATION CODES (or supported task "
            "management\nfunctions) SCSI command\n");
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
    /* 0xa */ "graphics [0xa]",
    "graphics [0xb]",
    "storage array controller",
    "enclosure services device",
    "simplified direct access device",
    "optical card reader/writer device",
    /* 0x10 */ "bridge controller commands",
    "object based storage",
    "automation/driver interface",
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

/* returns -1 when left < right, 0 when left == right, else returns 1 */
int opcode_num_compare(const void * left, const void * right)
{
    const unsigned char * ll = *(unsigned char **)left;
    const unsigned char * rr = *(unsigned char **)right;
    int l_serv_act = 0;
    int r_serv_act = 0;
    int l_opc, r_opc;

    if (NULL == ll)
        return -1;
    if (NULL == rr)
        return -1;
    l_opc = ll[0];
    if (ll[5] & 1)
        l_serv_act = ((ll[2] << 8) | ll[3]);
    r_opc = rr[0];
    if (rr[5] & 1)
        r_serv_act = ((rr[2] << 8) | rr[3]);
    if (l_opc < r_opc)
        return -1;
    if (l_opc > r_opc)
        return 1;
    if (l_serv_act < r_serv_act)
        return -1;
    if (l_serv_act > r_serv_act)
        return 1;
    return 0;
}

/* returns -1 when left < right, 0 when left == right, else returns 1 */
int opcode_alpha_compare(const void * left, const void * right)
{
    const unsigned char * ll = *(unsigned char **)left;
    const unsigned char * rr = *(unsigned char **)right;
    int l_serv_act = 0;
    int r_serv_act = 0;
    char l_name_buff[NAME_BUFF_SZ];
    char r_name_buff[NAME_BUFF_SZ];
    int l_opc, r_opc;

    if (NULL == ll)
        return -1;
    if (NULL == rr)
        return -1;
    l_opc = ll[0];
    if (ll[5] & 1)
        l_serv_act = ((ll[2] << 8) | ll[3]);
    l_name_buff[0] = '\0';
    sg_get_opcode_sa_name(l_opc, l_serv_act, peri_type,
                          NAME_BUFF_SZ, l_name_buff);
    r_opc = rr[0];
    if (rr[5] & 1)
        r_serv_act = ((rr[2] << 8) | rr[3]);
    r_name_buff[0] = '\0';
    sg_get_opcode_sa_name(r_opc, r_serv_act, peri_type,
                          NAME_BUFF_SZ, r_name_buff);
    return strncmp(l_name_buff, r_name_buff, NAME_BUFF_SZ);
}

void list_all_codes(unsigned char * rsoc_buff, int rsoc_len, int unsorted,
                    int alpha)
{
    int k, cd_len, serv_act;
    unsigned char * ucp;
    char name_buff[NAME_BUFF_SZ];
    char sa_buff[8];
    unsigned char ** sort_arr = NULL;

    cd_len = ((rsoc_buff[0] << 24) | (rsoc_buff[1] << 16) | 
              (rsoc_buff[2] << 8) | rsoc_buff[3]); 
    if (cd_len > (rsoc_len - 4)) {
        printf("sg_opcodes: command data length=%d, allocation=%d; "
               "truncate\n", cd_len, rsoc_len - 4);
        cd_len = ((rsoc_len - 4) / 8) * 8;
    }
    if (0 == cd_len) {
        printf("sg_opcodes: no commands to display\n");
        return;
    }
    printf("\nOpcode  Service    CDB    Name\n");
    printf(  "(hex)   action(h)  size       \n");
    printf("-----------------------------------------------\n");
    /* N.B. SPC-4 does _not_ requiring any ordering of response */
    if (! unsorted) {
        sort_arr = malloc(cd_len * sizeof(unsigned char *));
        if (NULL == sort_arr) {
            printf("sg_opcodes: no memory to sort operation codes, "
                   "try '-u'\n");
            return;
        }
        memset(sort_arr, 0, cd_len * sizeof(unsigned char *));
        ucp = rsoc_buff + 4;
        for (k = 0; k < cd_len; k += 8, ucp += 8)
            sort_arr[(k / 8)] = ucp;
        qsort(sort_arr, (cd_len / 8), sizeof(unsigned char *), 
              (alpha ? opcode_alpha_compare : opcode_num_compare));
    }
    for (k = 0; k < cd_len; k += 8) {
        ucp = unsorted ? (rsoc_buff + 4 + k) : sort_arr[(k / 8)];
        if (ucp[5] & 1) {
            serv_act = ((ucp[2] << 8) | ucp[3]);
            sg_get_opcode_sa_name(ucp[0], serv_act, peri_type,
                                  NAME_BUFF_SZ, name_buff);
            snprintf(sa_buff, sizeof(sa_buff), "%.4x", serv_act);
        } else {
            sg_get_opcode_name(ucp[0], peri_type, 
                               NAME_BUFF_SZ, name_buff);
            memset(sa_buff, ' ', sizeof(sa_buff));
        }
        printf(" %.2x     %.4s       %3d    %s\n",
               ucp[0], sa_buff, ((ucp[6] << 8) | ucp[7]), name_buff);
    }
}


int main(int argc, char * argv[])
{
    int sg_fd, k, num, cd_len, plen, jmp_out;
    const char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char rsoc_buff[MX_ALLOC_LEN];
    unsigned char * ucp;
    char name_buff[NAME_BUFF_SZ];
    int do_alpha = 0;
    int do_opcode = -1;
    int do_servact = -1;
    int do_verbose = 0;
    int do_unsorted = 0;
    int do_taskman = 0;
    int rep_opts = 0;
    int ret = 0;
    const char * cp;
    struct sg_simple_inquiry_resp inq_resp;

    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'a':
                    do_alpha = 1;
                    break;
                case 't':
                    do_taskman = 1;
                    break;
                case 'u':
                    do_unsorted = 1;
                    break;
                case 'v':
                    ++do_verbose;
                    break;
                case 'V':
                    fprintf(stderr, "Version string: %s\n", version_str);
                    exit(0);
                case 'h':
                case '?':
                    usage();
                    return 1;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("o=", cp, 2)) {
                num = sscanf(cp + 2, "%x", (unsigned int *)&do_opcode);
                if ((1 != num) || (do_opcode > 255)) {
                    fprintf(stderr, "Bad number after 'o=' option\n");
                    usage();
                    return 1;
                }
            } else if (0 == strncmp("s=", cp, 2)) {
                num = sscanf(cp + 2, "%x", (unsigned int *)&do_servact);
                if (1 != num) {
                    fprintf(stderr, "Bad number after 's=' option\n");
                    usage();
                    return 1;
                }
            } else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage();
                return 1;
            }
        } else if (0 == file_name)
            file_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", file_name, cp);
            usage();
            return 1;
        }
    }
    
    if (0 == file_name) {
        fprintf(stderr, "No <scsi_device> argument given\n");
        usage();
        return 1;
    }
    if ((-1 != do_servact) && (-1 == do_opcode)) {
        fprintf(stderr, "When '-s' is chosen, so must '-o' be chosen\n");
        usage();
        return 1;
    }
    if (do_unsorted && do_alpha)
        fprintf(stderr, "warning: unsorted ('-u') and alpha ('-a') options "
                "chosen, ignoring alpha\n");
    if (do_taskman && ((-1 != do_opcode) || do_alpha || do_unsorted)) {
        fprintf(stderr, "warning: task management functions ('-t') chosen "
                "so alpha ('-a'),\n          unsorted ('-u') and opcode "
                "('-o') options ignored\n");
    }

    if ((sg_fd = open(file_name, O_RDONLY | O_NONBLOCK)) < 0) {
        snprintf(ebuff, EBUFF_SZ, "sg_opcodes: error opening file: %s (ro)",
                 file_name);
        perror(ebuff);
        return 1;
    }
    if (0 == sg_simple_inquiry(sg_fd, &inq_resp, 1, do_verbose)) {
        printf("  %.8s  %.16s  %.4s\n", inq_resp.vendor, inq_resp.product,
               inq_resp.revision);
        peri_type = inq_resp.peripheral_type;
        cp = get_ptype_str(peri_type);
        if (strlen(cp) > 0)
            printf("  Peripheral device type: %s\n", cp);
        else
            printf("  Peripheral device type: 0x%x\n", peri_type);
    } else {
        printf("sg_opcodes: %s doesn't respond to a SCSI INQUIRY\n", file_name);
        return 1;
    }
    close(sg_fd);
#ifndef TEST_CODE
    if (5 == peri_type) {
        if (do_taskman)
            printf("'Report supported task management functions' command not "
                   "supported\nfor CD/DVD devices\n");
        else
            printf("'Report supported operation codes' command not "
                   "supported for CD/DVD devices\n");
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
    if (do_taskman) {
        if (0 != do_rstmf(sg_fd, rsoc_buff, sizeof(rsoc_buff), 1,
                          do_verbose))
            return 1;
    } else {
        if (0 != do_rsoc(sg_fd, rep_opts, do_opcode, do_servact, rsoc_buff,
                         sizeof(rsoc_buff), 1, do_verbose))
            return 1;
    }
#else
    if (do_taskman)
        rsoc_buff[0] = dummy_rsmft_r0;
    else
        memcpy(rsoc_buff, (unsigned char *)&dummy_resp, sizeof(dummy_resp));
#endif
    if (do_taskman) {
        printf("\nTask Management Functions supported by device:\n");
        if (rsoc_buff[0] & 0x80)
            printf("    Abort task\n");
        if (rsoc_buff[0] & 0x40)
            printf("    Abort task set\n");
        if (rsoc_buff[0] & 0x20)
            printf("    Clear ACA\n");
        if (rsoc_buff[0] & 0x10)
            printf("    Clear task set\n");
        if (rsoc_buff[0] & 0x8)
            printf("    Logical unit reset\n");
        if (rsoc_buff[0] & 0x4)
            printf("    Query task\n");
        if (rsoc_buff[0] & 0x2)
            printf("    Target reset\n");
        if (rsoc_buff[0] & 0x1)
            printf("    Wakeup\n");
        if (rsoc_buff[1] & 0x1)
            printf("    I_T nexus reset\n");
    } else if (0 == rep_opts)    /* list all supported operation codes */
        list_all_codes(rsoc_buff, sizeof(rsoc_buff), do_unsorted, do_alpha);
    else {    /* asked about specific command */
        const char * cp;
        int v = 0;

#ifdef TEST_CODE
        memcpy(rsoc_buff, dummy_1_cmd, sizeof(dummy_1_cmd));
#endif
        printf("\n  Opcode=0x%.2x", do_opcode);
        if (rep_opts > 1)
            printf("  Service_action=0x%.4x", do_servact);
        printf("\n");
        sg_get_opcode_sa_name(((do_opcode > 0) ? do_opcode : 0),
                              ((do_servact > 0) ? do_servact : 0),
                              peri_type, NAME_BUFF_SZ, name_buff);
        printf("  Command_name: %s\n", name_buff);
        switch((int)(rsoc_buff[1] & 7)) {
        case 0: cp = "not currently available"; break;
        case 1: cp = "NOT supported"; break;
        case 3: cp = "supported (conforming to SCSI standard)"; v = 1; break;
        case 5: cp = "supported (in a vendor specific manner)"; v = 1; break;
        default:
            snprintf(name_buff, NAME_BUFF_SZ, "support reserved [0x%x]",
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

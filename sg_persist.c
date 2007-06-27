#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
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

   This program issues the SCSI PERSISTENT IN and OUT commands. 

*/

static char * version_str = "0.15 20040708";


#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define SG_PERSISTENT_IN 0x5e
#define SG_PERSISTENT_OUT 0x5f
#define PRIN_RKEY_SA     0x0
#define PRIN_RRES_SA     0x1
#define PRIN_RCAP_SA     0x2
#define PRIN_RFSTAT_SA   0x3
#define PRINOUT_CMD_LEN 10
#define PROUT_REG_SA     0x0
#define PROUT_RES_SA     0x1
#define PROUT_REL_SA     0x2
#define PROUT_CLEAR_SA   0x3
#define PROUT_PREE_SA    0x4
#define PROUT_PREE_AB_SA 0x5
#define PROUT_REG_IGN_SA 0x6
#define MX_ALLOC_LEN 8192

#define INQUIRY_CMD 0x12
#define INQUIRY_CMDLEN 6

#define EBUFF_SZ 256

#define MAX_EXTRA_ARGS 16


static struct option long_options[] = {
        {"clear", 0, 0, 'C'},
        {"device", 1, 0, 'd'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"in", 0, 0, 'i'},
        {"out", 0, 0, 'o'},
        {"no-inquiry", 0, 0, 'n'},
        {"param-alltgpt", 0, 0, 'Y'},
        {"param-aptbl", 0, 0, 'Z'},
        {"param-rk", 1, 0, 'K'},
        {"param-sark", 1, 0, 'S'},
        {"preempt", 0, 0, 'P'},
        {"preempt-abort", 0, 0, 'A'},
        {"prout-type", 1, 0, 'T'},
        {"read-full-status", 0, 0, 's'},
        {"read-keys", 0, 0, 'k'},
        {"read-reservation", 0, 0, 'r'},
        {"read-status", 0, 0, 's'},
        {"register", 0, 0, 'G'},
        {"register-ignore", 0, 0, 'I'},
        {"release", 0, 0, 'L'},
        {"report-capabilities", 0, 0, 'c'},
        {"reserve", 0, 0, 'R'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0}
};

static const char * prin_sa_strs[] = {
    "Read keys",
    "Read reservation",
    "Report capabilities",
    "Read full status",
    "[reserved 0x4]",
    "[reserved 0x5]",
    "[reserved 0x6]",
    "[reserved 0x7]",
};
static const int num_prin_sa_strs = sizeof(prin_sa_strs) / 
                                    sizeof(prin_sa_strs[0]);

static const char * prout_sa_strs[] = {
    "Register",
    "Reserve",
    "Release",
    "Clear",
    "Preempt",
    "Preempt and abort",
    "Register and ignore existing key",
    "[reserved 0x7]",
};
static const int num_prout_sa_strs = sizeof(prout_sa_strs) / 
                                     sizeof(prout_sa_strs[0]);

static void dStrHex(const char* str, int len, int no_ascii);


/* Returns 0 when successful, else -1 */
static int do_prin(int sg_fd, int rq_servact, void * resp, int mx_resp_len,
                   int noisy, int verbose)
{
    int res, k;
    unsigned char prinCmdBlk[PRINOUT_CMD_LEN] = {SG_PERSISTENT_IN, 0, 0, 0,
                                                 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (rq_servact > 0) {
        prinCmdBlk[1] = (unsigned char)(rq_servact & 0x1f);

    }
    prinCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    prinCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);

    if (verbose) {
        fprintf(stderr, "    Persistent Reservation In cmd: ");
        for (k = 0; k < PRINOUT_CMD_LEN; ++k)
            fprintf(stderr, "%02x ", prinCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(prinCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = prinCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (PR In) error");
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
            snprintf(ebuff, EBUFF_SZ, "PRIN error, service_action: %s",
                     ((rq_servact < num_prin_sa_strs) ? 
                        prin_sa_strs[rq_servact] : "??"));
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

/* Returns 0 when successful, else -1 */
static int do_prout(int sg_fd, int rq_servact, int rq_scope, int rq_type,
                    void * paramp, int param_len, int noisy, int verbose)
{
    int res, k;
    unsigned char proutCmdBlk[PRINOUT_CMD_LEN] = {SG_PERSISTENT_OUT, 0, 0, 0,
                                                  0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if (rq_servact > 0) {
        proutCmdBlk[1] = (unsigned char)(rq_servact & 0x1f);

    }
    proutCmdBlk[2] = (((rq_scope & 0xf) << 4) | (rq_type & 0xf));
    proutCmdBlk[7] = (unsigned char)((param_len >> 8) & 0xff);
    proutCmdBlk[8] = (unsigned char)(param_len & 0xff);

    if (verbose) {
        fprintf(stderr, "    Persistent Reservation Out cmd: ");
        for (k = 0; k < PRINOUT_CMD_LEN; ++k)
            fprintf(stderr, "%02x ", proutCmdBlk[k]);
        fprintf(stderr, "\n");
        if (verbose > 1) {
            fprintf(stderr, "    Persistent Reservation Out parameters:\n");
            dStrHex(paramp, param_len, 0);
        }
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(proutCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = param_len;
    io_hdr.dxferp = paramp;
    io_hdr.cmdp = proutCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (PR Out) error");
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
            snprintf(ebuff, EBUFF_SZ, "PROUT error, service_action: %s",
                     ((rq_servact < num_prout_sa_strs) ? 
                        prout_sa_strs[rq_servact] : "??"));
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
            "Usage: 'sg_persist [<options>] [<scsi_device>] [extra_args]\n"
            " where Persistent Reservation (PR) <options> include:\n"
            "       --clear|-C                PR Out variant\n"
            "       --device=<scsi_device>    device to query or change\n"
            "       -d <scsi_device>          device to query or change "
            "('-d' optional)\n"
            "       --help|-h    output this usage message\n"
            "       --hex|-H     output response in hex (default ACSII)\n"
            "       --in|-i      request PR In command (default)\n"
            "       --out|-o     request PR Out command\n"
            "       --no-inquiry|-n  skip INQUIRY (default: do INQUIRY)\n"
            "       --param-alltgpt|-Y  PR Out parameter 'ALL_TG_PT'\n"
            "       --param-aptpl|-Z  PR Out parameter 'APTPL'\n"
            "       --param-rk=<h>|-K <h>  PR Out parameter reservation key\n"
            "                 (argument in hex)\n"
            "       --param-sark=<h>|-S <h>  PR Out parameter service action\n"
            "                 reservation key (argument in hex)\n"
            "       --preempt|-P           PR Out variant\n"
            "       --preempt-abort|-A     PR Out variant\n"
            "       --prout-type=<h>|-T <n>  PR Out command type\n"
            "       --read-keys|-k         PR In variant (service action)\n"
            "       --read-reservations|-r   PR In variant\n"
            "       --read-status|-s   PR In variant\n"
            "       --read-full-status|-s  same as '--read-status'\n"
            "       --register|-G          PR Out variant\n"
            "       --register-ignore|-I   PR Out Register and Ignore\n"
            "       --release|-L   PR Out variant (service action)\n"
            "       --report-capabilities|-c   PR In variant\n"
            "       --reserve|-R   PR Out variant (service action)\n"
            "       --verbose|-v   output additional debug information\n"
            "       --version|-V   output version string\n"
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

static const char * pr_type_strs[] = {
    "obsolete [0]",
    "Write Exclusive",
    "obsolete [2]",
    "Exclusive Access",
    "obsolete [4]",
    "Write Exclusive, registrants only",
    "Exclusive Access, registrants only",
    "Write Exclusive, all registrants",
    "Exclusive Access, all registrants",
    "obsolete [9]", "obsolete [0xa]", "obsolete [0xb]", "obsolete [0xc]",
    "obsolete [0xd]", "obsolete [0xe]", "obsolete [0xf]",
};

static void decode_transport_id(unsigned char * ucp, int len)
{
    int format_code, proto_id, num, j;
    unsigned long long ull;

    printf("      Transport Id of initiator [descriptor length=%d]:\n",
           len);
    format_code = ((ucp[0] >> 6) & 0x3);
    proto_id = (ucp[0] & 0xf);
    switch (proto_id) {
    case 0: /* Fibre channel */
        printf("        FCP-2 World Wide Name:\n");
        if (0 != format_code) 
            printf("        [Unexpected format code: %d]\n", format_code);
        dStrHex(&ucp[8], 8, 0);
        break;
    case 1: /* Parallel SCSI */
        printf("        Parallel SCSI initiator SCSI address: 0x%x:\n",
               ((ucp[2] << 8) | ucp[3]));
        if (0 != format_code) 
            printf("        [Unexpected format code: %d]\n", format_code);
        printf("        relative port number (of target): 0x%x:\n",
               ((ucp[6] << 8) | ucp[7]));
        break;
    case 2: /* SSA */
        printf("        SSA:\n");
        printf("        format code: %d\n", format_code);
        dStrHex(ucp, len, 0);
        break;
    case 3: /* IEEE 1394 */
        printf("        IEEE 1394 EUI-64 name:\n");
        if (0 != format_code) 
            printf("        [Unexpected format code: %d]\n", format_code);
        dStrHex(&ucp[8], 8, 0);
        break;
    case 4: /* Remote Direct Memory Access (RDMA) */
        printf("        RDMA initiator port identifier:\n");
        if (0 != format_code) 
            printf("        [Unexpected format code: %d]\n", format_code);
        dStrHex(&ucp[8], 16, 0);
        break;
    case 5: /* iSCSI */
        printf("        iSCSI ");
        num = ((ucp[2] << 8) | ucp[3]);
        if (0 == format_code)
            printf("name: %.*s\n", num, &ucp[4]);
        else if (1 == format_code)
            printf("world wide unique port id: %.*s\n", num, &ucp[4]);
        else {
            printf("        [Unexpected format code: %d]\n", format_code);
            dStrHex(ucp, len, 0);
        }
        break;
    case 6: /* SAS */
        ull = 0;
        for (j = 0; j < 8; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= ucp[4 + j];
        }
        printf("        SAS address: 0x%llx\n", ull);
        if (0 != format_code) 
            printf("        [Unexpected format code: %d]\n", format_code);
        break;
    case 7: /* Automation/Drive Interface Transport Protocol */
        printf("        ADT:\n");
        printf("        format code: %d\n", format_code);
        dStrHex(ucp, len, 0);
        break;
    case 8: /* ATAPI */
        printf("        ATAPI:\n");
        printf("        format code: %d\n", format_code);
        dStrHex(ucp, len, 0);
        break;
    default:
        fprintf(stderr, "        unknown protocol id=0x%x  format_code=%d\n",
                proto_id, format_code);
        dStrHex(ucp, len, 0);
    }
}

static void dStrHex(const char* str, int len, int no_ascii)
{
    const char* p = str;
    unsigned char c;
    char buff[82];
    int a = 0;
    const int bpstart = 5;
    const int cpstart = 60;
    int cpos = cpstart;
    int bpos = bpstart;
    int i, k;
    
    if (len <= 0) return;
    memset(buff,' ',80);
    buff[80]='\0';
    k = sprintf(buff + 1, "%.2x", a);
    buff[k + 1] = ' ';
    if (bpos >= ((bpstart + (9 * 3))))
        bpos++;

    for(i = 0; i < len; i++)
    {
        c = *p++;
        bpos += 3;
        if (bpos == (bpstart + (9 * 3)))
            bpos++;
        sprintf(&buff[bpos], "%.2x", (int)(unsigned char)c);
        buff[bpos + 2] = ' ';
        if (no_ascii)
            buff[cpos++] = ' ';
        else {
            if ((c < ' ') || (c >= 0x7f))
                c='.';
            buff[cpos++] = c;
        }
        if (cpos > (cpstart+15))
        {
            printf("%s\n", buff);
            bpos = bpstart;
            cpos = cpstart;
            a += 16;
            memset(buff,' ',80);
            k = sprintf(buff + 1, "%.2x", a);
            buff[k + 1] = ' ';
        }
    }
    if (cpos > cpstart)
    {
        printf("%s\n", buff);
    }
}


int main(int argc, char * argv[])
{
    int sg_fd, k, j, num, c, add_len, prout_type, add_desc_len, rel_pt_addr;
    unsigned int pr_gen;
    unsigned long long ull;
    unsigned long long param_rk = 0;
    unsigned long long param_sark = 0;
    char device_name[256];
    char ebuff[EBUFF_SZ];
    const char * extra_args[MAX_EXTRA_ARGS];
    char inq_buff[36];
    unsigned char pr_buff[MX_ALLOC_LEN];
    unsigned char * ucp;
    int num_prin_sa = 0;
    int num_prout_sa = 0;
    int num_extra_args = 0;
    int want_prin = 0;
    int want_prout = 0;
    int prin = 1;
    int prin_sa = -1;
    int prout_sa = -1;
    int param_alltgpt = 0;
    int param_aptpl = 0;
    int do_inquiry = 1;
    int do_hex = 0;
    int do_verbose = 0;
    int peri_type = 0;
    int ret = 0;

    device_name[0] = '\0';
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "AcCd:GHiIhkK:LnoPrRsS:T:vV", 
                        long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'A':
            prout_sa = PROUT_PREE_AB_SA;
            ++num_prout_sa;
            break;
        case 'c':
            prin_sa = PRIN_RCAP_SA;
            ++num_prin_sa;
            break;
        case 'C':
            prout_sa = PROUT_CLEAR_SA;
            ++num_prout_sa;
            break;
        case 'd':
            strncpy(device_name, optarg, sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            break;
        case 'G':
            prout_sa = PROUT_REG_SA;
            ++num_prout_sa;
            break;
        case 'h':
            usage();
            return 0;
        case 'H':
            do_hex = 1;
            break;
        case 'i':
            want_prin = 1;
            break;
        case 'I':
            prout_sa = PROUT_REG_IGN_SA;
            ++num_prout_sa;
            break;
        case 'k':
            prin_sa = PRIN_RKEY_SA;
            ++num_prin_sa;
            break;
        case 'K':
            if (1 != sscanf(optarg, "%llx", &param_rk)) {
                fprintf(stderr, "bad argument to '--param-rk'\n");
                return 1;
            }
            break;
        case 'L':
            prout_sa = PROUT_REL_SA;
            ++num_prout_sa;
            break;
        case 'n':
            do_inquiry = 0;
            break;
        case 'o':
            want_prout = 1;
            break;
        case 'P':
            prout_sa = PROUT_PREE_SA;
            ++num_prout_sa;
            break;
        case 'r':
            prin_sa = PRIN_RRES_SA;
            ++num_prin_sa;
            break;
        case 'R':
            prout_sa = PROUT_RES_SA;
            ++num_prout_sa;
            break;
        case 's':
            prin_sa = PRIN_RFSTAT_SA;
            ++num_prin_sa;
            break;
        case 'S':
            if (1 != sscanf(optarg, "%llx", &param_sark)) {
                fprintf(stderr, "bad argument to '--param-sark'\n");
                return 1;
            }
            break;
        case 'T':
            if (1 != sscanf(optarg, "%x", &prout_type)) {
                fprintf(stderr, "bad argument to '--prout-type'\n");
                return 1;
            }
            break;
        case 'v':
            ++do_verbose;
            break;
        case 'V':
            fprintf(stderr, "version: %s\n", version_str);
            return 0;
        case 'Y':
            param_alltgpt = 1;
            break;
        case 'Z':
            param_aptpl = 1;
            break;
        case '?':
            usage();
            return 1;
        default:
            fprintf(stderr, "unrecognised switch "
                                "code 0x%x ??\n", c);
            usage();
            return 1;
        }
    }
    if (optind < argc) {
        if ('\0' == device_name[0]) {
            strncpy(device_name, argv[optind], sizeof(device_name) - 1);
            device_name[sizeof(device_name) - 1] = '\0';
            ++optind;
        }
        for (; optind < argc; ++optind, ++num_extra_args)
                extra_args[num_extra_args] = argv[optind];
    }

    if ('\0' == device_name[0]) {
        fprintf(stderr, "No device name given\n");
        usage();
        return 1;
    }
    if ((want_prout + want_prin) > 1) {
        fprintf(stderr, "choose '--in' _or_ '--out' (not both)\n");
        usage();
        return 1;
    } else if (want_prout) { /* syntax check on PROUT arguments */
        prin = 0;
        if ((1 != num_prout_sa) || (0 != num_prin_sa)) {
            fprintf(stderr, ">> For Persistent Reservation Out one and "
                    "only one appropriate\n>> service action must be "
                    "chosen (e.g. '--register')\n");
            return 1;
        }
        // syntax check on arguments
    } else { /* syntax check on PRIN arguments */
        if (num_prout_sa > 0) {
            fprintf(stderr, ">> When a service action for Persistent "
                    "Reservation Out is chosen the\n"
                    ">> '--out' option must be given (as a safeguard)\n");
            return 1;
        }
        if (0 == num_prin_sa) {
            fprintf(stderr, ">> No service action given; assume Persistent"
                    " Reservations In command\n"
                    ">> with Read Keys service action\n");
            prin_sa = 0;
            ++num_prin_sa;
        } else if (num_prin_sa > 1)  {
            fprintf(stderr, "Too many service actions given; choose "
                    "one only\n");
            usage();
            return 1;
        }
    }

    if (do_inquiry) {
        if ((sg_fd = open(device_name, O_RDONLY | O_NONBLOCK)) < 0) {
            snprintf(ebuff, EBUFF_SZ, "sg_persist: error opening file: %s "
                     " (ro)", device_name);
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
            printf("sg_persist: %s doesn't respond to a SCSI INQUIRY\n", 
                   device_name);
            return 1;
        }
        close(sg_fd);
    }

    if ((sg_fd = open(device_name, O_RDWR | O_NONBLOCK)) < 0) {
        snprintf(ebuff, EBUFF_SZ, "sg_persist: error opening file: %s (rw)",
                 device_name);
        perror(ebuff);
        return 1;
    }

    if (prin) {
        memset(pr_buff, 0, sizeof(pr_buff));
        if (0 != do_prin(sg_fd, prin_sa, pr_buff, 
                     sizeof(pr_buff), 1, do_verbose)) {
            return 1;
        }
        if (PRIN_RCAP_SA == prin_sa) {
            if (8 != pr_buff[1]) {
                fprintf(stderr, "Unexpected response for PRIN Report "
                        "Capabilities\n");
                return 1;
            }
            if (do_hex)
                dStrHex(pr_buff, 8, 1);
            else {
                printf("Report capabilities response:\n");
                printf("  Compatible Reservation handling(CRH): %d\n",
                       !!(pr_buff[2] & 0x10));
                printf("  Specify Initiator Ports capable(SIP_C): %d\n",
                       !!(pr_buff[2] & 0x8));
                printf("  All target ports capable(ATP_C): %d\n",
                       !!(pr_buff[2] & 0x4));
                printf("  Persist Through Power Loss capable(PTPL_C): %d\n",
                       !!(pr_buff[2] & 0x1));
                printf("  Type Mask Valid(TMV): %d\n",
                       !!(pr_buff[3] & 0x80));
                printf("  Persist Through Power Loss active(PTPL_A): %d\n",
                       !!(pr_buff[3] & 0x1));
                if (pr_buff[3] & 0x80) {
                    printf("    Support indicated in Type mask:\n");
                    printf("      %s: %d\n", pr_type_strs[7],
                           !!(pr_buff[4] & 0x80));
                    printf("      %s: %d\n", pr_type_strs[6],
                           !!(pr_buff[4] & 0x40));
                    printf("      %s: %d\n", pr_type_strs[5],
                           !!(pr_buff[4] & 0x20));
                    printf("      %s: %d\n", pr_type_strs[3],
                           !!(pr_buff[4] & 0x8));
                    printf("      %s: %d\n", pr_type_strs[1],
                           !!(pr_buff[4] & 0x2));
                    printf("      %s: %d\n", pr_type_strs[8],
                           !!(pr_buff[5] & 0x1));
                }
            }
        } else {
            pr_gen = ((pr_buff[0] << 24) | (pr_buff[1] << 16) | 
                      (pr_buff[2] << 8) | pr_buff[3]); 
            add_len = ((pr_buff[4] << 24) | (pr_buff[5] << 16) | 
                       (pr_buff[6] << 8) | pr_buff[7]); 
            if (do_hex) {
                if (add_len <= 0)
                    printf("Additional length=%d\n", add_len);
                if (add_len > (int)sizeof(pr_buff)) {
                    printf("Additional length too large=%d, truncate\n",
                           add_len);
                    dStrHex(pr_buff, sizeof(pr_buff), 1);
                } else
                    dStrHex(pr_buff, add_len, 1);
            } else if (PRIN_RKEY_SA == prin_sa) {
                printf("  PR generation=0x%x, ", pr_gen);
                num = add_len / 8;
                if (num > 0) {
                    printf("%d reservation keys follow:\n", num);
                    ucp = pr_buff + 8;
                    for (k = 0; k < num; ++k, ucp += 8) {
                        ull = 0;
                        for (j = 0; j < 8; ++j) {
                            if (j > 0)
                                ull <<= 8;
                            ull |= ucp[j];
                        }
                        printf("    0x%llx\n", ull);
                    }
                } else
                    printf("there are NO reservation keys\n");
            } else if (PRIN_RRES_SA == prin_sa) {
                printf("  PR generation=0x%x, ", pr_gen);
                num = add_len / 16;
                if (num > 0) {
                    printf("Reservation follows:\n");
                    ucp = pr_buff + 8;
                    ull = 0;
                    for (j = 0; j < 8; ++j) {
                        if (j > 0)
                            ull <<= 8;
                        ull |= ucp[j];
                    }
                    printf("    Key=0x%llx\n", ull);
                    j = ((ucp[13] >> 4) & 0xf);
                    if (0 == j)
                        printf("    scope: LU_SCOPE, ");
                    else
                        printf("    scope: %d ", j);
                    j = (ucp[13] & 0xf);
                    printf(" type: %s\n", pr_type_strs[j]);
                } else
                    printf("there is NO reservation held\n");
            } else if (PRIN_RFSTAT_SA == prin_sa) {
                printf("  PR generation=0x%x\n", pr_gen);
                ucp = pr_buff + 8;
                for (k = 0; k < add_len; k += num, ucp += num) {
                    add_desc_len = ((ucp[20] << 24) | (ucp[21] << 16) |
                                    (ucp[22] << 8) | ucp[23]);
                    num = 24 + add_desc_len;
                    ull = 0;
                    for (j = 0; j < 8; ++j) {
                        if (j > 0)
                            ull <<= 8;
                        ull |= ucp[j];
                    }
                    printf("    Key=0x%llx\n", ull);
                    if (ucp[12] & 0x2)
                        printf("      All target ports bit set\n");
                    else {
                        printf("      All target ports bit clear\n");
                        rel_pt_addr = ((ucp[18] << 8) | ucp[19]);
                        printf("      Relative port address: 0x%x\n", 
                               rel_pt_addr);
                    }
                    if (ucp[12] & 0x1) {
                        printf("      << Reservation holder >>\n");
                        j = ((ucp[13] >> 4) & 0xf);
                        if (0 == j)
                            printf("      scope: LU_SCOPE, ");
                        else
                            printf("      scope: %d ", j);
                        j = (ucp[13] & 0xf);
                        printf(" type: %s\n", pr_type_strs[j]);
                    } else
                        printf("      not reservation holder\n");
                    if (add_desc_len > 0)
                        decode_transport_id(&ucp[24], add_desc_len);
                }
            }
        }
    } else {    /* doing Persistent Reservation Out */
        memset(pr_buff, 0, sizeof(pr_buff));
        for (j = 7; j >= 0; --j) {
            pr_buff[j] = (param_rk & 0xff);
            param_rk >>= 8;
        }
        for (j = 7; j >= 0; --j) {
            pr_buff[8 + j] = (param_sark & 0xff);
            param_sark >>= 8;
        }
        if (param_alltgpt)
            pr_buff[20] |= 0x4;
        if (param_aptpl)
            pr_buff[20] |= 0x1;
        if (0 != do_prout(sg_fd, prout_sa, 0, (int)prout_type, pr_buff,
                          24, 1, do_verbose)) {
            return 1;
        } else if (do_verbose) {
            char buff[64];

            if (prout_sa < num_prout_sa_strs)
                strncpy(buff, prout_sa_strs[prout_sa], sizeof(buff));
            else
                snprintf(buff, sizeof(buff), "service action=0x%x", prout_sa);
            fprintf(stderr, "Persistent Reservation Out command (%s) "
                    "successful\n", buff);
        }
    }

    close(sg_fd);
    return ret;
}

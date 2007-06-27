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

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2000-2004 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI LOG SENSE command.
   
*/

static char * version_str = "0.29 20040602";

#define ME "sg_logs: "

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define LOG_SENSE_CMD     0x4d
#define LOG_SENSE_CMDLEN  10
#define MX_ALLOC_LEN (1024 * 17)
#define INQUIRY_CMD     0x12
#define INQUIRY_CMDLEN  6

#define PG_CODE_ALL 0x00

#define EBUFF_SZ 256

struct simple_inquiry_t {
    unsigned char peripheral_qualifier;
    unsigned char peripheral_type;
    unsigned char rmb;
    unsigned char version;	/* as per recent drafts: whole of byte 2 */
    unsigned char byte_3;
    unsigned char byte_5;
    unsigned char byte_6;
    unsigned char byte_7;
    char vendor[9];
    char product[17];
    char revision[5];
};

/* Call LOG SENSE twice: the first time ask for 4 byte response to determine
   actual length of response; then a second time requesting the
   min(actual_len, mx_resp_len) bytes. If the calculated length for the
   second fetch is odd then it is incremented (perhaps should be made modulo 4
   in the future for SAS). */
static int do_logs(int sg_fd, int ppc, int sp, int pc, int pg_code, 
                   int paramp, unsigned char * resp, int mx_resp_len, 
		   int noisy, int verbose)
{
    int res, k;
    unsigned char logsCmdBlk[LOG_SENSE_CMDLEN] = 
        {LOG_SENSE_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char logsCmdBlk2[LOG_SENSE_CMDLEN]; 
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    int actual_len;

    logsCmdBlk[1] = (unsigned char)((ppc ? 2 : 0) | (sp ? 1 : 0));
    logsCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    logsCmdBlk[5] = (unsigned char)((paramp >> 8) & 0xff);
    logsCmdBlk[6] = (unsigned char)(paramp & 0xff);
    if (mx_resp_len > 0xffff) {
        printf( ME "mx_resp_len too big\n");
        return -1;
    }
    memcpy(logsCmdBlk2, logsCmdBlk, sizeof(logsCmdBlk));
    logsCmdBlk[8] = 4;
    if (verbose) {
        fprintf(stderr, "        log sense cdb: ");
        for (k = 0; k < LOG_SENSE_CMDLEN; ++k)
            fprintf(stderr, "%02x ", logsCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    if (mx_resp_len > 3)
        memset(resp, 0, 4);

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(logsCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = 4;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = logsCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (log sense) error");
        return -1;
    }
#if 0
    printf("SG_IO ioctl: log_sense(short): status=%d, info=%d, sb_len_wr=%d\n", 
           io_hdr.status, io_hdr.info, io_hdr.sb_len_wr);
#endif
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        break;
    default:
        if (noisy) {
            char ebuff[EBUFF_SZ];
            snprintf(ebuff, EBUFF_SZ, ME "log_sense(short): ppc=%d, sp=%d, "
                     "pc=%d, page_code=%x, paramp=%x\n    ", ppc, sp, pc, 
                     pg_code, paramp);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
    actual_len = (resp[2] << 8) + resp[3] + 4;
    if (actual_len < 4)
        return 0;
    /* Some HBAs don't like odd transfer lengths */
    if (actual_len % 2)
	actual_len += 1;
    if (actual_len > mx_resp_len)
        actual_len = mx_resp_len;
    logsCmdBlk2[7] = (unsigned char)((actual_len >> 8) & 0xff);
    logsCmdBlk2[8] = (unsigned char)(actual_len & 0xff);
    if (verbose) {
        fprintf(stderr, "        log sense cdb: ");
        for (k = 0; k < LOG_SENSE_CMDLEN; ++k)
            fprintf(stderr, "%02x ", logsCmdBlk2[k]);
        fprintf(stderr, "\n");
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(logsCmdBlk2);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = actual_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = logsCmdBlk2;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (log sense) error");
        return -1;
    }
#if 0
    printf("SG_IO ioctl: log_sense: status=%d, info=%d, sb_len_wr=%d\n", 
           io_hdr.status, io_hdr.info, io_hdr.sb_len_wr);
#endif
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_ERR_CAT_CLEAN:
    case SG_ERR_CAT_RECOVERED:
        return 0;
    default:
        if (noisy) {
            char ebuff[EBUFF_SZ];
            snprintf(ebuff, EBUFF_SZ, ME "log_sense: ppc=%d, sp=%d, "
                     "pc=%d, page_code=%x, paramp=%x\n    ", ppc, sp, pc, 
                     pg_code, paramp);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

/* Returns 0 when successful, else -1 */
static int do_simple_inq(int sg_fd, int noisy, 
	                 struct simple_inquiry_t * inq_data, int verbose)
{
    int res, k;
    unsigned char inqCmdBlk[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;
    unsigned char inq_resp[36];

    if (inq_data) {
	memset(inq_data, 0, sizeof(* inq_data));
	inq_data->peripheral_qualifier = 0x3;
	inq_data->peripheral_type = 0x1f;
    }
    inqCmdBlk[4] = (unsigned char)sizeof(inq_resp);
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
    io_hdr.dxfer_len = sizeof(inq_resp);
    io_hdr.dxferp = inq_resp;
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
	if (inq_data) {
	    inq_data->peripheral_qualifier = (inq_resp[0] >> 5) & 0x7;
	    inq_data->peripheral_type = inq_resp[0] & 0x1f;
	    inq_data->rmb = (inq_resp[1] & 0x80) ? 1 : 0;
	    inq_data->version = inq_resp[2];
	    inq_data->byte_3 = inq_resp[3];
	    inq_data->byte_5 = inq_resp[5];
	    inq_data->byte_6 = inq_resp[6];
	    inq_data->byte_7 = inq_resp[7];
	    memcpy(inq_data->vendor, inq_resp + 8, 8);
	    memcpy(inq_data->product, inq_resp + 16, 16);
	    memcpy(inq_data->revision, inq_resp + 32, 4);
        }
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
    printf("Usage: 'sg_logs [-a] [-c=<page_control] [-h] [-l] "
           "[-p=<page_number>]\n                [-p=<page_number>] "
           " [-paramp=<parameter_pointer> [-ppc] [-sp]\n"
           "                [-t] [-v] [-V] <sg_device>'\n"
           " where -a   output all log pages\n"
           "       -c=<page_control> page control(PC) (default: 1)\n"
           "             (0 [current threshhold], 1 [current cumulative]\n"
           "              2 [default threshhold], 3 [default cumulative])\n"
           "       -h   output in hex\n"
           "       -l   list supported log page names\n"
           "       -p=<page_code> page code (in hex)\n"
           "       -paramp=<parameter_pointer> (in hex) (def: 0)\n"
           "       -pcb show parameter control bytes (ignored if -h given)\n"
           "       -ppc set the Parameter Pointer Control (PPC) bit (def: 0)\n"
           "       -sp  set the Saving Parameters (SP) bit (def: 0)\n"
           "       -t   outputs temperature log page (0xd)\n"
           "       -v   verbose: output cdbs prior to execution\n"
           "       -V   output version string\n"
           "       -?   output this usage message\n");
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

static void show_page_name(int page_no, struct simple_inquiry_t * inq_dat)
{
    int done;

    /* first process log pages that do not depend on peripheral type */
    done = 1;
    switch (page_no) {
    case 0x0 : printf("    0x00    Supported log pages\n"); break;
    case 0x1 : printf("    0x01    Buffer over-run/under-run\n"); break;
    case 0x2 : printf("    0x02    Error counters (write)\n"); break;
    case 0x3 : printf("    0x03    Error counters (read)\n"); break;
    case 0x4 : printf("    0x04    Error counters (read reverse)\n"); break;
    case 0x5 : printf("    0x05    Error counters (verify)\n"); break;
    case 0x6 : printf("    0x06    Non-medium errors\n"); break;
    case 0x7 : printf("    0x07    Last n error events\n"); break;
    case 0xb : printf("    0x0b    Last n deferred errors of "
                "asynchronous events\n"); break;
    case 0xd : printf("    0x0d    Temperature\n"); break;
    case 0xe : printf("    0x0e    Start-stop cycle counter\n"); break;
    case 0xf : printf("    0x0f    Application client\n"); break;
    case 0x10 : printf("    0x10    Self-test results\n"); break;
    case 0x18 : printf("    0x18    Protocol specific port\n"); break;
    case 0x2f : printf("    0x2f    Informational exceptions (SMART)\n"); break;
    default : done = 0; break;
    }
    if (done)
	return;

    done = 1;
    switch (inq_dat->peripheral_type) {
    case 0: case 4: case 7: case 0xe:
        /* disk (direct access) type devices */
	{
	    switch (page_no) {
	    case 0x8 : printf("    0x08    Format status (sbc2)\n"); break;
	    case 0x37 : printf("    0x37    Cache (Seagate)\n"); break;
	    case 0x3e : printf("    0x3e    Factory (Seagate)\n"); break;
	    default: done = 0; break;
            }
	}
	break;
    case 1: case 2: case 8:
        /* tape (streaming) and medium changer type devices */
	{
	    switch (page_no) {
	    case 0xc : printf("    0x0c    Sequential Access (ssc-2)\n"); break;
	    case 0x2e : printf("    0x2e    Tape alerts (ssc-2)\n"); break;
	    default: done = 0; break;
	    }
        }
    default: done = 0; break;
    }
    if (done)
	return;

    printf("    0x%.2x    ??\n", page_no);
}

static void get_pcb_str(int pcb, char * outp, int maxoutlen)
{
    char buff[128];
    int n;

    n = sprintf(buff, "du=%d ds=%d tsd=%d etc=%d ", ((pcb & 0x80) ? 1 : 0),
                ((pcb & 0x40) ? 1 : 0), ((pcb & 0x20) ? 1 : 0), 
                ((pcb & 0x10) ? 1 : 0));
    if (pcb & 0x10)
        n += sprintf(buff + n, "tmc=%d ", ((pcb & 0xc) >> 2));
    if (pcb & 0x1)
        n += sprintf(buff + n, "lbin=%d ", ((pcb & 0x2) >> 1));
    n += sprintf(buff + n, "lp=%d  [0x%.2x]", pcb & 0x1, pcb);
    if (outp && (n < maxoutlen)) {
        memcpy(outp, buff, n);
        outp[n] = '\0';
    } else if (outp && (maxoutlen > 0))
        outp[0] = '\0';
}

static void show_buffer_under_overrun_page(unsigned char * resp, int len,
                                           int show_pcb)
{
    int k, j, num, pl, count_basis, cause, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[64];

    printf("Buffer over-run/under-run page\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pl = ucp[3] + 4;
        count_basis = (ucp[1] >> 5) & 0x7;
        printf("  Count basis: ");
        switch (count_basis) {
        case 0 : printf("undefined"); break;
        case 1 : printf("per command"); break;
        case 2 : printf("per failed reconnect"); break;
        case 3 : printf("per unit of time"); break;
        default: printf("reserved [0x%x]", count_basis); break;
        }
        cause = (ucp[1] >> 1) & 0xf;
        printf(", Cause: ");
        switch (cause) {
        case 0 : printf("undefined"); break;
        case 1 : printf("bus busy"); break;
        case 2 : printf("transfer rate too slow"); break;
        default: printf("reserved [0x%x]", cause); break;
        }
        printf(", Type: ");
        if (ucp[1] & 1)
            printf("over-run");
        else
            printf("under-run");
        pcb = ucp[2];
        printf(", count");
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %llu", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_error_counter_page(unsigned char * resp, int len, 
                                    int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[64];

    switch(resp[0]) {
    case 2:
        printf("Write error counter page\n");
        break;
    case 3:
        printf("Read error counter page\n");
        break;
    case 4:
        printf("Read Reverse error counter page\n");
        break;
    case 5:
        printf("Verify error counter page\n");
        break;
    default:
        printf("expecting error counter page, got page = 0x%x\n", resp[0]);
        return;
    }
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0: printf("  Errors corrected without substantion delay"); break;
        case 1: printf("  Errors corrected with possible delays"); break;
        case 2: printf("  Total operations"); break;
        case 3: printf("  Total errors corrected"); break;
        case 4: printf("  Total times correction algorithm processed"); break;
        case 5: printf("  Total bytes processed"); break;
        case 6: printf("  Total uncorrected errors"); break;
        default: printf("  Reserved or vendor specific [0x%x]", pc); break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %llu", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_non_medium_error_page(unsigned char * resp, int len,
                                       int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[64];

    printf("Non-medium error page\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Non-medium error count"); break;
        default: 
            if (pc <= 0x7fff)
                printf("  Reserved [0x%x]", pc);
            else
                printf("  Vendor specific [0x%x]", pc);
            break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %llu", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

const char * self_test_code[] = {
    "default", "background short", "background extended", "reserved",
    "aborted background", "foreground short", "foreground extended",
    "reserved"};

const char * self_test_result[] = {
    "completed without error", 
    "aborted by SEND DIAGNOSTIC", 
    "aborted other than by SEND DIAGNOSTIC", 
    "unknown error, unable to complete", 
    "self test completed with failure in test segment (which one unkown)", 
    "first segment in self test failed", 
    "second segment in self test failed", 
    "another segment in self test failed", 
    "reserved", "reserved", "reserved", "reserved", "reserved", "reserved",
    "reserved",
    "self test in progress"};

static void show_self_test_page(unsigned char * resp, int len, int show_pcb)
{
    int k, num, n, res, pcb;
    unsigned char * ucp;
    unsigned long long ull;
    char pcb_str[64];

    num = len - 4;
    if (num < 0x190) {
        printf("short self-test results page [length 0x%x rather than "
               "0x190 bytes]\n", num);
        return;
    }
    printf("Self-test results page\n");
    for (k = 0, ucp = resp + 4; k < 20; ++k, ucp += 20 ) {
        pcb = ucp[2];
        n = (ucp[6] << 8) | ucp[7];
        if ((0 == n) && (0 == ucp[4]))
            break;
        printf("  Parameter code = %d, accumulated power-on hours = %d\n",
               (ucp[0] << 8) | ucp[1], n);
        printf("    self-test code: %s [%d]\n",
               self_test_code[(ucp[4] >> 5) & 0x7], (ucp[4] >> 5) & 0x7);
        res = ucp[4] & 0xf;
        printf("    self-test result: %s [%d]\n",
               self_test_result[res], res);
        if (ucp[5])
            printf("    self-test number = %d\n", (int)ucp[5]);
        ull = ucp[8]; ull <<= 8; ull |= ucp[9]; ull <<= 8; ull |= ucp[10];
        ull <<= 8; ull |= ucp[11]; ull <<= 8; ull |= ucp[12];
        ull <<= 8; ull |= ucp[13]; ull <<= 8; ull |= ucp[14];
        ull <<= 8; ull |= ucp[15];
        if ((0xffffffffffffffffULL != ull) && (res > 0) && ( res < 0xf))
            printf("    address of first error = 0x%llx\n", ull);
        if (ucp[16] & 0xf)
            printf("    sense key = 0x%x, asc = 0x%x, asq = 0x%x",
                   ucp[16] & 0xf, ucp[17], ucp[18]);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_Temperature_page(unsigned char * resp, int len, 
                                  int show_pcb, int hdr)
{
    int k, num, extra, pc, pcb;
    unsigned char * ucp;
    char pcb_str[64];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed Temperature log page\n");
        return;
    }
    if (hdr)
        printf("Temperature log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Temperature log page\n");
            return;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (0 == pc) {
            if (extra > 5) {
                if (ucp[5] < 0xff)
                    printf("  Current temperature = %d C", ucp[5]);
                else
                    printf("  Current temperature = <not available>");
            }
        } else if (1 == pc) {
            if (extra > 5) {
                if (ucp[5] < 0xff)
                    printf("  Reference temperature = %d C", ucp[5]);
                else
                    printf("  Reference temperature = <not available>");
            }

        } else {
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_Start_Stop_page(unsigned char * resp, int len, int show_pcb)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    unsigned char * ucp;
    char pcb_str[64];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed Start-stop cycle counter log page\n");
        return;
    }
    printf("Start-stop cycle counter log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Start-stop cycle counter log page\n");
            return;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        switch (pc) {
        case 1:
            if (extra > 9)
                printf("  Date of manufacture, year: %.4s, week: %.2s", 
                       &ucp[4], &ucp[8]); 
            break;
        case 2:
            if (extra > 9)
                printf("  Accounting date, year: %.4s, week: %.2s", 
                       &ucp[4], &ucp[8]); 
            break;
        case 3:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                printf("  Specified cycle count over device lifetime = %u", 
                       n);
            }
            break;
        case 4:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                printf("  Accumulated start-stop cycles = %u", n);
            }
            break;
        default:
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_IE_page(unsigned char * resp, int len, int show_pcb, int full)
{
    int k, num, extra, pc, pcb;
    unsigned char * ucp;
    char pcb_str[64];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("badly formed Informational Exceptions log page\n");
        return;
    }
    if (full)
        printf("Informational Exceptions log page\n");
    for (k = num; k > 0; k -= extra, ucp += extra) {
        if (k < 3) {
            printf("short Informational Exceptions log page\n");
            return;
        }
        extra = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        if (0 == pc) {
            if (extra > 5) {
                if (full)
                    printf("  IE asc = 0x%x, ascq = 0x%x", ucp[4], ucp[5]); 
                if (extra > 6) {
                    if (ucp[6] < 0xff)
                        printf("\n  Current temperature = %d C", ucp[6]);
                    else
                        printf("\n  Current temperature = <not available>");
                    if (extra > 7) {
                        if (ucp[7] < 0xff)
                            printf("\n  Threshold temperature = %d C  [IBM "
                                   "extension]", ucp[7]);
                        else
                            printf("\n  Treshold temperature = <not "
                                   "available>");
                     }
                }
            }
        } else if (full) {
            printf("  parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static int show_protocol_specific_page(unsigned char * resp, int len, 
				       int show_pcb)
{
    int k, j, num, param_len, nphys, pcb, t, sz;
    unsigned char * ucp;
    unsigned char * vcp;
    unsigned long long ull;
    unsigned long ul;
    char pcb_str[64];
    char s[64];

    sz = sizeof(s);
    num = len - 4;
    for (k = 0, ucp = resp + 4; k < num; ) {
        pcb = ucp[2];
	param_len = ucp[3] + 4;
	/* each phy has a 48 byte descriptor but since param_len is
	   an 8 bit quantity then only the first 5 phys (of, for example,
	   a 8 phy wide link) can be represented */
	if (6 != (0xff & ucp[4]))
	    return 0;	/* only decode SAS log page */
	printf("SAS Protocol Specific page\n");
        printf("relative target port id=%d\n", (ucp[0] << 8) | ucp[1]);
	nphys = ucp[7];
	printf("number of phys = %d\n", nphys);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");

	for (j = 0, vcp = ucp + 8; j < (param_len - 8); vcp += 48, j += 48 ) {
	    printf("  phy identifier = %d\n", vcp[1]);
	    t = ((0x70 & vcp[4]) >> 4);
	    switch (t) {
	    case 0: snprintf(s, sz, "no device attached"); break;
	    case 1: snprintf(s, sz, "end device"); break;
	    case 2: snprintf(s, sz, "edge expander device"); break;
	    case 3: snprintf(s, sz, "fanout expander device"); break;
	    default: snprintf(s, sz, "reserved [%d]", t); break;
	    }
	    printf("    attached device type: %s\n", s);
	    t = (0xf & vcp[5]);
	    switch (t) {
	    case 0: snprintf(s, sz, "phy enabled; unknown");
			 break;
	    case 1: snprintf(s, sz, "phy disabled"); break;
	    case 2: snprintf(s, sz, "phy enabled; speed negotiation failed");
			 break;
	    case 3: snprintf(s, sz, "phy enabled; SATA spinup hold state");
			 break;
	    case 8: snprintf(s, sz, "phy enabled; 1.5Gbps"); break;
	    case 9: snprintf(s, sz, "phy enabled; 3.0Gbps"); break;
	    default: snprintf(s, sz, "reserved [%d]", t); break;
	    }
	    printf("    negotiated physical link rate: %s\n", s);
	    printf("    attached initiator port: ssp=%d, stp=%d smp=%d\n",
		   !! (vcp[6] & 8), !! (vcp[6] & 4), (vcp[6] & 2));
	    printf("    attached target port: ssp=%d, stp=%d smp=%d\n",
		   !! (vcp[7] & 8), !! (vcp[7] & 4), (vcp[7] & 2));
            ull = vcp[8]; ull <<= 8; ull |= vcp[9]; ull <<= 8; ull |= vcp[10];
            ull <<= 8; ull |= vcp[11]; ull <<= 8; ull |= vcp[12];
            ull <<= 8; ull |= vcp[13]; ull <<= 8; ull |= vcp[14];
            ull <<= 8; ull |= vcp[15];
            printf("    SAS address = 0x%llx\n", ull);
            ull = vcp[16]; ull <<= 8; ull |= vcp[17]; ull <<= 8; ull |= vcp[18];
            ull <<= 8; ull |= vcp[19]; ull <<= 8; ull |= vcp[20];
            ull <<= 8; ull |= vcp[21]; ull <<= 8; ull |= vcp[22];
            ull <<= 8; ull |= vcp[23];
            printf("    attached SAS address = 0x%llx\n", ull);
	    printf("    attached phy identifier = %d\n", vcp[24]);
	    ul = (vcp[32] << 24) | (vcp[33] << 16) | (vcp[34] << 8) | vcp[35];
            printf("    Invalid DWORD count = %ld\n", ul);
	    ul = (vcp[36] << 24) | (vcp[37] << 16) | (vcp[38] << 8) | vcp[39];
            printf("    Running disparity error count = %ld\n", ul);
	    ul = (vcp[40] << 24) | (vcp[41] << 16) | (vcp[42] << 8) | vcp[43];
            printf("    Loss of DWORD synchronization = %ld\n", ul);
	    ul = (vcp[44] << 24) | (vcp[45] << 16) | (vcp[46] << 8) | vcp[47];
            printf("    Phy reset problem = %ld\n", ul);
	}
	k += param_len;
	ucp += param_len;
    }
    return 1;
}

static void show_seagate_cache_page(unsigned char * resp, int len, 
                                    int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[64];

    printf("Seagate cache page [0x37]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0: printf("  Blocks sent to initiator"); break;
        case 1: printf("  Blocks received from initiator"); break;
        case 2: printf("  Blocks read from cache and sent to initiator"); break;
        case 3: printf("  Number of read and write commands whose size "
                       "<= segment size"); break;
        case 4: printf("  Number of read and write commands whose size "
                       "> segment size"); break;
        default: printf("  Unknown Seagate parameter code = 0x%x", pc); break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        printf(" = %llu", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_seagate_factory_page(unsigned char * resp, int len,
                                      int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[64];

    printf("Seagate factory page [0x3e]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0: printf("  number of hours powered up"); break;
        case 8: printf("  number of minutes until next internal SMART test");
            break;
        default: printf("  Unknown Seagate parameter code = 0x%x", pc); break;
        }
        k = pl - 4;
        xp = ucp + 4;
        if (k > (int)sizeof(ull)) {
            xp += (k - sizeof(ull));
            k = sizeof(ull);
        }
        ull = 0;
        for (j = 0; j < k; ++j) {
            if (j > 0)
                ull <<= 8;
            ull |= xp[j];
        }
        if (0 == pc)
            printf(" = %.2f", ((double)ull) / 60.0 );
        else
            printf(" = %llu", ull);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("  <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_ascii_page(unsigned char * resp, int len, int show_pcb, 
			    struct simple_inquiry_t * inq_dat)
{
    int k, num, done;

    if (len < 0) {
        printf("response has bad length\n");
        return;
    }
    num = len - 4;
    done = 1;
    switch (resp[0]) {
    case 0:
        printf("Supported pages:\n");
        for (k = 0; k < num; ++k)
            show_page_name((int)resp[4 + k], inq_dat);
        break;
    case 0x1:
        show_buffer_under_overrun_page(resp, len, show_pcb);
        break;
    case 0x2:
    case 0x3:
    case 0x4:
    case 0x5:
        show_error_counter_page(resp, len, show_pcb);
        break;
    case 0x6:
        show_non_medium_error_page(resp, len, show_pcb);
        break;
    case 0xd:
        show_Temperature_page(resp, len, show_pcb, 1);
        break;
    case 0xe:
        show_Start_Stop_page(resp, len, show_pcb);
        break;
    case 0x10:
        show_self_test_page(resp, len, show_pcb);
        break;
    case 0x18:
        done = show_protocol_specific_page(resp, len, show_pcb);
        break;
    case 0x2f:
        show_IE_page(resp, len, show_pcb, 1);
        break;
    case 0x37:
	{
	    switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_seagate_cache_page(resp, len, show_pcb);
                break;
	    default:
		done = 0;
		break;
	    }
	}
	break;
    case 0x3e:
	{
	    switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_seagate_factory_page(resp, len, show_pcb);
		break;
	    case 1: case 2: case 8:
                /* streaming or medium changer devices */
		// call ssc_device_status_log_page()
		break;
	    default:
		done = 0;
		break;
	    }
        }
        break;
    default:
	done = 0;
        break;
    }
    if (! done) {
        printf("No ascii information for page = 0x%x, here is hex:\n", 
               resp[0]);
        if (len > 128) {
            dStrHex((const char *)resp, 64, 1);
            printf(" .....  [truncated after 64 of %d bytes (use '-h' to "
                   "see the rest)]\n", len);
        }
        else
            dStrHex((const char *)resp, len, 1);
    }
}
        
static int fetchTemperature(int sg_fd, unsigned char * resp, int max_len,
			    int verbose)
{
    int res = 0;

    if (0 == do_logs(sg_fd, 0, 0, 1, 0xd, 0, resp, max_len, 0, verbose))
        show_Temperature_page(resp, (resp[2] << 8) + resp[3] + 4, 0, 0);
    else if (0 == do_logs(sg_fd, 0, 0, 1, 0x2f, 0, resp, max_len, 0, verbose))
        show_IE_page(resp, (resp[2] << 8) + resp[3] + 4, 0, 0);
    else {
        printf("Unable to find temperature in either log page (temperature "
               "or IE)\n");
        res = 1;
    }
    close(sg_fd);
    return res;
}


int main(int argc, char * argv[])
{
    int sg_fd, k, num, pg_len;
    char * file_name = 0;
    char ebuff[EBUFF_SZ];
    unsigned char rsp_buff[MX_ALLOC_LEN];
    unsigned int u;
    int pg_code = 0;
    int pc = 1; /* N.B. some disks only give data for current cumulative */
    int paramp = 0;
    int do_list = 0;
    int do_pcb = 0;
    int do_ppc = 0;
    int do_sp = 0;
    int do_hex = 0;
    int do_all = 0;
    int do_temp = 0;
    int do_verbose = 0;
    int oflags = O_RDWR | O_NONBLOCK;
    int oroflags = O_RDONLY | O_NONBLOCK;
    struct simple_inquiry_t inq_out;

    for (k = 1; k < argc; ++k) {
        if (0 == strncmp("-p=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (u > 63)) {
                printf("Bad page code after '-p' switch [0..63]\n");
                file_name = 0;
                break;
            }
            pg_code = u;
        }
        else if (0 == strncmp("-c=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (u > 3)) {
                printf("Bad page control after '-c' switch [0..3]\n");
                file_name = 0;
                break;
            }
            pc = u;
        }
        else if (0 == strncmp("-paramp=", argv[k], 8)) {
            num = sscanf(argv[k] + 8, "%x", &u);
            if ((1 != num) || (u > 0xffff)) {
                printf("Bad parameter pointer after '-paramp' switch\n");
                file_name = 0;
                break;
            }
            paramp = u;
        }
        else if (0 == strcmp("-l", argv[k]))
            do_list = 1;
        else if (0 == strcmp("-pcb", argv[k]))
            do_pcb = 1;
        else if (0 == strcmp("-ppc", argv[k]))
            do_ppc = 1;
        else if (0 == strcmp("-sp", argv[k]))
            do_sp = 1;
        else if (0 == strcmp("-a", argv[k]))
            do_all = 1;
        else if (0 == strcmp("-t", argv[k]))
            do_temp = 1;
        else if (0 == strcmp("-h", argv[k]))
            do_hex = 1;
        else if (0 == strcmp("-v", argv[k]))
            ++do_verbose;
        else if (0 == strcmp("-?", argv[k])) {
            file_name = 0;
            break;
        }
        else if (0 == strcmp("-V", argv[k])) {
            printf("Version string: %s\n", version_str);
            exit(0);
        }
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
        usage();
        return 1;
    }

    if ((sg_fd = open(file_name, oflags)) < 0) {
        if ((sg_fd = open(file_name, oroflags)) < 0) {
            snprintf(ebuff, EBUFF_SZ, ME "error opening file: %s", file_name);
            perror(ebuff);
            return 1;
	}
    }
    if (do_list || do_all)
        pg_code = PG_CODE_ALL;
    pg_len = 0;

    if (do_simple_inq(sg_fd, 1, &inq_out, do_verbose))
	printf(ME "%s doesn't respond to a SCSI INQUIRY\n", file_name);
    else
	printf("    %.8s  %.16s  %.4s\n", inq_out.vendor, inq_out.product,
	       inq_out.revision);

    if (1 == do_temp)
        return fetchTemperature(sg_fd, rsp_buff, MX_ALLOC_LEN, do_verbose);

    if (0 == do_logs(sg_fd, do_ppc, do_sp, pc, pg_code, paramp,
                     rsp_buff, MX_ALLOC_LEN, 1, do_verbose))
    {
        pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
        if ((pg_len + 4) > MX_ALLOC_LEN) {
            printf("Only fetched %d bytes of response, truncate output\n",
                   MX_ALLOC_LEN);
            pg_len = MX_ALLOC_LEN - 4;
        }
        if (do_hex) {
            printf("Returned log page code=0x%x,  page len=0x%x\n", 
                   rsp_buff[0], pg_len);
            dStrHex((const char *)rsp_buff, pg_len + 4, 1);
        }
        else
            show_ascii_page(rsp_buff, pg_len + 4, do_pcb, &inq_out);
    }
    if (do_all && (pg_len > 1)) {
        int my_len = pg_len - 1;
        unsigned char parr[256];

        memcpy(parr, rsp_buff + 5, my_len);
        for (k = 0; k < my_len; ++k) {
            printf("\n");
            pg_code = parr[k];
            if (0 == do_logs(sg_fd, do_ppc, do_sp, pc, pg_code, paramp,
                             rsp_buff, MX_ALLOC_LEN, 1, do_verbose))
            {
                pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
                if ((pg_len + 4) > MX_ALLOC_LEN) {
                    printf("Only fetched %d bytes of response, truncate "
                           "output\n", MX_ALLOC_LEN);
                    pg_len = MX_ALLOC_LEN - 4;
                }
                if (do_hex) {
                    printf("Returned log page code=0x%x,  page len=0x%x\n", 
                           rsp_buff[0], pg_len);
                    dStrHex((const char *)rsp_buff, pg_len + 4, 1);
                }
                else
                    show_ascii_page(rsp_buff, pg_len + 4, do_pcb, &inq_out);
            }
        }
    }
    close(sg_fd);
    return 0;
}

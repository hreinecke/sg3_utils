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
*  Copyright (C) 2000-2003 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI LOG SENSE command.
   
*/

static char * version_str = "0.21 20030513";

#define ME "sg_logs: "

/* #define SG_DEBUG */

#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define LOG_SENSE_CMD     0x4d
#define LOG_SENSE_CMDLEN  10
#define MX_ALLOC_LEN (1024 * 17)

#define PG_CODE_ALL 0x00

#define EBUFF_SZ 256


static int do_logs(int sg_fd, int ppc, int sp, int pc, int pg_code, 
		   int paramp, void * resp, int mx_resp_len, int noisy)
{
    int res;
    unsigned char logsCmdBlk[LOG_SENSE_CMDLEN] = 
    	{LOG_SENSE_CMD, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    sg_io_hdr_t io_hdr;

    logsCmdBlk[1] = (unsigned char)((ppc ? 2 : 0) | (sp ? 1 : 0));
    logsCmdBlk[2] = (unsigned char)(((pc << 6) & 0xc0) | (pg_code & 0x3f));
    logsCmdBlk[5] = (unsigned char)((paramp >> 8) & 0xff);
    logsCmdBlk[6] = (unsigned char)(paramp & 0xff);
    if (mx_resp_len > 0xffff) {
    	printf( ME "mx_resp_len too big\n");
	return -1;
    }
    logsCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    logsCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);

    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(logsCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = logsCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (log sense) error");
        return -1;
    }
#if 0
    printf("SG_IO ioctl: status=%d, info=%d, sb_len_wr=%d\n", 
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
	    snprintf(ebuff, EBUFF_SZ, ME "ppc=%d, sp=%d, "
	    	     "pc=%d, page_code=%x, paramp=%x\n    ", ppc, sp, pc, 
		     pg_code, paramp);
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
	   "                [-t] [-V] <sg_device>'\n"
	   " where -a   output all log pages\n"
	   "       -c=<page_control> page control(PC) (default: 1)\n"
	   "             (0 [current threshhold], 1 [current cumulative]\n"
	   "              2 [default threshhold], 3 [default cumulative])\n"
	   "       -h   output in hex\n"
	   "       -l   list supported log page names\n"
	   "       -p=<page_code> page code (in hex)\n"
	   "       -paramp=<parameter_pointer> (in hex) (def: 0)\n"
	   "       -ppc set the Parameter Pointer Control (PPC) bit (def: 0)\n"
	   "       -sp  set the Saving Parameters (SP) bit (def: 0)\n"
	   "       -t   outputs temperature log page (0xd)\n"
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

static void show_page_name(int page_no)
{
    switch (page_no) {
    case 0x0 : printf("    0x00    Supported log pages\n"); break;
    case 0x1 : printf("    0x01    Buffer over-run/under-run\n"); break;
    case 0x2 : printf("    0x02    Error counters (write)\n"); break;
    case 0x3 : printf("    0x03    Error counters (read)\n"); break;
    case 0x4 : printf("    0x04    Error counters (read reverse)\n"); break;
    case 0x5 : printf("    0x05    Error counters (verify)\n"); break;
    case 0x6 : printf("    0x06    Non-medium errors\n"); break;
    case 0x7 : printf("    0x07    Last n error events\n"); break;
    case 0x8 : printf("    0x08    Format status (sbc2)\n"); break;
    case 0xb : printf("    0x0b    Last n deferred errors of "
		"asynchronous events\n"); break;
    case 0xc : printf("    0x0c    Sequential Access (ssc-2)\n"); break;
    case 0xd : printf("    0x0d    Temperature\n"); break;
    case 0xe : printf("    0x0e    Start-stop cycle counter\n"); break;
    case 0xf : printf("    0x0f    Application client\n"); break;
    case 0x10 : printf("    0x10    Self-test results\n"); break;
    case 0x18 : printf("    0x18    Protocol specific port\n"); break;
    case 0x2e : printf("    0x2e    Tape alerts (ssc-2)\n"); break;
    case 0x2f : printf("    0x2f    Informational exceptions (SMART)\n"); break;
    default: printf("    0x%.2x\n", page_no); break;
    }
}

static void show_buffer_under_overrun_page(unsigned char * resp, int len)
{
    int k, j, num, pl, count_basis, cause;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;

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
	case 0 : printf("bus busy"); break;
	case 1 : printf("transfer rate too slow"); break;
	default: printf("reserved [0x%x]", cause); break;
	}
	printf(", Type: ");
	if (ucp[1] & 1)
	    printf("over-run");
	else
	    printf("under-run");
	printf(", count");
	k = pl - 4;
	xp = ucp + 4;
	if (k > sizeof(ull)) {
	    xp += (k - sizeof(ull));
	    k = sizeof(ull);
	}
	ull = 0;
	for (j = 0; j < k; ++j) {
	    if (j > 0)
	    	ull <<= 8;
	    ull |= xp[j];
	}
	printf(" = %llu\n", ull);
	num -= pl;
	ucp += pl;
    }
}

static void show_error_counter_page(unsigned char * resp, int len)
{
    int k, j, num, pl, pc;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;

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
    	printf("expecting error counter page, got page=0x%x\n", resp[0]);
	return;
    }
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
    	pc = (ucp[0] << 8) | ucp[1];
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
	if (k > sizeof(ull)) {
	    xp += (k - sizeof(ull));
	    k = sizeof(ull);
	}
	ull = 0;
	for (j = 0; j < k; ++j) {
	    if (j > 0)
	    	ull <<= 8;
	    ull |= xp[j];
	}
	printf(" = %llu\n", ull);
	num -= pl;
	ucp += pl;
    }
}

static void show_non_medium_error_page(unsigned char * resp, int len)
{
    int k, j, num, pl, pc;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;

    printf("Non-medium error page\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
    	pc = (ucp[0] << 8) | ucp[1];
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
	if (k > sizeof(ull)) {
	    xp += (k - sizeof(ull));
	    k = sizeof(ull);
	}
	ull = 0;
	for (j = 0; j < k; ++j) {
	    if (j > 0)
	    	ull <<= 8;
	    ull |= xp[j];
	}
	printf(" = %llu\n", ull);
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

static void show_self_test_page(unsigned char * resp, int len)
{
    int k, num, n, res;
    unsigned char * ucp;
    unsigned long long ull;

    num = len - 4;
    if (num < 0x190) {
	printf("badly formed self-test results page\n");
	return;
    }
    printf("Self-test results page\n");
    for (k = 0, ucp = resp + 4; k < 20; ++k, ucp += 20 ) {
	n = (ucp[6] << 8) | ucp[7];
	if ((0 == n) && (0 == ucp[4]))
	    break;
	printf("  Parameter code=%d, accumulated power-on hours=%d\n",
	       (ucp[0] << 8) | ucp[1], n);
	printf("    self test code: %s [%d]\n",
	       self_test_code[(ucp[4] >> 5) & 0x7], (ucp[4] >> 5) & 0x7);
	res = ucp[4] & 0xf;
	printf("    self test result: %s [%d]\n",
	       self_test_result[res], res);
	if (ucp[5])
	    printf("    self-test number=%d\n", (int)ucp[5]);
	ull = ucp[8]; ull <<= 8; ull |= ucp[9]; ull <<= 8; ull |= ucp[10];
	ull <<= 8; ull |= ucp[11]; ull <<= 8; ull |= ucp[12];
	ull <<= 8; ull |= ucp[13]; ull <<= 8; ull |= ucp[14];
	ull <<= 8; ull |= ucp[14]; ull <<= 8; ull |= ucp[15];
	if ((0xffffffffffffffffULL != ull) && (res > 0) && ( res < 0xf))
	    printf("    address of first error=0x%llx\n", ull);
	if (ucp[16] & 0xf)
	    printf("    sense key=0x%x, asc=0x%x, asq=0x%x\n",
		   ucp[16] & 0xf, ucp[17], ucp[18]);
    }
}

static void show_Temperature_page(unsigned char * resp, int len, int hdr)
{
    int k, num, extra, pc;
    unsigned char * ucp;

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
	pc = ((ucp[0] << 8) & 0xff) + ucp[1];
	if (0 == pc) {
	    if (extra > 5) {
		if (ucp[5] < 0xff)
		    printf("  Current temperature= %d C\n", ucp[5]);
		else
		    printf("  Current temperature=<not available>\n");
	    }
	} else if (1 == pc) {
	    if (extra > 5) {
		if (ucp[5] < 0xff)
		    printf("  Reference temperature= %d C\n", ucp[5]);
		else
		    printf("  Reference temperature=<not available>\n");
	    }

	}else {
	    printf("  parameter code=0x%x, contents in hex:\n", pc);
	    dStrHex((const char *)ucp, extra, 1);
	}
    }
}

static void show_IE_page(unsigned char * resp, int len, int full)
{
    int k, num, extra, pc;
    unsigned char * ucp;

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
	pc = ((ucp[0] << 8) & 0xff) + ucp[1];
	if (0 == pc) {
	    if (extra > 5) {
		if (full)
	            printf("  IE asc=0x%x, ascq=0x%x", ucp[4], ucp[5]); 
	        if (extra > 6) {
		    if (full)
		        printf(",");
		    if (ucp[6] < 0xff)
	                printf("  Current temperature=%d C", ucp[6]);
		    else
	                printf("  Current temperature=<not available>");
		}
	        printf("\n");
	    }
	} else if (full) {
	    printf("  parameter code=0x%x, contents in hex:\n", pc);
	    dStrHex((const char *)ucp, extra, 1);
	}
    }
}

static void show_ascii_page(unsigned char * resp, int len)
{
    int k, n, num;

    if (len < 0) {
    	printf("response has bad length\n");
    	return;
    }
    num = len - 4;
    switch (resp[0]) {
    case 0:
    	printf("Supported pages:\n");
	for (k = 0; k < num; ++k)
	    show_page_name((int)resp[4 + k]);
	break;
    case 0x1:
    	show_buffer_under_overrun_page(resp, len);
	break;
    case 0x2:
    case 0x3:
    case 0x4:
    case 0x5:
    	show_error_counter_page(resp, len);
	break;
    case 0x6:
    	show_non_medium_error_page(resp, len);
	break;
    case 0xd:
	show_Temperature_page(resp, len, 1);
	break;
    case 0xe:
    	if (len < 40) {
	    printf("badly formed start-stop cycle counter page\n");
	    break;
	}
	printf("Start-stop cycle counter page\n");
	printf("  Date of manufacture, year: %.4s, week: %.2s\n", 
	       &resp[8], &resp[12]); 
	printf("  Accounting date, year: %.4s, week: %.2s\n", 
	       &resp[18], &resp[22]); 
	n = (resp[28] << 24) | (resp[29] << 16) | (resp[30] << 8) | resp[31];
	printf("  Specified cycle count over device lifetime=%d\n", n);
	n = (resp[36] << 24) | (resp[37] << 16) | (resp[38] << 8) | resp[39];
	printf("  Accumulated start-stop cycles=%d\n", n);
	break;
    case 0x10:
    	show_self_test_page(resp, len);
	break;
    case 0x2f:
    	show_IE_page(resp, len, 1);
	break;
    default:
    	printf("No ascii information for page=0x%x, here is hex:\n", resp[0]);
	dStrHex((const char *)resp, len, 1);
	break;
    }
}
	
static int fetchTemperature(int sg_fd, int do_hex, unsigned char * resp, 
			    int max_len)
{
    int res = 0;

    if (0 == do_logs(sg_fd, 0, 0, 1, 0xd, 0, resp, max_len, 0))
    	show_Temperature_page(resp, (resp[2] << 8) + resp[3] + 4, 0);
    else if (0 == do_logs(sg_fd, 0, 0, 1, 0x2f, 0, resp, max_len, 0))
    	show_IE_page(resp, (resp[2] << 8) + resp[3] + 4, 0);
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
    int pc = 1;	/* N.B. some disks only give data for current cumulative */
    int paramp = 0;
    int do_list = 0;
    int do_ppc = 0;
    int do_sp = 0;
    int do_hex = 0;
    int do_all = 0;
    int do_temp = 0;
    int oflags = O_RDWR | O_NONBLOCK;

    for (k = 1; k < argc; ++k) {
        if (0 == strncmp("-p=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (u > 63)) {
                printf("Bad page code after '-p' switch\n");
                file_name = 0;
                break;
            }
	    pg_code = u;
        }
        else if (0 == strncmp("-c=", argv[k], 3)) {
            num = sscanf(argv[k] + 3, "%x", &u);
            if ((1 != num) || (u > 3)) {
                printf("Bad page control after '-c' switch\n");
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
        snprintf(ebuff, EBUFF_SZ, ME "error opening file: %s", file_name);
        perror(ebuff);
        return 1;
    }
    /* Just to be safe, check we have a new sg device by trying an ioctl */
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
        printf(ME "%s doesn't seem to be a version 3 sg device\n",
               file_name);
        close(sg_fd);
        return 1;
    }
    if (do_list || do_all)
    	pg_code = PG_CODE_ALL;
    pg_len = 0;
    if (1 == do_temp)
	return fetchTemperature(sg_fd, do_hex, rsp_buff, MX_ALLOC_LEN);

    if (0 == do_logs(sg_fd, do_ppc, do_sp, pc, pg_code, paramp,
    		     rsp_buff, MX_ALLOC_LEN, 1))
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
	    show_ascii_page(rsp_buff, pg_len + 4);
    }
    if (do_all && (pg_len > 1)) {
    	int my_len = pg_len - 1;
	unsigned char parr[256];

	memcpy(parr, rsp_buff + 5, my_len);
	for (k = 0; k < my_len; ++k) {
	    printf("\n");
	    pg_code = parr[k];
	    if (0 == do_logs(sg_fd, do_ppc, do_sp, pc, pg_code, paramp,
			     rsp_buff, MX_ALLOC_LEN, 1))
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
		    show_ascii_page(rsp_buff, pg_len + 4);
	    }
	}
    }
    close(sg_fd);
    return 0;
}

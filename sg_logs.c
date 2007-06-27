#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "sg_lib.h"
#include "sg_cmds_basic.h"

/* A utility program for the Linux OS SCSI generic ("sg") device driver.
*  Copyright (C) 2000-2006 D. Gilbert
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.

   This program outputs information provided by a SCSI LOG SENSE command.
   
*/

static char * version_str = "0.65 20061012";    /* SPC-4 revision 7a */

#define ME "sg_logs: "

#define MX_ALLOC_LEN (0xfffe)
#define SHORT_RESP_LEN 128
#define PG_CODE_ALL 0x0
#define SUBPG_CODE_ALL 0xff

#define PCB_STR_LEN 128


/* Call LOG SENSE twice: the first time ask for 4 byte response to determine
   actual length of response; then a second time requesting the
   min(actual_len, mx_resp_len) bytes. If the calculated length for the
   second fetch is odd then it is incremented (perhaps should be made modulo 4
   in the future for SAS). Returns 0 if ok, SG_LIB_CAT_INVALID_OP for
   log_sense not supported, SG_LIB_CAT_ILLEGAL_REQ for bad field in log sense
   command, SG_LIB_CAT_NOT_READY, SG_LIB_CAT_UNIT_ATTENTION,
   SG_LIB_CAT_ABORTED_COMMAND and -1 for other errors. */
static int do_logs(int sg_fd, int ppc, int sp, int pc, int pg_code, 
                   int subpg_code, int paramp, unsigned char * resp,
                   int mx_resp_len, int noisy, int verbose)
{
    int actual_len;
    int res;

    memset(resp, 0, mx_resp_len);
    if ((res = sg_ll_log_sense(sg_fd, ppc, sp, pc, pg_code, subpg_code,
                               paramp, resp, 4, noisy, verbose))) {
        switch (res) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            return res;
        default:
            return -1;
        }
    }
    actual_len = (resp[2] << 8) + resp[3] + 4;
    if (verbose > 1) {
        fprintf(stderr, "  Log sense (find length) response:\n");
        dStrHex((const char *)resp, 4, 1);
        fprintf(stderr, "  hence calculated response length=%d\n",
                actual_len);
    }
    /* Some HBAs don't like odd transfer lengths */
    if (actual_len % 2)
        actual_len += 1;
    if (actual_len > mx_resp_len)
        actual_len = mx_resp_len;
    if ((res = sg_ll_log_sense(sg_fd, ppc, sp, pc, pg_code, subpg_code,
                               paramp, resp, actual_len, noisy, verbose))) {
        switch (res) {
        case SG_LIB_CAT_NOT_READY:
        case SG_LIB_CAT_INVALID_OP:
        case SG_LIB_CAT_ILLEGAL_REQ:
        case SG_LIB_CAT_UNIT_ATTENTION:
        case SG_LIB_CAT_ABORTED_COMMAND:
            return res;
        default:
            return -1;
        }
    }
    if (verbose > 1) {
        fprintf(stderr, "  Log sense response:\n");
        dStrHex((const char *)resp, actual_len, 1);
    }
    return 0;
}

static void usage()
{
    printf("Usage:  sg_logs [-a] [-A] [-c=<page_control] [-h] [-H] [-l] "
           "[-L]\n"
           "                [-m=<max_len>] [-p=<page_number>[,"
           "<subpage_code>]]\n"
           "                [-paramp=<parameter_pointer>] [-pcb] [-ppc] "
           "[-r] [-select]\n"
           "                [-sp] [-t] [-T] [-v] [-V] [-?] <scsi_device>\n"
           "  where:\n"
           "    -a     fetch and decode all log pages\n"
           "    -A     fetch and decode all log pages and subpages\n"
           "    -c=<page_control> page control(PC) (default: 1)\n"
           "                  0: current threshhold, 1: current cumulative\n"
           "                  2: default threshhold, 3: default cumulative\n"
           "    -h     output in hex (default: decode if known)\n"
           "    -H     output in hex (same as '-h')\n"
           "    -l     list supported log page names (equivalent to "
           "'-p=0')\n"
           "    -L     list supported log page and subpages names "
           "(equivalent to\n"
           "           '-p=0,ff')\n"
           "    -m=<max_len>   max response length (decimal) (def: 0 "
           "-> everything)\n"
           "    -p=<page_code>   page code (in hex)\n"
           "    -p=<page_code>,<subpage_code>   both in hex, (defs: 0)\n"
           "    -paramp=<parameter_pointer>   (in hex) (def: 0)\n"
           "    -pcb   show parameter control bytes (ignored if -h "
           "given)\n");
    printf("    -ppc   set the Parameter Pointer Control (PPC) bit "
           "(def: 0)\n"
           "    -r     reset log parameters (takes PC and SP into "
           "account)\n"
           "           (uses PCR bit in LOG SELECT)\n"
           "    -select  perform LOG SELECT using SP and PC values\n"
           "    -sp    set the Saving Parameters (SP) bit (def: 0)\n"
           "    -t     outputs temperature log page (0xd)\n"
           "    -T     outputs transport (protocol specific port) log "
           "page (0x18)\n"
           "    -v     verbose: output cdbs prior to execution\n"
           "    -V     output version string\n"
           "    -?     output this usage message\n\n"
           "Performs a SCSI LOG SENSE (or LOG SELECT) command\n");
}

static void show_page_name(int pg_code, int subpg_code,
                           struct sg_simple_inquiry_resp * inq_dat)
{
    int done;
    char b[64];

    memset(b, 0, sizeof(b));
    /* first process log pages that do not depend on peripheral type */
    if (0 == subpg_code)
        snprintf(b, sizeof(b) - 1, "    0x%02x        ", pg_code);
    else
        snprintf(b, sizeof(b) - 1, "    0x%02x,0x%02x   ", pg_code,
                 subpg_code);
    done = 1;
    if ((0 == subpg_code) || (0xff == subpg_code)) {
        switch (pg_code) {
        case 0x0: printf("%sSupported log pages", b); break;
        case 0x1: printf("%sBuffer over-run/under-run", b); break;
        case 0x2: printf("%sError counters (write)", b); break;
        case 0x3: printf("%sError counters (read)", b); break;
        case 0x4: printf("%sError counters (read reverse)", b); break;
        case 0x5: printf("%sError counters (verify)", b); break;
        case 0x6: printf("%sNon-medium errors", b); break;
        case 0x7: printf("%sLast n error events", b); break;
        case 0xb: printf("%sLast n deferred errors or "
                         "asynchronous events", b); break;
        case 0xd: printf("%sTemperature", b); break;
        case 0xe: printf("%sStart-stop cycle counter", b); break;
        case 0xf: printf("%sApplication client", b); break;
        case 0x10: printf("%sSelf-test results", b); break;
        case 0x18: printf("%sProtocol specific port", b); break;
        case 0x19: printf("%sGeneral statistics and performance", b); break;
        case 0x2f: printf("%sInformational exceptions (SMART)", b); break;
        default : done = 0; break;
        }
        if (done) {
            if (0xff == subpg_code)
                printf(" and subpages\n");
            else
                printf("\n");
            return;
        }
    }
    if ((0x19 == pg_code) && (subpg_code > 0) && (subpg_code < 32)) {
        printf("%sGroup statistics and performance (%d)\n", b, subpg_code);
        return;
    }
    if (subpg_code > 0) {
        printf("%s??\n", b);
        return;
    }

    done = 1;
    switch (inq_dat->peripheral_type) {
    case 0: case 4: case 7: case 0xe:
        /* disk (direct access) type devices */
        {
            switch (pg_code) {
            case 0x8:
                printf("%sFormat status (sbc-2)\n", b);
                break;
            case 0x15:
                printf("%sBackground scan results (sbc-3)\n", b);
                break;
            case 0x17:
                printf("%sNon-volatile cache (sbc-2)\n", b);
                break;
            case 0x30:
                printf("%sPerformance counters (Hitachi)\n", b);
                break;
            case 0x37:
                printf("%sCache (Seagate), Miscellaneous (Hitachi)\n", b);
                break;
            case 0x3e:
                printf("%sFactory (Seagate/Hitachi)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 1: case 2:
        /* tape (streaming) and printer (obsolete) devices */
        {
            switch (pg_code) {
            case 0xc:
                printf("%sSequential access device (ssc-2)\n", b);
                break;
            case 0x14:
                printf("%sDevice statistics (ssc-3)\n", b);
                break;
            case 0x16:
                printf("%sTape diagnostic (ssc-3)\n", b);
                break;
            case 0x2e:
                printf("%sTapeAlert (ssc-2)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }
    case 8:
        /* medium changer type devices */
        {
            switch (pg_code) {
            case 0x14:
                printf("%sMedia changer statistics (smc-3)\n", b);
                break;
            case 0x2e:
                printf("%sTapeAlert (smc-3)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }
    case 0x12: /* Automation Device interface (ADC) */
        {
            switch (pg_code) {
            case 0x11:
                printf("%sDTD status (adc)\n", b);
                break;
            case 0x12:
                printf("%sTape alert response (adc)\n", b);
                break;
            case 0x13:
                printf("%sRequested recovery (adc)\n", b);
                break;
            case 0x14:
                printf("%sDevice statistics (adc)\n", b);
                break;
            case 0x15:
                printf("%sService buffers information (adc)\n", b);
                break;
            default:
                done = 0;
                break;
            }
        }

    default: done = 0; break;
    }
    if (done)
        return;

    printf("%s??\n", b);
}

static void get_pcb_str(int pcb, char * outp, int maxoutlen)
{
    char buff[PCB_STR_LEN];
    int n;

    n = sprintf(buff, "du=%d [ds=%d] tsd=%d etc=%d ", ((pcb & 0x80) ? 1 : 0),
                ((pcb & 0x40) ? 1 : 0), ((pcb & 0x20) ? 1 : 0), 
                ((pcb & 0x10) ? 1 : 0));
    if (pcb & 0x10)
        n += sprintf(buff + n, "tmc=%d ", ((pcb & 0xc) >> 2));
#if 1
    n += sprintf(buff + n, "format+linking=%d  [0x%.2x]", pcb & 3,
                 pcb);
#else
    if (pcb & 0x1)
        n += sprintf(buff + n, "lbin=%d ", ((pcb & 0x2) >> 1));
    n += sprintf(buff + n, "lp=%d  [0x%.2x]", pcb & 0x1, pcb);
#endif
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
    char pcb_str[PCB_STR_LEN];

    printf("Buffer over-run/under-run page\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pl = ucp[3] + 4;
        count_basis = (ucp[1] >> 5) & 0x7;
        cause = (ucp[1] >> 1) & 0xf;
        if ((0 == count_basis) && (0 == cause))
            printf("Count basis+Cause both undefined(0), unsupported??");
        else {
            printf("  Count basis: ");
            switch (count_basis) {
            case 0 : printf("undefined"); break;
            case 1 : printf("per command"); break;
            case 2 : printf("per failed reconnect"); break;
            case 3 : printf("per unit of time"); break;
            default: printf("reserved [0x%x]", count_basis); break;
            }
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
        }
        if (show_pcb) {
            pcb = ucp[2];
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
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
    char pcb_str[PCB_STR_LEN];

    switch(resp[0] & 0x3f) {
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
        case 0: printf("  Errors corrected without substantial delay"); break;
        case 1: printf("  Errors corrected with possible delays"); break;
        case 2: printf("  Total rewrites or rereads"); break;
        case 3: printf("  Total errors corrected"); break;
        case 4: printf("  Total times correction algorithm processed"); break;
        case 5: printf("  Total bytes processed"); break;
        case 6: printf("  Total uncorrected errors"); break;
        case 0x8009: printf("  Track following errors [Hitachi]"); break;
        case 0x8015: printf("  Positioning errors [Hitachi]"); break;
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
            printf("\n        <%s>\n", pcb_str);
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
    char pcb_str[PCB_STR_LEN];

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
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_last_n_error_page(unsigned char * resp, int len,
                                   int show_pcb)
{
    int k, num, pl, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("No error events logged\n");
        return;
    }
    printf("Last n error events log page\n");
    for (k = num; k > 0; k -= pl, ucp += pl) {
        if (k < 3) {
            printf("short Last n error events log page\n");
            return;
        }
        pl = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        printf("  Error event %d:\n", pc);
        if (pl > 4) {
            if ((pcb & 0x1) && (pcb & 0x2)) {
                printf("    [binary]:\n");
                dStrHex((const char *)ucp + 4, pl - 4, 1);
            } else if (pcb & 0x1)
                printf("    %.*s\n", pl - 4, (const char *)(ucp + 4));
            else {
                printf("    [data counter?? (LP bit should be set)]:\n");
                dStrHex((const char *)ucp + 4, pl - 4, 1);
            }
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
    }
}

static void show_last_n_deferred_error_page(unsigned char * resp,
                                            int len, int show_pcb)
{
    int k, num, pl, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    num = len - 4;
    ucp = &resp[0] + 4;
    if (num < 4) {
        printf("No deferred errors logged\n");
        return;
    }
    printf("Last n deferred errors log page\n");
    for (k = num; k > 0; k -= pl, ucp += pl) {
        if (k < 3) {
            printf("short Last n deferred errors log page\n");
            return;
        }
        pl = ucp[3] + 4;
        pc = (ucp[0] << 8) + ucp[1];
        pcb = ucp[2];
        printf("  Deferred error %d:\n", pc);
        dStrHex((const char *)ucp + 4, pl - 4, 1);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("        <%s>\n", pcb_str);
        }
    }
}

static const char * self_test_code[] = {
    "default", "background short", "background extended", "reserved",
    "aborted background", "foreground short", "foreground extended",
    "reserved"};

static const char * self_test_result[] = {
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
    char pcb_str[PCB_STR_LEN];

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
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_Temperature_page(unsigned char * resp, int len, 
                                  int show_pcb, int hdr, int show_unknown)
{
    int k, num, extra, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

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
            if ((extra > 5) && (k > 5)) {
                if (ucp[5] < 0xff)
                    printf("  Current temperature = %d C", ucp[5]);
                else
                    printf("  Current temperature = <not available>");
            }
        } else if (1 == pc) {
            if ((extra > 5) && (k > 5)) {
                if (ucp[5] < 0xff)
                    printf("  Reference temperature = %d C", ucp[5]);
                else
                    printf("  Reference temperature = <not available>");
            }

        } else if (show_unknown) {
            printf("  unknown parameter code = 0x%x, contents in hex:\n", pc);
            dStrHex((const char *)ucp, extra, 1);
        } else
            continue;
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_Start_Stop_page(unsigned char * resp, int len, int show_pcb,
                                 int verbose)
{
    int k, num, extra, pc, pcb;
    unsigned int n;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

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
            if (10 == extra)
                printf("  Date of manufacture, year: %.4s, week: %.2s", 
                       &ucp[4], &ucp[8]); 
            else if (verbose) {
                printf("  Date of manufacture parameter length "
                       "strange: %d\n", extra - 4);
                dStrHex((const char *)ucp, extra, 1);
            }
            break;
        case 2:
            if (10 == extra)
                printf("  Accounting date, year: %.4s, week: %.2s", 
                       &ucp[4], &ucp[8]); 
            else if (verbose) {
                printf("  Accounting date parameter length strange: %d\n",
                       extra - 4);
                dStrHex((const char *)ucp, extra, 1);
            }
            break;
        case 3:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Specified cycle count over device lifetime "
                           "= -1");
                else
                    printf("  Specified cycle count over device lifetime "
                           "= %u", n);
            }
            break;
        case 4:
            if (extra > 7) {
                n = (ucp[4] << 24) | (ucp[5] << 16) | (ucp[6] << 8) | ucp[7];
                if (0xffffffff == n)
                    printf("  Accumulated start-stop cycles = -1");
                else
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
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_IE_page(unsigned char * resp, int len, int show_pcb, int full)
{
    int k, num, extra, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];
    char b[256];

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
                if (full) {
                    printf("  IE asc = 0x%x, ascq = 0x%x", ucp[4], ucp[5]); 
                    if (ucp[4]) {
                        if(sg_get_asc_ascq_str(ucp[4], ucp[5], sizeof(b), b))
                            printf("\n    [%s]", b);
                    }
                }
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
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
    }
}

static void show_sas_phy_event_info(int peis, unsigned long val,
                                    unsigned long thresh_val)
{
    switch (peis) {
    case 0:
        printf("     No event\n");
        break;
    case 0x1:
        printf("     Invalid word count: %lu\n", val);
        break;
    case 0x2:
        printf("     Running disparity error count: %lu\n", val);
        break;
    case 0x3:
        printf("     Loss of dword synchronization count: %lu\n", val);
        break;
    case 0x4:
        printf("     Phy reset problem count: %lu\n", val);
        break;
    case 0x5:
        printf("     Elasticity buffer overflow count: %lu\n", val);
        break;
    case 0x6:
        printf("     Received ERROR  count: %lu\n", val);
        break;
    case 0x20:
        printf("     Received address frame error count: %lu\n", val);
        break;
    case 0x21:
        printf("     Transmitted OPEN_REJECT abandon count: %lu\n", val);
        break;
    case 0x22:
        printf("     Received OPEN_REJECT abandon count: %lu\n", val);
        break;
    case 0x23:
        printf("     Transmitted OPEN_REJECT retry count: %lu\n", val);
        break;
    case 0x24:
        printf("     Received OPEN_REJECT retry count: %lu\n", val);
        break;
    case 0x25:
        printf("     Received AIP (PARTIAL) count: %lu\n", val);
        break;
    case 0x26:
        printf("     Received AIP (CONNECTION) count: %lu\n", val);
        break;
    case 0x27:
        printf("     Transmitted BREAK count: %lu\n", val);
        break;
    case 0x28:
        printf("     Received BREAK count: %lu\n", val);
        break;
    case 0x29:
        printf("     Break timeout count: %lu\n", val);
        break;
    case 0x2a:
        printf("     Connection count: %lu\n", val);
        break;
    case 0x2b:
        printf("     Peak transmitted pathway blocked count: %lu\n",
               val & 0xff);
        printf("         Peak value detector threshold: %lu\n",
               thresh_val & 0xff);
        break;
    case 0x2c:
        printf("     Peak transmitted arbitration wait time (us to 32767): "
               "%lu\n", val & 0xffff);
        printf("         Peak value detector threshold: %lu\n",
               thresh_val & 0xffff);
        break;
    case 0x2d:
        printf("     Peak arbitration time (us): %lu\n", val);
        printf("         Peak value detector threshold: %lu\n", thresh_val);
        break;
    case 0x2e:
        printf("     Peak connection time (us): %lu\n", val);
        printf("         Peak value detector threshold: %lu\n", thresh_val);
        break;
    case 0x40:
        printf("     Transmitted SSP frame count: %lu\n", val);
        break;
    case 0x41:
        printf("     Received SSP frame count: %lu\n", val);
        break;
    case 0x42:
        printf("     Transmitted SSP frame error count: %lu\n", val);
        break;
    case 0x43:
        printf("     Received SSP frame error count: %lu\n", val);
        break;
    case 0x44:
        printf("     Transmitted CREDIT_BLOCKED count: %lu\n", val);
        break;
    case 0x45:
        printf("     Received CREDIT_BLOCKED count: %lu\n", val);
        break;
    case 0x50:
        printf("     Transmitted SATA frame count: %lu\n", val);
        break;
    case 0x51:
        printf("     Received SATA frame count: %lu\n", val);
        break;
    case 0x52:
        printf("     SATA flow control buffer overflow count: %lu\n", val);
        break;
    case 0x60:
        printf("     Transmitted SMP frame count: %lu\n", val);
        break;
    case 0x61:
        printf("     Received SMP frame count: %lu\n", val);
        break;
    /* case 0x63: */
    case 0x63:
        printf("     Received SMP frame error count: %lu\n", val);
        break;
    default:
        break;
    }
}

static int show_protocol_specific_page(unsigned char * resp, int len, 
                                       int show_pcb)
{
    int k, j, m, num, param_len, nphys, pcb, t, sz, spld_len;
    unsigned char * ucp;
    unsigned char * vcp;
    unsigned long long ull;
    unsigned long ul;
    char pcb_str[PCB_STR_LEN];
    char s[64];

    sz = sizeof(s);
    num = len - 4;
    for (k = 0, ucp = resp + 4; k < num; ) {
        pcb = ucp[2];
        param_len = ucp[3] + 4;
        /* each phy has a 48 byte descriptor but since param_len is
           an 8 bit quantity then only the first 5 phys (of, for example,
           a 8 phy wide link) can be represented */
        if (6 != (0xf & ucp[4]))
            return 0;   /* only decode SAS log page [sas2r05a] */
        if (0 == k)
            printf("SAS Protocol Specific page\n");
        printf("relative target port id = %d\n", (ucp[0] << 8) | ucp[1]);
        nphys = ucp[7];
        printf(" number of phys = %d", nphys);
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");

        for (j = 0, vcp = ucp + 8; j < (param_len - 8);
             vcp += spld_len, j += spld_len) {
            printf("  phy identifier = %d\n", vcp[1]);
            spld_len = vcp[3];
            if (spld_len < 44)
                spld_len = 48;
            else
                spld_len += 4;
            t = ((0x70 & vcp[4]) >> 4);
            switch (t) {
            case 0: snprintf(s, sz, "no device attached"); break;
            case 1: snprintf(s, sz, "end device"); break;
            case 2: snprintf(s, sz, "expander device"); break;
            case 3: snprintf(s, sz, "expander device (fanout)"); break;
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
            case 4: snprintf(s, sz, "phy enabled; port selector");
                         break;
            case 5: snprintf(s, sz, "phy enabled; reset in progress");
                         break;
            case 8: snprintf(s, sz, "phy enabled; 1.5 Gbps"); break;
            case 9: snprintf(s, sz, "phy enabled; 3 Gbps"); break;
            case 0xa: snprintf(s, sz, "phy enabled; 6 Gbps"); break;
            default: snprintf(s, sz, "reserved [%d]", t); break;
            }
            printf("    negotiated physical link rate: %s\n", s);
            printf("    attached initiator port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[6] & 8), !! (vcp[6] & 4), !! (vcp[6] & 2));
            printf("    attached target port: ssp=%d stp=%d smp=%d\n",
                   !! (vcp[7] & 8), !! (vcp[7] & 4), !! (vcp[7] & 2));
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
            if (spld_len > 51) {
                int num_ped, peis;
                unsigned char * xcp;
                unsigned long pvdt;

                num_ped = vcp[51];
                if (num_ped > 0)
                    printf("    Phy event descriptors:\n");
                xcp = vcp + 52;
                for (m = 0; m < (num_ped * 12); m += 12, xcp += 12) {
                    peis = xcp[3];
                    ul = (xcp[4] << 24) | (xcp[5] << 16) | (xcp[6] << 8) |
                         xcp[7];
                    pvdt = (xcp[8] << 24) | (xcp[9] << 16) | (xcp[10] << 8) |
                           xcp[11];
                    show_sas_phy_event_info(peis, ul, pvdt);
                }
            }
        }
        k += param_len;
        ucp += param_len;
    }
    return 1;
}

static void show_format_status_page(unsigned char * resp, int len, 
                                    int show_pcb)
{
    int k, j, num, pl, pc, pcb, all_ff, counter;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    printf("Format status page (sbc-2) [0x8]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        counter = 1;
        switch (pc) {
        case 0: printf("  Format data out:\n");
            counter = 0;
            dStrHex((const char *)ucp, pl, 0);
            break;
        case 1: printf("  Grown defects during certification"); break;
        case 2: printf("  Total blocks relocated during format"); break;
        case 3: printf("  Total new blocks relocated"); break;
        case 4: printf("  Power on minutes since format"); break;
        default:
            printf("  Unknown Format status code = 0x%x\n", pc);
            counter = 0;
            dStrHex((const char *)ucp, pl, 0);
            break;
        }
        if (counter) {
            k = pl - 4;
            xp = ucp + 4;
            if (k > (int)sizeof(ull)) {
                xp += (k - sizeof(ull));
                k = sizeof(ull);
            }
            ull = 0;
            for (all_ff = 0, j = 0; j < k; ++j) {
                if (j > 0)
                    ull <<= 8;
                else
                    all_ff = 1;
                ull |= xp[j];
                if (0xff != xp[j])
                    all_ff = 0;
            }
            if (all_ff)
                printf(" <not available>");
            else
                printf(" = %llu", ull);
            if (show_pcb) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("\n        <%s>\n", pcb_str);
            } else
                printf("\n");
        } else {
            if (show_pcb) {
                get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
                printf("\n        <%s>\n", pcb_str);
            }
        }
        num -= pl;
        ucp += pl;
    }
}

static void show_non_volatile_cache_page(unsigned char * resp, int len,
                                         int show_pcb)
{
    int j, num, pl, pc, pcb;
    unsigned char * ucp;
    char pcb_str[PCB_STR_LEN];

    printf("Non-volatile cache page (sbc-2) [0x17]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Remaining non-volatile time: ");
            if (3 == ucp[4]) {
                j = (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
                switch (j) {
                case 0:
                    printf("0 (i.e. it is now volatile)\n");
                    break;
                case 1:
                    printf("<unknown>\n");
                    break;
                case 0xffffff:
                    printf("<indefinite>\n");
                    break;
                default:
                    printf("%d minutes [%d:%d]\n", j, (j / 60), (j % 60));
                    break;
                }
            } else
                printf("<unexpected parameter length=%d>\n", ucp[4]);
            break;
        case 1:
            printf("  Maximum non-volatile time: ");
            if (3 == ucp[4]) {
                j = (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
                switch (j) {
                case 0:
                    printf("0 (i.e. it is now volatile)\n");
                    break;
                case 1:
                    printf("<reserved>\n");
                    break;
                case 0xffffff:
                    printf("<indefinite>\n");
                    break;
                default:
                    printf("%d minutes [%d:%d]\n", j, (j / 60), (j % 60));
                    break;
                }
            } else
                printf("<unexpected parameter length=%d>\n", ucp[4]);
            break;
        default:
            printf("  Unknown Format status code = 0x%x\n", pc);
            dStrHex((const char *)ucp, pl, 0);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        }
        num -= pl;
        ucp += pl;
    }
}

static const char * bms_status[] = {
    "no background scans active",
    "background scan is active",
    "background pre-scan is active",
    "background scan halted due to fatal error",
    "background scan halted due to a vendor specific pattern of error",
    "background scan halted due to medium formatted without P-List",
    "background scan halted - vendor specific cause",
    "background scan halted due to temperature out of range",
    "background scan halted until BM interval timer expires", /* 8 */
};

static const char * reassign_status[] = {
    "No reassignment needed",
    "Reassignment pending receipt of Reassign command or Write command",
    "Logical block successfully reassigned",
    "Reassign status: Reserved [0x3]",
    "Reassignment failed",
    "Logical block recovered via rewrite in-place",
    "Logical block reassigned by application client, has valid data",
    "Logical block reassigned by application client, contains no valid data",
    "Logical block unsuccessfully reassigned by application client", /* 8 */
};

static void show_background_scan_results_page(unsigned char * resp, int len,
                                              int show_pcb, int verbose)
{
    int j, m, num, pl, pc, pcb;
    unsigned char * ucp;
    char str[PCB_STR_LEN];

    printf("Background scan results page (sbc-3) [0x15]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        switch (pc) {
        case 0:
            printf("  Status parameters:\n");
            if ((pl < 16) || (num < 16)) {
                if (num < 16)
                    fprintf(stderr, "    truncated by response length, "
                            "expected at least 16 bytes\n");
                else
                    fprintf(stderr, "    parameter length >= 16 expected, "
                            "got %d\n", pl);
                break;
            }
            printf("    Accumulated power on minutes: ");
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf("%d [h:m  %d:%d]\n", j, (j / 60), (j % 60));
            printf("    Status: ");
            j = ucp[9];
            if (j < (int)(sizeof(bms_status) / sizeof(bms_status[0])))
                printf("%s\n", bms_status[j]);
            else
                printf("unknown [0x%x] background scan status value\n", j);
            printf("    Number of background scans performed: %d\n",
                   (ucp[10] << 8) + ucp[11]);
            printf("    Background medium scan progress: %.2f%%\n",
                   (double)((ucp[12] << 8) + ucp[13]) * 100.0 / 65536.0);
            break;
        default:
            printf("  Medium scan parameter # %d\n", pc);
            if ((pl < 24) || (num < 24)) {
                if (num < 24)
                    fprintf(stderr, "    truncated by response length, "
                            "expected at least 24 bytes\n");
                else
                    fprintf(stderr, "    parameter length >= 24 expected, "
                            "got %d\n", pl);
                break;
            }
            printf("    Power on minutes when error detected: ");
            j = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
            printf("%d [%d:%d]\n", j, (j / 60), (j % 60));
            j = (ucp[8] >> 4) & 0xf;
            if (j < 
                (int)(sizeof(reassign_status) / sizeof(reassign_status[0])))
                printf("    %s\n", reassign_status[j]);
            else
                printf("    Reassign status: reserved [0x%x]\n", j);
            printf("    sense key: %s  [sk,asc,ascq: 0x%x,0x%x,0x%x]\n",
                   sg_get_sense_key_str(ucp[8] & 0xf, sizeof(str), str),
                   ucp[8] & 0xf, ucp[9], ucp[10]);
            printf("      %s\n", sg_get_asc_ascq_str(ucp[9], ucp[10],
                                                     sizeof(str), str));
            if (verbose) {
                printf("    vendor bytes [11 -> 15]: ");
                for (m = 0; m < 5; ++m)
                    printf("0x%02x ", ucp[11 + m]);
                printf("\n");
            }
            printf("    LBA (associated with medium error): 0x");
            for (m = 0; m < 8; ++m)
                printf("%02x", ucp[16 + m]);
            printf("\n");
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, str, sizeof(str));
            printf("\n        <%s>\n", str);
        }
        num -= pl;
        ucp += pl;
    }
}

static void show_sequential_access_page(unsigned char * resp, int len, 
                                        int show_pcb, int verbose)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull, gbytes;
    char pcb_str[PCB_STR_LEN];

    printf("Sequential access device page (ssc-3)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
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
        gbytes = ull / 1000000000;
        switch (pc) {
        case 0: 
            printf("  Data bytes received with WRITE commands: %llu GB",
                   gbytes);
            if (verbose)
                printf(" [%llu bytes]", ull);
            printf("\n");
            break;
        case 1: 
            printf("  Data bytes written to media by WRITE commands: %llu "
                   "GB", gbytes);
            if (verbose)
                printf(" [%llu bytes]", ull);
            printf("\n");
            break;
        case 2: 
            printf("  Data bytes read from media by READ commands: %llu "
                   "GB", gbytes);
            if (verbose)
                printf(" [%llu bytes]", ull);
            printf("\n");
            break;
        case 3: 
            printf("  Data bytes transferred by READ commands: %llu "
                   "GB", gbytes);
            if (verbose)
                printf(" [%llu bytes]", ull);
            printf("\n");
            break;
        case 4: 
            printf("  Native capacity from BOP to EOD: %llu MB\n", ull);
            break;
        case 5: 
            printf("  Native capacity from BOP to EW of current partition: "
                   "%llu MB\n", ull);
            break;
        case 6: 
            printf("  Minimum native capacity from EW to EOP of current "
                   "partition: %llu MB\n", ull);
            break;
        case 7: 
            printf("  Native capacity from BOP to current position: %llu "
                   "MB\n", ull);
            break;
        case 8: 
            printf("  Maximum native capacity in device object buffer: %llu "
                   "MB\n", ull);
            break;
        case 0x100: 
            if (ull > 0)
                printf("  Cleaning action required\n");
            else
                printf("  Cleaning action not required (or completed)\n");
            if (verbose)
                printf("    cleaning value: %llu\n", ull);
            break;
        default:
            if (pc >= 0x8000)
                printf("  Vendor specific parameter [0x%x] value: %llu\n",
                       pc, ull);
            else
                printf("  Reserved parameter [0x%x] value: %llu\n",
                       pc, ull);
            break;
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_device_stats_page(unsigned char * resp, int len, 
                                   int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    printf("Device statistics page (ssc-3 and adc)\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        if (pc < 0x1000) {
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
            switch (pc) {
            case 0: 
                printf("  Lifetime media loads: %llu\n", ull);
                break;
            case 1: 
                printf("  Lifetime cleaning operations: %llu\n", ull);
                break;
            case 2: 
                printf("  Lifetime power on hours: %llu\n", ull);
                break;
            case 3: 
                printf("  Lifetime media motion (head) hours: %llu\n", ull);
                break;
            case 4: 
                printf("  Lifetime metres of tape processed: %llu\n", ull);
                break;
            case 5: 
                printf("  Lifetime media motion (head) hours when "
                       "incompatible media last loaded: %llu\n", ull);
                break;
            case 6: 
                printf("  Lifetime power on hours when "
                       "last temperature condition occurred: %llu\n", ull);
                break;
            case 7: 
                printf("  Lifetime power on hours when last power "
                       "consumption condition occurred: %llu\n", ull);
                break;
            case 8: 
                printf("  Media motion (head) hours since last successful "
                       "cleaning operation: %llu\n", ull);
                break;
            case 9: 
                printf("  Media motion (head) hours since 2nd to last "
                       "successful cleaning: %llu\n", ull);
                break;
            case 0xa: 
                printf("  Media motion (head) hours since 3rd to last "
                       "successful cleaning: %llu\n", ull);
                break;
            case 0xb: 
                printf("  Lifetime power on hours when last operator "
                       "initiated forced reset\n    and/or emergency "
                       "eject occurred: %llu\n", ull);
                break;
            default:
                printf("  Reserved parameter [0x%x] value: %llu\n",
                       pc, ull);
                break;
            }
        } else {
            switch (pc) {
            case 0x1000: 
                printf("  Media motion (head) hours for each medium type:\n");
                printf("      <<to be decoded, dump in hex for now>>:\n");
                dStrHex((const char *)ucp, pl, 0);
                break;
            default:
                printf("  Reserved parameter [0x%x], dump in hex:\n", pc);
                dStrHex((const char *)ucp, pl, 0);
                break;
            }
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_seagate_cache_page(unsigned char * resp, int len, 
                                    int show_pcb)
{
    int k, j, num, pl, pc, pcb;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

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
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_seagate_factory_page(unsigned char * resp, int len,
                                      int show_pcb)
{
    int k, j, num, pl, pc, pcb, valid;
    unsigned char * ucp;
    unsigned char * xp;
    unsigned long long ull;
    char pcb_str[PCB_STR_LEN];

    printf("Seagate/Hitachi factory page [0x3e]\n");
    num = len - 4;
    ucp = &resp[0] + 4;
    while (num > 3) {
        pc = (ucp[0] << 8) | ucp[1];
        pcb = ucp[2];
        pl = ucp[3] + 4;
        valid = 1;
        switch (pc) {
        case 0: printf("  number of hours powered up"); break;
        case 8: printf("  number of minutes until next internal SMART test");
            break;
        default:
            valid = 0;
            printf("  Unknown Seagate/Hitachi parameter code = 0x%x", pc);
            break;
        }
        if (valid) {
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
        }
        if (show_pcb) {
            get_pcb_str(pcb, pcb_str, sizeof(pcb_str));
            printf("\n        <%s>\n", pcb_str);
        } else
            printf("\n");
        num -= pl;
        ucp += pl;
    }
}

static void show_ascii_page(unsigned char * resp, int len, int show_pcb, 
                            struct sg_simple_inquiry_resp * inq_dat,
                            int verbose)
{
    int k, num, done, pg_code, subpg_code, spf;

    if (len < 0) {
        printf("response has bad length\n");
        return;
    }
    num = len - 4;
    done = 1;
    spf = !!(resp[0] & 0x40);
    pg_code = resp[0] & 0x3f;
    subpg_code = spf ? resp[1] : 0;

    if ((0 != pg_code ) && (0xff == subpg_code)) {
        printf("Supported subpages for log page=0x%x\n", pg_code);
        for (k = 0; k < num; k += 2)
            show_page_name((int)resp[4 + k], (int)resp[4 + k + 1],
                           inq_dat);
        return;
    }
    switch (pg_code) {
    case 0:
        if (spf) {
            printf("Supported log pages and subpages:\n");
            for (k = 0; k < num; k += 2)
                show_page_name((int)resp[4 + k], (int)resp[4 + k + 1],
                               inq_dat);
        } else {
            printf("Supported log pages:\n");
            for (k = 0; k < num; ++k)
                show_page_name((int)resp[4 + k], 0, inq_dat);
        }
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
    case 0x7:
        show_last_n_error_page(resp, len, show_pcb);
        break;
    case 0x8:
        {
            switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_format_status_page(resp, len, show_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0xb:
        show_last_n_deferred_error_page(resp, len, show_pcb);
        break;
    case 0xc:
        {
            switch (inq_dat->peripheral_type) {
            case 1: case 2: case 8:
                /* tape, (printer) and medium changer type devices */
                show_sequential_access_page(resp, len, show_pcb, verbose);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0xd:
        show_Temperature_page(resp, len, show_pcb, 1, 1);
        break;
    case 0xe:
        show_Start_Stop_page(resp, len, show_pcb, verbose);
        break;
    case 0x10:
        show_self_test_page(resp, len, show_pcb);
        break;
    case 0x14:
        {
            switch (inq_dat->peripheral_type) {
            case 1: case 8: case 0x12:
                /* tape, medium changer and adc type devices */
                show_device_stats_page(resp, len, show_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0x15:
        {
            switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_background_scan_results_page(resp, len, show_pcb,
                                                  verbose);
                break;
            default:
                done = 0;
                break;
            }
        }
        break;
    case 0x17:
        {
            switch (inq_dat->peripheral_type) {
            case 0: case 4: case 7: case 0xe:
                /* disk (direct access) type devices */
                show_non_volatile_cache_page(resp, len, show_pcb);
                break;
            default:
                done = 0;
                break;
            }
        }
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
                /* call ssc_device_status_log_page() */
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
               resp[0] & 0x3f);
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

    res = do_logs(sg_fd, 0, 0, 1, 0xd, 0, 0, resp, max_len, 0, verbose);
    if (0 == res)
        show_Temperature_page(resp, (resp[2] << 8) + resp[3] + 4, 0, 0, 0);
    else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "Device not ready\n");
    else {
        res = do_logs(sg_fd, 0, 0, 1, 0x2f, 0, 0, resp, max_len, 0, verbose);
        if (0 == res)
            show_IE_page(resp, (resp[2] << 8) + resp[3] + 4, 0, 0);
        else
            fprintf(stderr, "Unable to find temperature in either log page "
                    "(temperature or IE)\n");
    }
    sg_cmds_close_device(sg_fd);
    return (res >= 0) ? res : SG_LIB_CAT_OTHER;
}

static unsigned char rsp_buff[MX_ALLOC_LEN];

int main(int argc, char * argv[])
{
    int sg_fd, k, num, pg_len, res, plen, jmp_out, resp_len;
    const char * file_name = 0;
    const char * cp;
    unsigned int u, uu;
    int pg_code = 0;
    int subpg_code = 0;
    int subpg_code_set = 0;
    int pc = 1; /* N.B. some disks only give data for current cumulative */
    int paramp = 0;
    int do_list = 0;
    int do_pcb = 0;
    int do_ppc = 0;
    int do_select = 0;
    int do_sp = 0;
    int do_hex = 0;
    int do_all = 0;
    int do_temp = 0;
    int do_pcreset = 0;
    int do_verbose = 0;
    int max_len = 0;
    int ret = 0;
    struct sg_simple_inquiry_resp inq_out;

    memset(rsp_buff, 0, sizeof(rsp_buff));
    for (k = 1; k < argc; ++k) {
        cp = argv[k];
        plen = strlen(cp);
        if (plen <= 0)
            continue;
        if ('-' == *cp) {
            for (--plen, ++cp, jmp_out = 0; plen > 0; --plen, ++cp) {
                switch (*cp) {
                case 'a':
                    do_all = 1;
                    break;
                case 'A':
                    do_all = 2;
                    break;
                case 'h':
                case 'H':
                    do_hex = 1;
                    break;
                case 'l':
                    do_list = 1;
                    break;
                case 'L':
                    do_list = 2;
                    break;
                case 'r':
                    do_pcreset = 1;
                    do_select = 1;
                    break;
                case 't':
                    do_temp = 1;
                    break;
                case 'T':
                    pg_code = 0x18;
                    break;
                case 'v':
                    ++do_verbose;
                    break;
                case 'V':
                    fprintf(stderr, "Version string: %s\n", version_str);
                    exit(0);
                case '?':
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                case '-':
                    ++cp;
                    jmp_out = 1;
                    break;
                default:
                    jmp_out = 1;
                    break;
                }
                if (jmp_out)
                    break;
            }
            if (plen <= 0)
                continue;
            if (0 == strncmp("c=", cp, 2)) {
                num = sscanf(cp + 2, "%x", &u);
                if ((1 != num) || (u > 3)) {
                    printf("Bad page control after '-c=' option [0..3]\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                pc = u;
            } else if (0 == strncmp("m=", cp, 2)) {
                num = sscanf(cp + 2, "%d", &max_len);
                if ((1 != num) || (max_len < 0) || (max_len > MX_ALLOC_LEN)) {
                    printf("Bad maximum response length after '-m=' option\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else if (0 == strncmp("p=", cp, 2)) {
                if (NULL == strchr(cp + 2, ',')) {
                    num = sscanf(cp + 2, "%x", &u);
                    if ((1 != num) || (u > 63)) {
                        fprintf(stderr, "Bad page code value after '-p=' "
                                "option\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    pg_code = u;
                } else if (2 == sscanf(cp + 2, "%x,%x", &u, &uu)) {
                    if (uu > 255) {
                        fprintf(stderr, "Bad sub page code value after '-p=' "
                                "option\n");
                        usage();
                        return SG_LIB_SYNTAX_ERROR;
                    }
                    pg_code = u;
                    subpg_code = uu;
                    subpg_code_set = 1;
                } else {
                    fprintf(stderr, "Bad page code, subpage code sequence "
                            "after '-p=' option\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
            } else if (0 == strncmp("paramp=", cp, 7)) {
                num = sscanf(cp + 7, "%x", &u);
                if ((1 != num) || (u > 0xffff)) {
                    printf("Bad parameter pointer after '-paramp=' option\n");
                    usage();
                    return SG_LIB_SYNTAX_ERROR;
                }
                paramp = u;
            } else if (0 == strncmp("pcb", cp, 3))
                do_pcb = 1;
            else if (0 == strncmp("ppc", cp, 3))
                do_ppc = 1;
            else if (0 == strncmp("select", cp, 6))
                do_select = 1;
            else if (0 == strncmp("sp", cp, 2))
                do_sp = 1;
            else if (jmp_out) {
                fprintf(stderr, "Unrecognized option: %s\n", cp);
                usage();
                return SG_LIB_SYNTAX_ERROR;
            }
        } else if (0 == file_name)
            file_name = cp;
        else {
            fprintf(stderr, "too many arguments, got: %s, not expecting: "
                    "%s\n", file_name, cp);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    
    if (0 == file_name) {
        fprintf(stderr, "No <scsi_device> argument given. Try '-?' for "
                "usage.\n");
        return SG_LIB_SYNTAX_ERROR;
    }

    if ((sg_fd = sg_cmds_open_device(file_name, 0 /* rw */,
                                     do_verbose)) < 0) {
        if ((sg_fd = sg_cmds_open_device(file_name, 1 /* r0 */,
                                         do_verbose)) < 0) {
            fprintf(stderr, ME "error opening file: %s: %s \n", file_name,
                    safe_strerror(-sg_fd));
            return SG_LIB_FILE_ERROR;
        }
    }
    if (do_list || do_all) {
        pg_code = PG_CODE_ALL;
        if ((do_list > 1) || (do_all > 1))
            subpg_code = SUBPG_CODE_ALL;
    }
    pg_len = 0;

    if (sg_simple_inquiry(sg_fd, &inq_out, 1, do_verbose)) {
        fprintf(stderr, ME "%s doesn't respond to a SCSI INQUIRY\n",
                file_name);
        sg_cmds_close_device(sg_fd);
        return SG_LIB_CAT_OTHER;
    } else
        printf("    %.8s  %.16s  %.4s\n", inq_out.vendor, inq_out.product,
               inq_out.revision);

    if (1 == do_temp)
        return fetchTemperature(sg_fd, rsp_buff, SHORT_RESP_LEN, do_verbose);

    if (do_select) {
        k = sg_ll_log_select(sg_fd, !!(do_pcreset), do_sp, pc, pg_code,
                             subpg_code, NULL, 0, 1, do_verbose);
        if (k) {
            if (SG_LIB_CAT_NOT_READY == k)
                fprintf(stderr, "log_select: device not ready\n");
            else if (SG_LIB_CAT_INVALID_OP == k)
                fprintf(stderr, "log_select: not supported\n");
            else if (SG_LIB_CAT_UNIT_ATTENTION == k)
                fprintf(stderr, "log_select: unit attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == k)
                fprintf(stderr, "log_select: aborted command\n");
        }
        return (k >= 0) ?  k : SG_LIB_CAT_OTHER;
    }
    resp_len = (max_len > 0) ? max_len : MX_ALLOC_LEN;
    res = do_logs(sg_fd, do_ppc, do_sp, pc, pg_code, subpg_code, paramp,
                  rsp_buff, resp_len, 1, do_verbose);
    if (0 == res) {
        pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
        if ((pg_len + 4) > resp_len) {
            printf("Only fetched %d bytes of response (available: %d "
                   "bytes)\n    truncate output\n",
                   resp_len, pg_len + 4);
            pg_len = resp_len - 4;
        }
    } else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "log_sense: not supported\n");
    else if (SG_LIB_CAT_NOT_READY == res)
        fprintf(stderr, "log_sense: device not ready\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "log_sense: field in cdb illegal\n");
    else if (SG_LIB_CAT_UNIT_ATTENTION == res)
        fprintf(stderr, "log_sense: unit attention\n");
    else if (SG_LIB_CAT_ABORTED_COMMAND == res)
        fprintf(stderr, "log_sense: aborted command\n");
    if ((pg_len > 1) && (0 == do_all)) {
        if (do_hex) {
            if (rsp_buff[0] & 0x40)
                printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, "
                       "page_len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                       !!(rsp_buff[0] & 0x80), pg_len);
            else
                printf("Log page code=0x%x, DS=%d, SPF=0, page_len=0x%x\n",
                       rsp_buff[0] & 0x3f, !!(rsp_buff[0] & 0x80), pg_len);
            dStrHex((const char *)rsp_buff, pg_len + 4, 1);
        }
        else
            show_ascii_page(rsp_buff, pg_len + 4, do_pcb, &inq_out,
                            do_verbose);
    }
    ret = res;

    if (do_all && (pg_len > 1)) {
        int my_len = pg_len;
        int spf;
        unsigned char parr[1024];

        spf = !!(rsp_buff[0] & 0x40);
        if (my_len > (int)sizeof(parr)) {
            fprintf(stderr, "Unexpectedly large page_len=%d, trim to %d\n",
                    my_len, (int)sizeof(parr));
            my_len = sizeof(parr);
        }
        memcpy(parr, rsp_buff + 4, my_len);
        for (k = 0; k < my_len; ++k) {
            printf("\n");
            pg_code = parr[k] & 0x3f;
            if (spf)
                subpg_code = parr[++k];
            else
                subpg_code = 0;
            
            res = do_logs(sg_fd, do_ppc, do_sp, pc, pg_code, subpg_code,
                          paramp, rsp_buff, resp_len, 1, do_verbose);
            if (0 == res) {
                pg_len = (rsp_buff[2] << 8) + rsp_buff[3];
                if ((pg_len + 4) > resp_len) {
                    printf("Only fetched %d bytes of response, truncate "
                           "output\n", resp_len);
                    pg_len = resp_len - 4;
                }
                if (do_hex) {
                    if (rsp_buff[0] & 0x40)
                        printf("Log page code=0x%x,0x%x, DS=%d, SPF=1, page_"
                               "len=0x%x\n", rsp_buff[0] & 0x3f, rsp_buff[1],
                               !!(rsp_buff[0] & 0x80), pg_len);
                    else
                        printf("Log page code=0x%x, DS=%d, SPF=0, page_len="
                               "0x%x\n", rsp_buff[0] & 0x3f,
                               !!(rsp_buff[0] & 0x80), pg_len);
                    dStrHex((const char *)rsp_buff, pg_len + 4, 1);
                }
                else
                    show_ascii_page(rsp_buff, pg_len + 4, do_pcb, &inq_out,
                                    do_verbose);
            } else if (SG_LIB_CAT_INVALID_OP == res)
                fprintf(stderr, "log_sense: page=0x%x,0x%x not supported\n",
                        pg_code, subpg_code);
            else if (SG_LIB_CAT_NOT_READY == res)
                fprintf(stderr, "log_sense: device not ready\n");
            else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "log_sense: field in cdb illegal "
                        "[page=0x%x,0x%x]\n", pg_code, subpg_code);
            else if (SG_LIB_CAT_UNIT_ATTENTION == res)
                fprintf(stderr, "log_sense: unit attention\n");
            else if (SG_LIB_CAT_ABORTED_COMMAND == res)
                fprintf(stderr, "log_sense: aborted command\n");
        }
    }
    sg_cmds_close_device(sg_fd);
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

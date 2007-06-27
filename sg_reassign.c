/*
 * Copyright (c) 2005 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 * This utility invokes the REASSIGN BLOCKS SCSI command to reassign
 * an existing (possibly damaged) lba on a direct access device (e.g.
 * a disk) to a new physical location. The previous contents is 
 * recoverable then it is written to the remapped lba otherwise
 * vendor specific data is written.
 */

static char * version_str = "1.02 20050331";

#define ME "sg_reassign: "

#define REASSIGN_BLKS_CMD     0x7
#define REASSIGN_BLKS_CMDLEN  6
#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define DEF_DEFECT_LIST_FORMAT 4        /* bytes from index */

#define MAX_NUM_ADDR 1024

#define EBUFF_SZ 256


static struct option long_options[] = {
        {"address", 1, 0, 'a'},
        {"dummy", 0, 0, 'd'},
        {"eight", 1, 0, 'e'},
        {"grown", 0, 0, 'g'},
        {"help", 0, 0, 'h'},
        {"longlist", 1, 0, 'l'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sg_reassign --address=<n>[,<n>...] [--dummy] [--eight=0|1] "
          "[--grown]\n"
          "                   [--help] [--longlist=0|1] [--verbose] "
          "[--version]\n"
          "                   <scsi_device>\n"
          "  where:\n"
          "      --address=<n>[,<n>...]\n"
          "        -a <n>[,<n>...]     comma separated logical block "
          "addresses\n"
          "                            (at least one required)\n"
          "      --address=- | -a -    read stdin for logical block "
          "addresses\n"
          "      --dummy | -d          prepare but do not execute "
          "REASSIGN BLOCKS\n"
          "                            command\n"
          "      --eight=0|1\n"
          "        -e 0|1              force eight byte (64 bit) lbas "
          "when 1,\n"
          "                            four byte (32 bit) lbas when 0 "
          "(def)\n"
          "      --grown | -g          fetch grown defect list length, "
          "don't reassign\n"
          "      --help | -h           print out usage message\n"
          "      --longlist=0|1\n"
          "         -l 0|1             use 4 byte list length when "
          "'--longlist=1',\n"
          "                            safe to ignore and use 2 byte "
          "list length\n"
          "      --verbose | -v        increase verbosity\n"
          "      --version | -V        print version string and exit\n\n"
          );
}

/* Invokes a SCSI REASSIGN BLOCKS command.  Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
int sg_ll_reassign_blocks(int sg_fd, int dummy, int longlba, int longlist,
                          void * paramp, int param_len, int noisy, int verbose)
{
    int res, k;
    unsigned char reassCmdBlk[REASSIGN_BLKS_CMDLEN] = 
        {REASSIGN_BLKS_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    reassCmdBlk[1] = (unsigned char)(((longlba << 1) & 0x2) | (longlist & 0x1));
    if (verbose) {
        fprintf(stderr, "    reassign blocks cdb: ");
        for (k = 0; k < REASSIGN_BLKS_CMDLEN; ++k)
            fprintf(stderr, "%02x ", reassCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    if (verbose > 1) {
        fprintf(stderr, "    reassign blocks parameter block\n");
        dStrHex((const char *)paramp, param_len, -1);
    }

    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    memset(sense_b, 0, sizeof(sense_b));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = REASSIGN_BLKS_CMDLEN;
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_TO_DEV;
    io_hdr.dxfer_len = param_len;
    io_hdr.dxferp = paramp;
    io_hdr.cmdp = reassCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (dummy) {
        fprintf(stderr, ">>> dummy: REASSIGN BLOCKS not executed\n");
        return 0;
    }

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        fprintf(stderr, "reassign blocks SG_IO error: %s\n",
                safe_strerror(errno));
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("Reassign blocks, continuing", &io_hdr);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        return 0;
    case SG_LIB_CAT_INVALID_OP:
    case SG_LIB_CAT_ILLEGAL_REQ:
        if (verbose > 1)
            sg_chk_n_print3("Reassign blocks error", &io_hdr);
        return res;
    default:
        if (noisy || verbose) {
            char ebuff[EBUFF_SZ];

            snprintf(ebuff, EBUFF_SZ, "Reassign blocks error, longlba=%d "
                    "longlist=%d\n     ", longlba, longlist);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

/* Trying to decode multipliers as sg_get_llnum() [in sg_libs does] would
 * only confuse things here, so use this local trimmed version */
long long get_llnum(const char * buf)
{
    int res;
    long long num;
    unsigned long long unum;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1LL;
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1]))) {
        res = sscanf(buf + 2, "%llx", &unum);
        num = unum;
    } else
        res = sscanf(buf, "%lld", &num);
    if (1 == res)
        return num;
    else
        return -1LL;
}

/* Read numbers (up to 64 bits in size) from command line (comma separated */
/* list) or from stdin (one per line, comma separated list or */
/*  space separated list). Assumed decimal unless prefixed by '0x' (for */
/* hex). Returns 0 if ok, or 1 if error. */
static int build_lba_arr(const char * inp, unsigned long long * lba_arr,
                           int * lba_arr_len, int max_arr_len)
{
    int in_len, k, j, m;
    const char * lcp;
    long long ll;
    char * cp;

    if ((NULL == inp) || (NULL == lba_arr) ||
        (NULL == lba_arr_len))
        return 1;
    lcp = inp;
    in_len = strlen(inp);
    if (0 == in_len)
        *lba_arr_len = 0;
    if ('-' == inp[0]) {        /* read from stdin */
        char line[512];
        int off = 0;

        for (j = 0; j < 512; ++j) {
            if (NULL == fgets(line, sizeof(line), stdin))
                break;
            in_len = strlen(line);
            if (in_len > 0) {
                if ('\n' == line[in_len - 1]) {
                    --in_len;
                    line[in_len] = '\0';
                }
            }
            if (0 == in_len)
                continue;
            lcp = line;
            m = strspn(lcp, " \t");
            if (m == in_len)
                continue;
            lcp += m;
            in_len -= m;
            if ('#' == *lcp)
                continue;
            k = strspn(lcp, "0123456789aAbBcCdDeEfFxX ,\t");
            if ((k < in_len) && ('#' != lcp[k])) {
                fprintf(stderr, "build_lba_arr: syntax error at "
                        "line %d, pos %d\n", j + 1, m + k + 1);
                return 1;
            }
            for (k = 0; k < 1024; ++k) {
                ll = get_llnum(lcp);
                if (-1 != ll) {
                    if ((off + k) >= max_arr_len) {
                        fprintf(stderr, "build_lba_arr: array length "
                                "exceeded\n");
                        return 1;
                    }
                    lba_arr[off + k] = (unsigned long long)ll;
                    lcp = strpbrk(lcp, " ,\t");
                    if (NULL == lcp)
                        break;
                    lcp += strspn(lcp, " ,\t");
                    if ('\0' == *lcp)
                        break;
                } else {
                    if ('#' == *lcp) {
                        --k;
                        break;
                    }
                    fprintf(stderr, "build_lba_arr: error in "
                            "line %d, at pos %d\n", j + 1,
                            (int)(lcp - line + 1));
                    return 1;
                }
            }
            off += (k + 1);
        }
        *lba_arr_len = off;
    } else {        /* hex string on command line */
        k = strspn(inp, "0123456789aAbBcCdDeEfFxX,");
        if (in_len != k) {
            fprintf(stderr, "build_lba_arr: error at pos %d\n", k + 1);
            return 1;
        }
        for (k = 0; k < max_arr_len; ++k) {
            ll = get_llnum(lcp);
            if (-1 != ll) {
                lba_arr[k] = (unsigned long long)ll;
                cp = strchr(lcp, ',');
                if (NULL == cp)
                    break;
                lcp = cp + 1;
            } else {
                fprintf(stderr, "build_lba_arr: error at pos %d\n",
                        (int)(lcp - inp + 1));
                return 1;
            }
        }
        *lba_arr_len = k + 1;
        if (k == max_arr_len) {
            fprintf(stderr, "build_lba_arr: array length exceeded\n");
            return 1;
        }
    }
    return 0;
}


int main(int argc, char * argv[])
{
    int sg_fd, res, c, num, k, j;
    int dummy = 0;
    int got_addr = 0;
    int eight = -1;
    int addr_arr_len = 0;
    int grown = 0;
    int longlist = 0;
    int verbose = 0;
    char device_name[256];
    unsigned long long addr_arr[MAX_NUM_ADDR];
    unsigned char param_arr[4 + (MAX_NUM_ADDR * 8)];
    int param_len = 4;
    int ret = 1;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "a:de:ghl:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            memset(addr_arr, 0, sizeof(addr_arr));
            if (0 != build_lba_arr(optarg, addr_arr, &addr_arr_len,
                                   MAX_NUM_ADDR)) {
                fprintf(stderr, "bad argument to '--address'\n");
                return 1;
            }
            got_addr = 1;
            break;
        case 'd':
            dummy = 1;
            break;
        case 'e':
            num = sscanf(optarg, "%d", &res);
            if ((1 == num) && ((0 == res) || (1 == res)))
                eight = res;
            else {
                fprintf(stderr, "value for '--eight=' must be 0 or 1\n");
                return 1;
            }
            break;
        case 'g':
            grown = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            num = sscanf(optarg, "%d", &res);
            if ((1 == num) && ((0 == res) || (1 == res)))
                longlist = res;
            else {
                fprintf(stderr, "value for '--longlist=' must be 0 or 1\n");
                return 1;
            }
            break;
        case 'v':
            ++verbose;
            break;
        case 'V':
            fprintf(stderr, ME "version: %s\n", version_str);
            return 0;
        default:
            fprintf(stderr, "unrecognised switch code 0x%x ??\n", c);
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
        if (optind < argc) {
            for (; optind < argc; ++optind)
                fprintf(stderr, "Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return 1;
        }
    }
    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    if (grown) {
        if (got_addr) {
            fprintf(stderr, "can't have both '--grown' and '--address='\n");
            usage();
            return 1;
        }
    } else if ((0 == got_addr) || (addr_arr_len < 1)) {
        fprintf(stderr, "need at least one address (see '--address=')\n");
        usage();
        return 1;
    }
    if (got_addr) {
        for (k = 0; k < addr_arr_len; ++k) {
            if (addr_arr[k] >= ULONG_MAX) {
                if (eight < 0) {
                    eight = 1;
                    break;
                } else if (0 == eight) {
                    fprintf(stderr, "address number %d exceeds 32 bits so "
                            "'--eight=0' invalid\n", k + 1);
                    return 1;
                }
            }
        }
        if (eight < 0)
            eight = 0;

        k = 4;
        for (j = 0; j < addr_arr_len; ++j) {
            if (eight) {
                param_arr[k++] = (addr_arr[j] >> 56) & 0xff;
                param_arr[k++] = (addr_arr[j] >> 48) & 0xff;
                param_arr[k++] = (addr_arr[j] >> 40) & 0xff;
                param_arr[k++] = (addr_arr[j] >> 32) & 0xff;
            }
            param_arr[k++] = (addr_arr[j] >> 24) & 0xff;
            param_arr[k++] = (addr_arr[j] >> 16) & 0xff;
            param_arr[k++] = (addr_arr[j] >> 8) & 0xff;
            param_arr[k++] = addr_arr[j] & 0xff;
        }
        param_len = k;
        k -= 4;
        if (longlist) {
            param_arr[0] = (k >> 24) & 0xff;
            param_arr[1] = (k >> 16) & 0xff;
        }
        param_arr[2] = (k >> 8) & 0xff;
        param_arr[3] = k & 0xff;
    }

    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s: ", device_name);
        perror("");
        return 1;
    } 

    if (got_addr) {
        res = sg_ll_reassign_blocks(sg_fd, dummy, eight, longlist,
                                    param_arr, param_len, 1, verbose);
        if (SG_LIB_CAT_INVALID_OP == res) {
            fprintf(stderr, "REASSIGN BLOCKS not supported\n");
            goto err_out;
        } else if (SG_LIB_CAT_INVALID_OP == res) {
            fprintf(stderr, "bad field in REASSIGN BLOCKS cdb\n");
            goto err_out;
        } else if (0 != res) {
            fprintf(stderr, "REASSIGN BLOCKS failed\n");
            goto err_out;
        }
        ret = 0;
    } else /* if (grown) */ {
        int dl_format = DEF_DEFECT_LIST_FORMAT;
        int div = 0;
        int dl_len;

        param_len = 4;
        memset(param_arr, 0, param_len);
        res = sg_ll_read_defect10(sg_fd, 0 /* req_plist */,
                                  1 /* req_glist */, dl_format,
                                  param_arr, param_len, 0, verbose);
        if (SG_LIB_CAT_INVALID_OP == res) {
            fprintf(stderr, "READ DEFECT DATA (10) not supported\n");
            goto err_out;
        } else if (SG_LIB_CAT_INVALID_OP == res) {
            fprintf(stderr, "bad field in READ DEFECT DATA (10) cdb\n");
            goto err_out;
        } else if (0 != res) {
            fprintf(stderr, "READ DEFECT DATA (10) failed\n");
            goto err_out;
        }

        if (0x8 != (param_arr[1] & 0x18)) {
            fprintf(stderr, "asked for grown defect list but didn't get it\n");
            goto err_out;
        }
        if (verbose)
            fprintf(stderr, "asked for defect list format %d, got %d\n",
                    dl_format, (param_arr[1] & 0x7));
        dl_format = (param_arr[1] & 0x7);
        switch (dl_format) {
            case 0:     /* short block */
                div = 4;
                break;
            case 3:     /* long block */
            case 4:     /* bytes from index */
            case 5:     /* physical sector */
                div = 8;
                break;
            default:
                fprintf(stderr, "defect list format %d unknown\n", dl_format);
                break;
        }
        dl_len = (param_arr[2] << 8) + param_arr[3];
        if (0 == dl_len)
            printf(">> Elements in grown defect list: 0\n");
        else {
            if (0 == div)
                printf(">> Grown defect list length=%d bytes [unknown "
                       "number of elements]\n", dl_len);
            else
                printf(">> Elements in grown defect list: %d\n",
                       dl_len / div);
        }
    }

err_out:
    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
        return 1;
    }
    return ret;
}

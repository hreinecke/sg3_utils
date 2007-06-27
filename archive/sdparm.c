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
#include <ctype.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 * This utility fetches various parameters associated with a given
 * SCSI disk (or a disk that uses, or translates the SCSI command
 * set). In some cases these parameters can be changed.
 */

static char * version_str = "0.90 20050411";

#define ME "sdparm: "

#define DEF_MODE_RESP_LEN 252
#define RW_ERR_RECOVERY_MP 1
#define DISCONNECT_MP 2
#define V_ERR_RECOVERY_MP 7
#define CACHING_MP 8
#define CONTROL_MP 0xa
#define POWER_MP 0x1a
#define IEC_MP 0x1c
#define PROT_SPEC_LU_MP 0x18
#define PROT_SPEC_PORT_MP 0x19

#define MODE_DATA_OVERHEAD 128
#define EBUFF_SZ 256
#define MAX_MP_IT_VAL 128
#define MAX_MODE_DATA_LEN 2048


static struct option long_options[] = {
        {"six", 0, 0, '6'},
        {"all", 0, 0, 'a'},
        {"clear", 1, 0, 'c'},
        {"defaults", 1, 0, 'D'},
        {"dummy", 1, 0, 'd'},
        {"enumerate", 0, 0, 'e'},
        {"get", 1, 0, 'g'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"inquiry", 0, 0, 'i'},
        {"long", 0, 0, 'l'},
        {"page", 1, 0, 'p'},
        {"set", 1, 0, 's'},
        {"save", 0, 0, 'S'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

static void usage()
{
    fprintf(stderr, "Usage: "
          "sdparm    [-all] [--clear=<str>] [--defaults] [-dummy] "
          "[--enumerate]\n"
          "                 [--get=<str>] [--help] [--hex] [--inquiry] "
          "[--long]\n"
          "                 [--page=<pg>] [--save] [--set=<str>] [--six] "
          "[--verbose]\n"
          "                 [--version] <scsi_disk>\n"
          "  where:\n"
          "      --all | -a            list all known parameters for given "
          "disk\n"
          "      --clear=<str> | -c <str>  clear (zero) parameter value(s)\n"
          "      --defaults | -D       set a mode page to its default "
          "values\n"
          "      --dummy | -d          don't write back modified mode page\n"
          "      --enumerate | -e      list known pages and parameters "
          "(ignore disk)\n"
          "      --get=<str> | -g <str>  get (fetch) parameter value(s)\n"
          "      --help | -h           print out usage message\n"
          "      --hex | -H            output in hex rather than name/value "
          "pairs\n"
          "      --inquiry | -i        output INQUIRY VPD page(s) (def mode "
          "page(s))\n"
          "      --long | -l           add description to parameter output\n"
          "      --page=<pg> | -p <pg>  page ([,subpage]) number to output "
          "(or change)\n"
          "      --save | -S           place mode changes in saved page as "
          "well\n"
          "      --set=<str> | -s <str>  set parameter value(s)\n"
          "      --six | -6            use 6 byte SCSI cdbs (def 10 byte)\n"
          "      --verbose | -v        increase verbosity\n"
          "      --version | -V        print version string and exit\n\n"
          "View or change parameters of a SCSI disk\n"
          );
}

struct values_name_t {
    int value;
    int subvalue;
    const char * acron;
    const char * name;
};

static struct values_name_t mode_nums_name[] = {
    {CACHING_MP, 0, "ca", "Caching"},
    {CONTROL_MP, 0, "co", "Control"},
    {DISCONNECT_MP, 0, "dr", "Disconnect-reconnect"},
    {IEC_MP, 0, "ie", "Informational exception control"},
    {PROT_SPEC_LU_MP, 0, "pl", "Protocol specific logical unit"},
    {POWER_MP, 0, "po", "Power condition"},
    {PROT_SPEC_PORT_MP, 0, "pp", "Protocol specific port"},
    {RW_ERR_RECOVERY_MP, 0, "rw", "Read write error recovery"},
    {V_ERR_RECOVERY_MP, 0, "ve", "Verify error recovery"},
};

static int mode_nums_name_len =
        (sizeof(mode_nums_name) / sizeof(mode_nums_name[0]));

static void list_mps()
{
    int k;
    const struct values_name_t * vnp;

    for (k = 0, vnp = mode_nums_name; k < mode_nums_name_len; ++k, ++vnp) {
        if (vnp->subvalue)
            printf("  %-4s 0x%02x,0x%02x %s\n", vnp->acron, vnp->value,
                   vnp->subvalue, vnp->name);
        else
            printf("  %-4s 0x%02x      %s\n", vnp->acron, vnp->value,
                   vnp->name);
    }
}

static const char * get_mode_name(int page_num, int subpage_num)
{
    int k;
    const struct values_name_t * vnp;

    for (k = 0, vnp = mode_nums_name; k < mode_nums_name_len; ++k, ++vnp) {
        if ((page_num == vnp->value) && (subpage_num == vnp->subvalue))
            return vnp->name;
    }
    return NULL;
}

static const struct values_name_t * find_mp_by_acron(const char * ap)
{
    int k;
    const struct values_name_t * vnp;

    for (k = 0, vnp = mode_nums_name; k < mode_nums_name_len; ++k, ++vnp) {
        if (0 == strncmp(vnp->acron, ap, 2))
            return vnp;
    }
    return NULL;
}

struct mode_page_item {
    const char * acron;
    int page_num;
    int subpage_num;
    int start_byte;
    int start_bit;
    int num_bits;
    int common;
    const char * description;
};

struct mode_page_it_val {
    struct mode_page_item mpi;
    int val;
};

struct mode_page_settings {
    int page_num;
    int subpage_num;
    struct mode_page_it_val it_vals[MAX_MP_IT_VAL];
    int num_it_vals;
};


static struct mode_page_item mitem_arr[] = {
    {"AWRE", RW_ERR_RECOVERY_MP, 0, 2, 7, 1, 1,   /* [0x1] sbc2 */
        "Automatic write reallocation enabled"},
    {"ARRE", RW_ERR_RECOVERY_MP, 0, 2, 6, 1, 1,
        "Automatic read reallocation enabled"},
    {"TB", RW_ERR_RECOVERY_MP, 0, 2, 5, 1, 0,
        "Transfer block"},
    {"RC", RW_ERR_RECOVERY_MP, 0, 2, 4, 1, 0,
        "Read continuous"},
    {"EER", RW_ERR_RECOVERY_MP, 0, 2, 3, 1, 0,
        "Enable early recover"},
    {"PER", RW_ERR_RECOVERY_MP, 0, 2, 2, 1, 1,
        "Post error"},
    {"DTE", RW_ERR_RECOVERY_MP, 0, 2, 1, 1, 0,
        "Data terminate on error"},
    {"DCR", RW_ERR_RECOVERY_MP, 0, 2, 0, 1, 0,
        "Disable correction"},
    {"RRC", RW_ERR_RECOVERY_MP, 0, 3, 7, 8, 0,
        "Read retry count"},
    {"WRC", RW_ERR_RECOVERY_MP, 0, 8, 7, 8, 0,
        "Write retry count"},
    {"RTL", RW_ERR_RECOVERY_MP, 0, 10, 7, 16, 0,
        "Recovery time limit (ms)"},

    {"BITL", DISCONNECT_MP, 0, 4, 7, 16, 0,     /* [0x2] spc3,sas1 */
        "Bus inactivity time limit (sas: 100us)"},
    {"MCTL", DISCONNECT_MP, 0, 8, 7, 16, 0,
        "Maximum connect time limit (sas: 100us)"},
    {"MBS", DISCONNECT_MP, 0, 10, 7, 16, 0,
        "Maximum burst size"},
    {"FBS", DISCONNECT_MP, 0, 14, 7, 16, 0,
        "First burst size"},

    {"V_EER", V_ERR_RECOVERY_MP, 0, 2, 3, 1, 0,   /* [0x8] sbc2 */
        "Enable early recover"},
    {"V_PER", V_ERR_RECOVERY_MP, 0, 2, 2, 1, 0,
        "Post error"},
    {"V_DTE", V_ERR_RECOVERY_MP, 0, 2, 1, 1, 0,
        "Data terminate on error"},
    {"V_DCR", V_ERR_RECOVERY_MP, 0, 2, 0, 1, 0,
        "Disable correction"},
    {"V_RC", V_ERR_RECOVERY_MP, 0, 3, 7, 8, 0,
        "Verify retry count"},
    {"V_RTL", V_ERR_RECOVERY_MP, 0, 10, 7, 16, 0,
        "Verify recovery time limit (ms)"},

    {"IC", CACHING_MP, 0, 2, 7, 1, 0,    /* [0x8] sbc2 */
        "Initiator control"},
    {"ABPF", CACHING_MP, 0, 2, 6, 1, 0,
        "Abort pre-fetch"},
    {"CAP", CACHING_MP, 0, 2, 5, 1, 0,
        "Caching analysis permitted"},
    {"DISC", CACHING_MP, 0, 2, 4, 1, 0,
        "Discontinuity"},
    {"SIZE", CACHING_MP, 0, 2, 3, 1, 0,
        "Size"},
    {"WCE", CACHING_MP, 0, 2, 2, 1, 1,
        "Write cache enable"},
    {"MF", CACHING_MP, 0, 2, 1, 1, 0,
        "Multiplication factor"},
    {"RCD", CACHING_MP, 0, 2, 0, 1, 1,
        "Read cache disable"},
    {"DRRP", CACHING_MP, 0, 3, 7, 4, 0,
        "Demand read retension prioriry"},
    {"WRP", CACHING_MP, 0, 3, 3, 4, 0,
        "Write retension prioriry"},
    {"DPTL", CACHING_MP, 0, 4, 7, 16, 0,
        "Disable pre-fetch transfer length"},
    {"MIPF", CACHING_MP, 0, 6, 7, 16, 0,
        "Minimum pre-fetch"},
    {"MAPF", CACHING_MP, 0, 8, 7, 16, 0,
        "Maximum pre-fetch"},
    {"MAPFC", CACHING_MP, 0, 10, 7, 16, 0,
        "Maximum pre-fetch ceiling"},
    {"FSW", CACHING_MP, 0, 12, 7, 1, 0,
        "Force sequential write"},
    {"LBCSS", CACHING_MP, 0, 12, 5, 1, 0,
        "Logical block cache segment size"},
    {"DRA", CACHING_MP, 0, 12, 4, 1, 0,
        "disable read ahead"},
    {"NV_DIS", CACHING_MP, 0, 12, 0, 1, 0,
        "Non-volatile cache disbale"},
    {"NCS", CACHING_MP, 0, 13, 7, 8, 0,
        "Number of cache segments"},
    {"CSS", CACHING_MP, 0, 14, 7, 16, 0,
        "Cache segment size"},

    {"TST", CONTROL_MP, 0, 2, 7, 3, 0,    /* [0xa] spc3 */
        "Task set type"},
    {"TMF_ONLY", CONTROL_MP, 0, 2, 4, 1, 0,
        "Task management functions only"},
    {"D_SENSE", CONTROL_MP, 0, 2, 2, 1, 0,
        "Descriptor format sense data"},
    {"GLTSD", CONTROL_MP, 0, 2, 1, 1, 0,
        "Global logging target save disable"},
    {"RLEC", CONTROL_MP, 0, 2, 0, 1, 0,
        "Report log exception condition"},
    {"QAM", CONTROL_MP, 0, 3, 7, 4, 0,
        "Queue algorithm modifier"},
    {"QERR", CONTROL_MP, 0, 3, 2, 2, 0,
        "Queue error management"},
    {"RAC", CONTROL_MP, 0, 4, 6, 1, 0,
        "Report a check"},
    {"UA_INTLCK", CONTROL_MP, 0, 4, 5, 2, 0,
        "Unit attention interlocks controls"},
    {"SWP", CONTROL_MP, 0, 4, 3, 1, 1,
        "Software write protect"},
    {"ATO", CONTROL_MP, 0, 5, 7, 1, 0,
        "Application tag owner"},
    {"TAS", CONTROL_MP, 0, 5, 6, 1, 0,
        "Task aborted status"},
    {"AUTOLOAD", CONTROL_MP, 0, 5, 2, 3, 0,
        "Autoload mode"},
    {"BTP", CONTROL_MP, 0, 8, 7, 16, 0,
        "Busy timeout period (100us)"},
    {"ESTCT", CONTROL_MP, 0, 10, 7, 16, 0,
        "Extended self test completion time (sec)"},

    {"PID", PROT_SPEC_PORT_MP, 0, 2, 3, 4, 0,    /* [0x19] spc3 */
        "Protocol identifier"},

    {"LUPID", PROT_SPEC_LU_MP, 0, 2, 3, 4, 0,    /* [0x18] spc3 */
        "Protocol identifier"},

    {"IDLE", POWER_MP, 0, 3, 1, 1, 0,    /* [0x1a] spc3 */
        "Idle timer active"},
    {"STANDBY", POWER_MP, 0, 3, 0, 1, 0,
        "Standby timer active"},
    {"ICT", POWER_MP, 0, 4, 7, 32, 0,
        "Idle condition timer (100 ms)"},
    {"SCT", POWER_MP, 0, 8, 7, 32, 0,
        "Standby condition timer (100 ms)"},

    {"PERF", IEC_MP, 0, 2, 7, 1, 0,    /* [0x1c] spc3 */
        "Performance"},
    {"EBF", IEC_MP, 0, 2, 5, 1, 0,
        "Enable background function"},
    {"EWASC", IEC_MP, 0, 2, 4, 1, 1,
        "Enable warning"},
    {"DEXCPT", IEC_MP, 0, 2, 3, 1, 1,
        "Disable exceptions"},
    {"TEST", IEC_MP, 0, 2, 2, 1, 0,
        "Test (simulate device failure"},
    {"LOGERR", IEC_MP, 0, 2, 0, 1, 0,
        "Log errors"},
    {"MRIE", IEC_MP, 0, 3, 3, 4, 1,
        "Method of reporting infomational exceptions"},
    {"INTT", IEC_MP, 0, 4, 7, 32, 0,
        "Interval timer (100 ms)"},
    {"REPC", IEC_MP, 0, 8, 7, 32, 0,
        "Report count"},
};

static int mitem_arr_len = (sizeof(mitem_arr) / sizeof(mitem_arr[0]));

static void list_mitems(int pn, int spn)
{
    int k, t_pn, t_spn;
    const struct mode_page_item * mpi;
    const char * name;
    int found = 0;

    t_pn = -1;
    t_spn = -1;
    for (k = 0, mpi = mitem_arr; k < mitem_arr_len; ++k, ++mpi) {
        if ((t_pn != mpi->page_num) || (t_spn != mpi->subpage_num)) {
            t_pn = mpi->page_num;
            t_spn = mpi->subpage_num;
            if ((pn >= 0) && ((pn != t_pn) || (spn != t_spn)))
                continue;
            name = get_mode_name(t_pn, t_spn);
            if (name) {
                if (t_spn)
                    printf("%s mode page [0x%x,0x%x]:\n", name, t_pn, t_spn);
                else
                    printf("%s mode page [0x%x]:\n", name, t_pn);
            } else if (0 == t_spn)
                printf("mode page 0x%x:\n", t_pn);
            else
                printf("mode page 0x%x,0x%x:\n", t_pn, t_spn);
        } else {
            if ((pn >= 0) && ((pn != t_pn) || (spn != t_spn)))
                continue;
        }
        printf("  %-10s [0x%02x:%d:%-2d]  %s\n", mpi->acron, mpi->start_byte,
               mpi->start_bit, mpi->num_bits, mpi->description);
        found = 1;
    }
    if ((! found) && (pn >= 0)) {
        name = get_mode_name(pn, spn);
        if (name) {
            if (spn)
                printf("%s mode page [0x%x,0x%x]: no items found\n", name,
                       pn, spn);
            else
                printf("%s mode page [0x%x]: no items found\n", name, pn);
        } else if (0 == spn)
            printf("mode page 0x%x: no items found\n", pn);
        else
            printf("mode page 0x%x,0x%x: no items found\n", pn, spn);
    }
}

static const struct mode_page_item * find_mitem_by_acron(const char * ap, int * from)
{
    int k = 0;
    const struct mode_page_item * mpi;

    if (from) {
        k = *from;
        if (k < 0)
            k = 0;
    }
    for (mpi = mitem_arr + k; k < mitem_arr_len; ++k, ++mpi) {
        if (0 == strcmp(mpi->acron, ap))
            break;
    }
    if (k >= mitem_arr_len) {
        k = mitem_arr_len;
        mpi = NULL;
    }
    if (from)
        *from = k + 1;
    return mpi;
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
    /* 0x10 */ "bridge controller commands",
    "object based storage",
    "automation/driver interface",
    "0x13", "0x14", "0x15", "0x16", "0x17", "0x18",
    "0x19", "0x1a", "0x1b", "0x1c", "0x1d",
    "well known logical unit",
    "no physical device on this lu",
};

static unsigned int get_big_endian(const unsigned char * from, int start_bit,
                                   int num_bits)
{
    unsigned int res;
    int sbit_o1 = start_bit + 1;

    res = (*from++ & ((1 << sbit_o1) - 1));
    num_bits -= sbit_o1;
    while (num_bits > 0) {
        res <<= 8;
        res |= *from++;
        num_bits -= 8;
    }
    if (num_bits < 0)
        res >>= (-num_bits);
    return res;
}

static void set_big_endian(unsigned int val, unsigned char * to,
                           int start_bit, int num_bits)
{
    int sbit_o1 = start_bit + 1;
    int mask, num, k, x;

    mask = (8 != sbit_o1) ? ((1 << sbit_o1) - 1) : 0xff;
    k = start_bit - ((num_bits - 1) % 8);
    if (0 != k)
        val <<= ((k > 0) ? k : (8 + k));
    num = (num_bits + 15 - sbit_o1) / 8;
    for (k = 0; k < num; ++k) {
        if ((sbit_o1 - num_bits) > 0)
            mask &= ~((1 << (sbit_o1 - num_bits)) - 1);
        if (k < (num - 1))
            x = (val >> ((num - k - 1) * 8)) & 0xff;
        else
            x = val & 0xff;
        to[k] = (to[k] & ~mask) | (x & mask); 
        mask = 0xff;
        num_bits -= sbit_o1;
        sbit_o1 = 8;
    }
}

static unsigned int mp_get_value(const struct mode_page_item *mpi,
                                 const unsigned char * mp)
{
    return get_big_endian(mp + mpi->start_byte, mpi->start_bit,
                          mpi->num_bits);
}

static unsigned int mp_get_value_check(const struct mode_page_item *mpi,
                                       const unsigned char * mp,
                                       int * all_set)
{
    unsigned int res;

    res = get_big_endian(mp + mpi->start_byte, mpi->start_bit,
                         mpi->num_bits);
    if (all_set) {
        if ((16 == mpi->num_bits) && (0xffff == res))
            *all_set = 1;
        else if ((32 == mpi->num_bits) && (0xffffffff == res))
            *all_set = 1;
        else
            *all_set = 0;
    }
    return res;
}

static void mp_set_value(unsigned int val, struct mode_page_item *mpi,
                         unsigned char * mp)
{
    set_big_endian(val, mp + mpi->start_byte, mpi->start_bit, mpi->num_bits);
}
 
static void print_mp_entry(const char * pre, int smask,
                           const struct mode_page_item *mpi,
                           const unsigned char * cur_mp,
                           const unsigned char * cha_mp,
                           const unsigned char * def_mp,
                           const unsigned char * sav_mp,
                           int long_out)
{
    int sep = 0;
    int all_set;
    unsigned int u;
    const char * acron;

    all_set = 0;
    acron = (mpi->acron ? mpi->acron : "");
    u = mp_get_value_check(mpi, cur_mp, &all_set);
    if (all_set)
        printf("%s%-10s -1", pre, acron);
    else
        printf("%s%-10s %u", pre, acron, u);
    if (smask & 0xe) {
        printf("  [");
        if (smask & 2) {
            printf("Changeable: %s",
                   (mp_get_value(mpi, cha_mp) ? "y" : "n"));
            sep = 1;
        }
        if (smask & 4) {
            all_set = 0;
            u = mp_get_value_check(mpi, def_mp, &all_set);
            if (all_set)
                printf("%sdef: -1", (sep ? ", " : " "));
            else
                printf("%sdef: %u", (sep ? ", " : " "), u);
            sep = 1;
        }
        if (smask & 8) {
            all_set = 0;
            u = mp_get_value_check(mpi, sav_mp, &all_set);
            if (all_set)
                printf("%ssaved: -1", (sep ? ", " : " "));
            else
                printf("%ssaved: %u", (sep ? ", " : " "), u);
        }
        printf("]");
    }
    if (long_out && mpi->description)
        printf("  %s", mpi->description);
    printf("\n");
}

static void print_mode_info(int sg_fd, int mode6, int pn, int spn, int all,
                            int long_out, int hex, int verbose)
{
    int k, res, len, verb, smask, single, fetch;
    const struct mode_page_item * mpi;
    unsigned char cur_mp[DEF_MODE_RESP_LEN];
    unsigned char cha_mp[DEF_MODE_RESP_LEN];
    unsigned char def_mp[DEF_MODE_RESP_LEN];
    unsigned char sav_mp[DEF_MODE_RESP_LEN];
    const char * name;

    verb = (verbose > 0) ? verbose - 1 : 0;
    if (pn >= 0) {
        single = 1;
        fetch = 1;
        for (k = 0, mpi = mitem_arr; k < mitem_arr_len; ++k, ++mpi) {
            if ((pn == mpi->page_num) && (spn == mpi->subpage_num))
                break;
        }
        if (k >= mitem_arr_len) {
            if (verbose) {
                if (0 == spn)
                    printf("mode page 0x%x, attributes not found\n", pn);
                else
                    printf("mode page 0x%x,0x%x, attributes not found\n",
                           pn, spn);
            }
            if (hex) {
                k = 0;
                mpi = mitem_arr;    /* trick to enter main loop once */
            }
        }
    } else {
        single = 0;
        fetch = 0;
        mpi = mitem_arr;
        k = 0;
    }
    name = "";
    smask = 0;
    for (; k < mitem_arr_len; ++k, ++mpi, fetch = 0) {
        if (0 == fetch) {
            if (! (all || mpi->common))
                continue;
            if ((pn != mpi->page_num) || (spn != mpi->subpage_num)) {
                if (single)
                    break;
                fetch = 1;
                pn = mpi->page_num;
                spn = mpi->subpage_num;
            }
        }
        if (fetch) {
            smask = 0;
            res = sg_get_mode_page_types(sg_fd, mode6, pn, spn,
                                         DEF_MODE_RESP_LEN, &smask, cur_mp,
                                         cha_mp, def_mp, sav_mp, verb);
            if (SG_LIB_CAT_INVALID_OP == res) {
                if (mode6)
                    fprintf(stderr, "6 byte MODE SENSE cdb not supported, "
                            "try again without '-6' option\n");
                else
                    fprintf(stderr, "10 byte MODE SENSE cdb not supported, "
                            "try again with '-6' option\n");
                return;
            }
            if ((smask & 1)) {
                name = get_mode_name(pn, spn);
                if (name) {
                    if (0 == spn)
                        printf("%s mode page [0x%x]:\n", name, pn);
                    else
                        printf("%s mode page [0x%x,0x%x]:\n", name, pn, spn);
                } else if (0 == spn)
                    printf("mode page 0x%x:\n", pn);
                else
                    printf("mode page 0x%x,0x%x:\n", pn, spn);
                if (hex) {
                    if (cur_mp[0] & 0x40)
                        len = (cur_mp[2] << 8) + cur_mp[3] + 4;
                    else
                        len = cur_mp[1] + 2;
                    printf("    Current:\n");
                    dStrHex((const char *)cur_mp, len, 1);
                    if (smask & 2) {
                        printf("    Changeable:\n");
                        dStrHex((const char *)cha_mp, len, 1);
                    }
                    if (smask & 4) {
                        printf("    Default:\n");
                        dStrHex((const char *)def_mp, len, 1);
                    }
                    if (smask & 8) {
                        printf("    Saved:\n");
                        dStrHex((const char *)sav_mp, len, 1);
                    }
                }
            } else {
                if (verbose || single) {
                    name = get_mode_name(pn, spn);
                    if (name)
                        printf(">> %s mode page not supported\n", name);
                    else if (0 == spn)
                        printf(">> mode page 0x%x not supported\n", pn);
                    else
                        printf(">> mode page 0x%x,0x%x not supported\n",
                               pn, spn);
                }
            }
        }
        if (smask && (! hex))
            print_mp_entry("  ", smask, mpi, cur_mp, cha_mp,
                     def_mp, sav_mp, long_out);
    }
}

static void get_mode_info(int sg_fd, int mode6,
                          struct mode_page_settings * mps, int long_out,
                          int hex, int verbose)
{
    int k, res, verb, smask, pn, spn;
    unsigned int u, val;
    const struct mode_page_item * mpi;
    unsigned char cur_mp[DEF_MODE_RESP_LEN];
    unsigned char cha_mp[DEF_MODE_RESP_LEN];
    unsigned char def_mp[DEF_MODE_RESP_LEN];
    unsigned char sav_mp[DEF_MODE_RESP_LEN];
    const struct mode_page_it_val * ivp;

    verb = (verbose > 0) ? verbose - 1 : 0;
    for (k = 0, pn = 0, spn = 0; k < mps->num_it_vals; ++k) {
        ivp = &mps->it_vals[k];
        val = ivp->val;
        mpi = &ivp->mpi;
        if ((0 == k) || (pn != mpi->page_num) || (spn != mpi->subpage_num)) {
            pn = mpi->page_num;
            spn = mpi->subpage_num;
            smask = 0;
            switch (val) {
            case 0:
                res = sg_get_mode_page_types(sg_fd, mode6, pn, spn,
                                             DEF_MODE_RESP_LEN, &smask,
                                             cur_mp, cha_mp, def_mp, sav_mp,
                                             verb);
                break;
            case 1:
                res = sg_get_mode_page_types(sg_fd, mode6, pn, spn,
                                             DEF_MODE_RESP_LEN, &smask,
                                             cur_mp, NULL, NULL, NULL, verb);
                break;
            default:
                if (mpi->acron)
                    fprintf(stderr, "bad format 'val' given to %s\n",
                            mpi->acron);
                else
                    fprintf(stderr, "bad format 'val' given to 0x%x:%d:%d\n",
                            mpi->start_byte, mpi->start_bit, mpi->num_bits);
                return;
            }
            if (SG_LIB_CAT_INVALID_OP == res) {
                if (mode6)
                    fprintf(stderr, "6 byte MODE SENSE cdb not supported, "
                            "try again without '-6' option\n");
                else
                    fprintf(stderr, "10 byte MODE SENSE cdb not supported, "
                            "try again with '-6' option\n");
                return;
            }
        }
        if (0 == val) {
            if (hex) {
                if (smask & 1) {
                    u = mp_get_value(mpi, cur_mp);
                    printf("0x%02x ", u);
                } else
                    printf("-    ");
                if (smask & 2) {
                    u = mp_get_value(mpi, cha_mp);
                    printf("0x%02x ", u);
                } else
                    printf("-    ");
                if (smask & 4) {
                    u = mp_get_value(mpi, def_mp);
                    printf("0x%02x ", u);
                } else
                    printf("-    ");
                if (smask & 8) {
                    u = mp_get_value(mpi, sav_mp);
                    printf("0x%02x ", u);
                } else
                    printf("-    ");
                printf("\n");
            } else
                print_mp_entry("", smask, mpi, cur_mp, cha_mp,
                               def_mp, sav_mp, long_out);
        } else if (1 == val) {
            if (hex) {
                if (smask & 1) {
                    u = mp_get_value(mpi, cur_mp);
                    printf("0x%02x ", u);
                } else
                    printf("-    ");
                printf("\n");
            } else
                print_mp_entry("", smask, mpi, cur_mp, NULL,
                               NULL, NULL, long_out);
        }
    }
}

/* Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, -1 -> other failure */
static int change_mode_page(int sg_fd, int save, int mode_6,
                            struct mode_page_settings * mps, int dummy,
                            int verbose)
{
    int k, len, off, md_len, res;
    char ebuff[EBUFF_SZ];
    unsigned char mdpg[MAX_MODE_DATA_LEN];
    struct mode_page_it_val * ivp;

    len = MAX_MODE_DATA_LEN;
    memset(mdpg, 0, len);
    if (mode_6)
        res = sg_ll_mode_sense6(sg_fd, 0 /* dbd */, 0 /*current */,
                                mps->page_num, mps->subpage_num,
                                mdpg, ((len > 252) ? 252 : len), 1,
                                verbose);
    else
        res = sg_ll_mode_sense10(sg_fd, 0 /* llbaa */, 0 /* dbd */,
                                 0 /* current */, mps->page_num,
                                 mps->subpage_num, mdpg, len, 1, verbose);
    if (0 != res) {
        fprintf(stderr, "change_mode_page: failed fetching page: 0x%x,0x%x\n",
                mps->page_num, mps->subpage_num);
        return -1;
    }
    off = sg_mode_page_offset(mdpg, len, mode_6, ebuff, EBUFF_SZ);
    if (off < 0) {
        fprintf(stderr, "change_mode_page: page offset failed: %s\n", ebuff);
        return -1;
    }
    if (mode_6)
        md_len = mdpg[0] + 1;
    else
        md_len = (mdpg[0] << 8) + mdpg[1] + 2;
    mdpg[0] = 0;        /* mode data length reserved for mode select */
    if (! mode_6)
        mdpg[1] = 0;    /* mode data length reserved for mode select */
    if (md_len > len) {
        fprintf(stderr, "change_mode_page: mode data length=%d exceeds "
                "allocation length=%d\n", md_len, len);
        return -1;
    }

    for (k = 0; k < mps->num_it_vals; ++k) {
        ivp = &mps->it_vals[k];
        mp_set_value(ivp->val, &ivp->mpi, mdpg + off);
    }

    if ((! (mdpg[off] & 0x80)) && save) {
        fprintf(stderr, "change_mode_page: mode page indicates it is not "
                "savable but\n    '--save' option given (try without "
                "it)\n");
        return -1;
    }
    mdpg[off] &= 0x7f;   /* mask out PS bit, reserved in mode select */
    if (dummy) {
        printf("Mode data that would have been written:\n");
        dStrHex((const char *)mdpg, md_len, 1);
        return 0;
    }
    if (verbose) {
        printf("Mode data about to be written:\n");
        dStrHex((const char *)mdpg, md_len, 1);
    }
    if (mode_6)
        res = sg_ll_mode_select6(sg_fd, 1, save, mdpg, md_len, 1,
                                 verbose);
    else
        res = sg_ll_mode_select10(sg_fd, 1, save, mdpg, md_len, 1,
                                  verbose);
    if (0 != res) {
        fprintf(stderr, "change__mode_page: failed setting page: 0x%x,0x%x\n",
                mps->page_num, mps->subpage_num);
        return -1;
    }
    return 0;
}

/* Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, -1 -> other failure */
static int set_mode_page(int sg_fd, int pn, int spn, int save, int mode_6,
                         unsigned char * mode_pg, int mode_pg_len,
                         int dummy, int verbose)
{
    int len, off, md_len;
    unsigned char * mdp;
    char ebuff[EBUFF_SZ];
    int ret = -1;

    len = mode_pg_len + MODE_DATA_OVERHEAD;
    mdp = malloc(len);
    if (NULL ==mdp) {
        fprintf(stderr, "set_mode_page: malloc failed, out of memory\n");
        return -1;
    }
    memset(mdp, 0, len);
    if (mode_6)
        ret = sg_ll_mode_sense6(sg_fd, 0 /* dbd */, 0 /*current */, pn,
                                spn, mdp, ((len > 252) ? 252 : len), 1,
                                verbose);
    else
        ret = sg_ll_mode_sense10(sg_fd, 0 /* llbaa */, 0 /* dbd */,
                                 0 /* current */, pn, spn, mdp, len, 1,
                                 verbose);
    if (0 != ret) {
        fprintf(stderr, "set_mode_page: failed fetching page: 0x%x,0x%x\n",
                pn, spn);
        goto err_out;
    }
    off = sg_mode_page_offset(mdp, len, mode_6, ebuff, EBUFF_SZ);
    if (off < 0) {
        fprintf(stderr, "set_mode_page: page offset failed: %s\n", ebuff);
        ret = -1;
        goto err_out;
    }
    if (mode_6)
        md_len = mdp[0] + 1;
    else
        md_len = (mdp[0] << 8) + mdp[1] + 2;
    mdp[0] = 0;        /* mode data length reserved for mode select */
    if (! mode_6)
        mdp[1] = 0;    /* mode data length reserved for mode select */
    if (md_len > len) {
        fprintf(stderr, "set_mode_page: mode data length=%d exceeds "
                "allocation length=%d\n", md_len, len);
        ret = -1;
        goto err_out;
    }
    if ((md_len - off) > mode_pg_len) {
        fprintf(stderr, "set_mode_page: mode length length=%d exceeds "
                "new contents length=%d\n", md_len - off, mode_pg_len);
        ret = -1;
        goto err_out;
    }
    memcpy(mdp + off, mode_pg, md_len - off);
    mdp[off] &= 0x7f;   /* mask out PS bit, reserved in mode select */
    if (dummy) {
        printf("Mode data that would have been written:\n");
        dStrHex((const char *)mdp, md_len, 1);
        ret = 0;
        goto err_out;
    }
    if (verbose) {
        printf("Mode data about to be written:\n");
        dStrHex((const char *)mdp, md_len, 1);
    }
    if (mode_6)
        ret = sg_ll_mode_select6(sg_fd, 1, save, mdp, md_len, 1,
                                 verbose);
    else
        ret = sg_ll_mode_select10(sg_fd, 1, save, mdp, md_len, 1,
                                  verbose);
    if (0 != ret) {
        fprintf(stderr, "set_mode_page: failed setting page: 0x%x,0x%x\n",
                pn, spn);
        goto err_out;
    }

err_out:
    free(mdp);
    return ret;
}

static int set_mp_defaults(int sg_fd, int pn, int spn, int saved,
                           int mode_6, int dummy, int verbose)
{
    int smask, res, len;
    unsigned char cur_mp[DEF_MODE_RESP_LEN];
    unsigned char def_mp[DEF_MODE_RESP_LEN];
    const char * name;


    smask = 0;
    res = sg_get_mode_page_types(sg_fd, mode_6, pn, spn, DEF_MODE_RESP_LEN,
                                 &smask, cur_mp, NULL, def_mp, NULL,
                                 verbose);
    if (SG_LIB_CAT_INVALID_OP == res) {
        if (mode_6)
            fprintf(stderr, "6 byte MODE SENSE cdb not supported, "
                    "try again without '-6' option\n");
        else
            fprintf(stderr, "10 byte MODE SENSE cdb not supported, "
                    "try again with '-6' option\n");
        return -1;
    }
    if ((smask & 1)) {
        if ((smask & 4)) {
            if (cur_mp[0] & 0x40)
                len = (cur_mp[2] << 8) + cur_mp[3] + 4; /* spf set */
            else
                len = cur_mp[1] + 2; /* spf clear (not subpage) */
            return set_mode_page(sg_fd, pn, spn, saved, mode_6, def_mp,
                                 len, dummy, verbose);
        }
        else {
            name = get_mode_name(pn, spn);
            if (name)
                printf(">> %s mode page (default) not supported\n", name);
            else if (0 == spn)
                printf(">> mode page 0x%x (default) not supported\n", pn);
            else
                printf(">> mode page 0x%x,0x%x (default) not supported\n",
                       pn, spn);
            return -1;
        }
    } else {
        name = get_mode_name(pn, spn);
        if (name)
            printf(">> %s mode page not supported\n", name);
        else if (0 == spn)
            printf(">> mode page 0x%x not supported\n", pn);
        else
            printf(">> mode page 0x%x,0x%x not supported\n", pn, spn);
        return -1;
    }
}

/* Trying to decode multipliers as sg_get_num() [in sg_libs does] would
 * only confuse things here, so use this local trimmed version */
static int get_num(const char * buf)
{
    int res;
    int num;
    unsigned int unum;

    if ((NULL == buf) || ('\0' == buf[0]))
        return -1;
    if (('0' == buf[0]) && (('x' == buf[1]) || ('X' == buf[1]))) {
        res = sscanf(buf + 2, "%x", &unum);
        num = unum;
    } else
        res = sscanf(buf, "%d", &num);
    if (1 == res)
        return num;
    else
        return -1;
}

static int build_mp_settings(const char * arg,
                             struct mode_page_settings * mps, int clear,
                             int get)
{
    int len, b_sz, num, from, cont;
    unsigned int u;
    char buff[64];
    char acron[64];
    char vb[64];
    const char * cp;
    const char * ncp;
    const char * ecp;
    struct mode_page_it_val * ivp;
    const struct mode_page_item * mpi;
    const struct mode_page_item * prev_mpi;

    b_sz = sizeof(buff) - 1;
    cp = arg;
    while (mps->num_it_vals < MAX_MP_IT_VAL) {
        memset(buff, 0, sizeof(buff));
        ivp = &mps->it_vals[mps->num_it_vals];
        if ('\0' == *cp)
            break;
        ncp = strchr(cp, ',');
        if (ncp) {
            len = ncp - cp;
            if (len <= 0) {
                ++cp;
                continue;
            }
            strncpy(buff, cp, (len < b_sz ? len : b_sz));
        } else
            strncpy(buff, cp, b_sz);
        if (isalpha(buff[0])) {
            ecp = strchr(buff, '=');
            if (ecp) {
                strncpy(acron, buff, ecp - buff);
                acron[ecp - buff] = '\0';
                strcpy(vb, ecp + 1);
                if (0 == strcmp("-1", vb))
                    ivp->val = -1;
                else {
                    ivp->val = get_num(vb);
                    if (-1 == ivp->val) {
                        fprintf(stderr, "build_mp_settings: unable to "
                                "decode: %s value\n", buff);
                        fprintf(stderr, "    expected: <acronym>[=<val>]\n");
                        return -1;
                    }
                }
            } else {
                strcpy(acron, buff);
                ivp->val = ((clear || get) ? 0 : -1);
            }
            from = 0;
            cont = 0;
            prev_mpi = NULL;
            if (get) {
                do {
                    mpi = find_mitem_by_acron(acron, &from);
                    if (NULL == mpi) {
                        if (cont) {
                            mpi = prev_mpi;
                            break;
                        } else
                            fprintf(stderr, "build_mp_settings: couldn't "
                                    "find acronym: %s\n", acron);
                        return -1;
                    }
                    if (mps->page_num < 0) {
                        mps->page_num = mpi->page_num;
                        mps->subpage_num = mpi->subpage_num;
                        break;
                    }
                    cont = 1;
                    prev_mpi = mpi;
                } while ((mps->page_num != mpi->page_num) ||
                         (mps->subpage_num != mpi->subpage_num));
            } else {
                do {
                    mpi = find_mitem_by_acron(acron, &from);
                    if (NULL == mpi) {
                        if (cont) {
                            fprintf(stderr, "build_mp_settings: mode page "
                                    "of acronym: %s [0x%x,0x%x] doesn't "
                                    "match prior\n", acron,
                                    prev_mpi->page_num,
                                    prev_mpi->subpage_num);
                            fprintf(stderr, "    mode page: 0x%x,0x%x\n",
                                    mps->page_num, mps->subpage_num);
                        } else
                            fprintf(stderr, "build_mp_settings: couldn't "
                                    "find acronym: %s\n", acron);
                        return -1;
                    }
                    if (mps->page_num < 0) {
                        mps->page_num = mpi->page_num;
                        mps->subpage_num = mpi->subpage_num;
                        break;
                    }
                    cont = 1;
                    prev_mpi = mpi;
                } while ((mps->page_num != mpi->page_num) ||
                         (mps->subpage_num != mpi->subpage_num));
            }
            if (mpi->num_bits < 32)
                ivp->val &= (1 << mpi->num_bits) - 1;
            ivp->mpi = *mpi;    /* struct assignment */
        } else {    /* expect "byte_off:bit_off:num_bits[=<val>]" */
            if ((0 == strncmp("0x", buff, 2)) ||
                (0 == strncmp("0X", buff, 2))) {
                num = sscanf(buff + 2, "%x:%d:%d=%s", &u,
                             &ivp->mpi.start_bit, &ivp->mpi.num_bits, vb);
                ivp->mpi.start_byte = u;
            } else
                num = sscanf(buff, "%d:%d:%d=%s", &ivp->mpi.start_byte,
                             &ivp->mpi.start_bit, &ivp->mpi.num_bits, vb);
            if (num < 3) {
                fprintf(stderr, "build_mp_settings: unable to decode: %s\n",
                        buff);
                fprintf(stderr, "    expected: byte_off:bit_off:num_bits[="
                        "<val>]\n");
                return -1;
            }
            if (3 == num)
                ivp->val = ((clear || get) ? 0 : -1);
            else {
                if (0 == strcmp("-1", vb))
                    ivp->val = -1;
                else {
                    ivp->val = get_num(vb);
                    if (-1 == ivp->val) {
                        fprintf(stderr, "build_mp_settings: unable to "
                                "decode byte_off:bit_off:num_bits value\n");
                        return -1;
                    }
                }
            }
            if (ivp->mpi.start_byte < 0) {
                fprintf(stderr, "build_mp_settings: need positive start "
                        "byte offset\n");
                return -1;
            }
            if ((ivp->mpi.start_bit < 0) || (ivp->mpi.start_bit > 7)) {
                fprintf(stderr, "build_mp_settings: need start bit in "
                        "0..7 range (inclusive)\n");
                return -1;
            }
            if ((ivp->mpi.num_bits < 1) || (ivp->mpi.num_bits > 32)) {
                fprintf(stderr, "build_mp_settings: need number of bits in "
                        "1..32 range (inclusive)\n");
                return -1;
            }
            if (mps->page_num < 0) {
                fprintf(stderr, "build_mp_settings: need '--page=' option "
                        "for mode page number\n");
                return -1;
            } else if (get) {
                ivp->mpi.page_num = mps->page_num;
                ivp->mpi.subpage_num = mps->subpage_num;
            }
            if (ivp->mpi.num_bits < 32)
                ivp->val &= (1 << ivp->mpi.num_bits) - 1;
        }
        ++mps->num_it_vals;
        if (ncp)
            cp = ncp + 1;
        else
            break;
    }
    return 0;
}

int main(int argc, char * argv[])
{
    int sg_fd, res, c, pdt, flags;
    int six_byte_cdb = 0;
    int all = 0;
    const char * clear_str = NULL;
    const char * get_str = NULL;
    const char * set_str = NULL;
    int defaults = 0;
    int dummy = 0;
    int enumerate = 0;
    int hex = 0;
    int inquiry = 0;
    int long_out = 0;
    int saved = 0;
    int verbose = 0;
    char device_name[256];
    int pn = -1;
    int spn = -1;
    int rw = 0;
    struct sg_simple_inquiry_resp sir;
    const struct values_name_t * vnp;
    struct mode_page_settings mp_settings; 
    char * cp;
    int ret = 1;

    memset(device_name, 0, sizeof(device_name));
    memset(&mp_settings, 0, sizeof(mp_settings));
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "6ac:Ddeg:hHilp:s:SvV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case '6':
            six_byte_cdb = 1;
            break;
        case 'a':
            all = 1;
            break;
        case 'c':
            clear_str = optarg;
            rw = 1;
            break;
        case 'd':
            dummy = 1;
            break;
        case 'D':
            defaults = 1;
            rw = 1;
            break;
        case 'e':
            enumerate = 1;
            break;
        case 'g':
            get_str = optarg;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            hex = 1;
            break;
        case 'i':
            inquiry = 1;
            break;
        case 'l':
            long_out = 1;
            break;
        case 'p':
            if (isalpha(optarg[0])) {
                vnp = find_mp_by_acron(optarg);
                if (NULL == vnp) {
                    fprintf(stderr, "mode page acronym not found\n");
                    return 1;
                }
                pn = vnp->value;
                spn = vnp->subvalue;
            } else {
                cp = strchr(optarg, ',');
                pn = get_num(optarg);
                if ((pn < 0) || (pn > 255)) {
                    fprintf(stderr, "Bad page code value after '-p' "
                            "switch\n");
                    return 1;
                }
                if (cp) {
                    spn = get_num(cp + 1);
                    if ((spn < 0) || (spn > 255)) {
                        fprintf(stderr, "Bad page code value after "
                                "'-p' switch\n");
                        return 1;
                    }
                } else
                    spn = 0;
            }
            break;
        case 's':
            set_str = optarg;
            rw = 1;
            break;
        case 'S':
            saved = 1;
            rw = 1;
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
/* think about --get= with --enumerate */
    if (pn < 0) {
        mp_settings.page_num = -1;
        mp_settings.subpage_num = -1;
    } else {
        mp_settings.page_num = pn;
        mp_settings.subpage_num = spn;
    }
    if (get_str) {
        if (set_str || clear_str) {
            fprintf(stderr, "'--get=' can't be used with '--set=' or "
                    "'--clear='\n");
            return 1;
        }
        if (build_mp_settings(get_str, &mp_settings, 0, 1))
            return 1;
    }
    if (enumerate) {
        if (device_name[0] || set_str || clear_str || get_str || saved)
            printf("Most option including <scsi_disk> are ignored when "
                   "'--enumerate' is given\n");
        if (pn < 0) {
            printf("Mode pages:\n");
            list_mps();
        }
        if (all || (pn >= 0))
            list_mitems(pn, spn);
        return 0;
    }
    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }

    if (inquiry) {
        fprintf(stderr, "INQUIRY VPD pages not supported yet\n");
        return 1;
    }
    if (defaults && (set_str || clear_str || get_str)) {
        fprintf(stderr, "'--get=', '--set=' or '--clear=' can't be used "
                "with '--defaults'\n");
        return 1;
    }

    if (set_str) {
        if (build_mp_settings(set_str, &mp_settings, 0, 0))
            return 1;
    }
    if (clear_str) {
        if (build_mp_settings(clear_str, &mp_settings, 1, 0))
            return 1;
    }

    if (verbose && (mp_settings.num_it_vals > 0)) {
        struct mode_page_it_val * ivp;
        int k;

        printf("mp_settings: page,subpage=0x%x,0x%x  num=%d\n",
               mp_settings.page_num, mp_settings.subpage_num,
               mp_settings.num_it_vals);
        for (k = 0; k < mp_settings.num_it_vals; ++k) {
            ivp = &mp_settings.it_vals[k];
            if (get_str)
                printf("  [0x%x,0x%x]  byte_off=0x%x, bit_off=%d, num_bits"
                       "=%d  val=%d  acronym: %s\n", ivp->mpi.page_num,
                       ivp->mpi.subpage_num, ivp->mpi.start_byte,
                       ivp->mpi.start_bit, ivp->mpi.num_bits, ivp->val,
                       (ivp->mpi.acron ? ivp->mpi.acron : ""));
            else
                printf("  byte_off=0x%x, bit_off=%d, num_bits=%d "
                       " val=%d  acronym: %s\n", ivp->mpi.start_byte,
                       ivp->mpi.start_bit, ivp->mpi.num_bits, ivp->val,
                       (ivp->mpi.acron ? ivp->mpi.acron : ""));
        }
    }

    if (defaults && (pn < 0)) {
        fprintf(stderr, "to set defaults, the '--page=' option must "
                "be used\n");
        return 1;
    }

    flags = (O_NONBLOCK | (rw ? O_RDWR : O_RDONLY));
    sg_fd = open(device_name, flags);
    if (sg_fd < 0) {
        fprintf(stderr, ME "open error: %s, flags=0x%x: ", device_name,
                flags);
        perror("");
        return 1;
    } 

    if (sg_simple_inquiry(sg_fd, &sir, 0, verbose)) {
        fprintf(stderr, "SCSI INQUIRY command failed on %s\n", device_name);
        goto err_out;
    }
    pdt = sir.peripheral_type;
    if (0 == hex) {
        printf("    %s: %.8s  %.16s  %.4s",
               device_name, sir.vendor, sir.product, sir.revision);
        if (0 != pdt)
            printf("  [pdt=%d]", pdt);
        printf("\n");
        if (! ((0 == pdt) || (4 == pdt) || (7 == pdt) || (0xe == pdt))) {
            fprintf(stderr, "        expected disk device type, got %s\n",
                    scsi_ptype_strs[pdt]);
        }
    }

    if ((pn > 0x3e) || (spn > 0xfe)) {
        fprintf(stderr, "Allowable mode page numbers are 0 to 62\n");
        fprintf(stderr, "  Allowable mode subpage numbers are 0 to 254\n");
        goto err_out;
    }
    if (defaults) {
        res = set_mp_defaults(sg_fd, pn, spn, saved, six_byte_cdb, dummy,
                              verbose);
        if (0 != res)
            goto err_out;
    } else if (set_str || clear_str) {
        if (mp_settings.num_it_vals < 1) {
            fprintf(stderr, "no parameters found to set or clear\n");
            goto err_out;
        }
        res = change_mode_page(sg_fd, saved, six_byte_cdb, &mp_settings,
                               dummy, verbose);
        if (0 != res)
            goto err_out;
    } else if (get_str) {
        if (mp_settings.num_it_vals < 1) {
            fprintf(stderr, "no parameters found to get\n");
            goto err_out;
        }
        get_mode_info(sg_fd, six_byte_cdb, &mp_settings, long_out, hex,
                      verbose);
    } else
        print_mode_info(sg_fd, six_byte_cdb, pn, spn, ((pn >= 0) ? 1 : all),
                        long_out, hex, verbose);
    ret = 0;

err_out:
    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
        return 1;
    }
    return ret;
}

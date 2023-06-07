/* A utility program originally written for the Linux OS SCSI subsystem.
 *  Copyright (C) 2000-2023 D. Gilbert
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This program outputs information provided by a SCSI LOG SENSE command
 * and in some cases issues a LOG SELECT command.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>
#include <errno.h>
#include <sys/stat.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_lib_names.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

#include "sg_logs.h"


/* Tape usage: Vendor specific (LTO-5 and LTO-6): 0x30 */
bool
show_tape_usage_page(const uint8_t * resp, int len, struct opts_t * op,
                     sgj_opaque_p jop)
{
    int k, num, extra;
    uint64_t ull;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[256];
    static const int blen = sizeof(b);
    static const char * tu_lp = "Tape usage log page";

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed %s\n", __func__, tu_lp);
        return false;
    }
    if (op->verbose || ((0 == op->do_raw) &&
        ((0 == op->do_hex) || (op->do_hex > 3)))) {
        const char * leadin = (op->do_hex > 3) ? "# " : "";

        sgj_pr_hr(jsp, "%s%s  (LTO-5 and LTO-6 specific) [0x30]\n", leadin,
                  tu_lp);
   }
    if ((op->do_hex > 2) || op->do_raw > 1) {
        if (op->do_raw > 1)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
   if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, tu_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "tape_usage_log_parameters");
    }

    for (k = num; k > 0; k -= extra, bp += extra) {
        int pc = sg_get_unaligned_be16(bp + 0);

        extra = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw > 0) {
            dStrRaw(bp, extra);
            goto skip;
        } else if (op->do_hex) {
            hex2stdout(bp, extra, op->dstrhex_no_ascii);
            goto skip;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, NULL);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        ull = 0;

        switch (bp[3]) {
        case 2:
            ull = sg_get_unaligned_be16(bp + 4);
            break;
        case 4:
            ull = sg_get_unaligned_be32(bp + 4);
            break;
        case 8:
            ull = sg_get_unaligned_be64(bp + 4);
            break;
        }
        ccp = NULL;
        switch (pc) {
        case 0x01:
            if (extra == 8)
                ccp = "Thread count";
            break;
        case 0x02:
            if (extra == 12)
                ccp = "Total data sets written";
            break;
        case 0x03:
            if (extra == 8)
                ccp = "Total write retries";
            break;
        case 0x04:
            if (extra == 6)
                ccp = "Total unrecovered write errors";
            break;
        case 0x05:
            if (extra == 6)
                ccp = "Total suspended writes";
            break;
        case 0x06:
            if (extra == 6)
                ccp = "Total fatal suspended writes";
            break;
        case 0x07:
            if (extra == 12)
                ccp = "Total data sets read";
            break;
        case 0x08:
            if (extra == 8)
                ccp = "Total read retries";
            break;
        case 0x09:
            if (extra == 6)
                ccp = "Total unrecovered read errors";
            break;
        case 0x0a:
            if (extra == 6)
                ccp = "Total suspended reads";
            break;
        case 0x0b:
            if (extra == 6)
                ccp = "Total fatal suspended reads";
            break;
        default:
            sgj_pr_hr(jsp, "  %s %s = 0x%x, contents in hex:\n", unkn_s,
                      param_c, pc);
            hex2str(bp, extra, "    ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json)
                sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp, extra);
            break;
        }
        if (ccp)
            sgj_haj_vi(jsp, jo3p, 2, ccp, SGJ_SEP_COLON_1_SPACE, ull,
                       false);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
skip:
        if (op->filter_given)
            break;
    }
    return true;
}

/* 0x30 */
bool
show_hgst_perf_page(const uint8_t * resp, int len, struct opts_t * op,
                    sgj_opaque_p jop)
{
    bool valid = false;
    int num, pl;
    uint32_t ul;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * hwpc_lp = "HGST/WDC performance counters log page";

    if (op->verbose || ((0 == op->do_raw) &&
        ((0 == op->do_hex) || (op->do_hex > 3)))) {
        const char * leadin = (op->do_hex > 3) ? "# " : "";

        sgj_pr_hr(jsp, "%s%s  [0x30]\n", leadin, hwpc_lp);
    }
    if ((op->do_hex > 2) || op->do_raw > 1) {
        if (op->do_raw > 1)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
    num = len - 4;
    if (num < 0x30) {
        pr2serr("%s too short (%d) < 48\n", hwpc_lp, num);
        return valid;
    }
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, hwpc_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                        "performance_counters_log_parameters");
    }

    while (num > 3) {
        int pc = sg_get_unaligned_be16(bp + 0);

        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw > 0) {
            dStrRaw(bp, pl);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            break;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, NULL);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        switch (pc) {
        case 0:
            valid = true;
            sgj_haj_vi(jsp, jo2p, 3, "Zero Seeks", SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be16(bp + 4), false);
            ul = sg_get_unaligned_be16(bp + 6);
            sgj_pr_hr(jsp, "  Seeks >= 2/3 = %u\n", ul);
            sgj_js_nv_i(jsp, jo3p, "seeks_ge_2_3", ul);
            ul = sg_get_unaligned_be16(bp + 8);
            sgj_pr_hr(jsp, "  Seeks >= 1/3 and < 2/3 = %u\n", ul);
            sgj_js_nv_i(jsp, jo3p, "seeks_ge_1_3_and_lt_2_3", ul);
            ul = sg_get_unaligned_be16(bp + 10);
            sgj_pr_hr(jsp, "  Seeks >= 1/6 and < 1/3 = %u\n", ul);
            sgj_js_nv_i(jsp, jo3p, "seeks_ge_1_6_and_lt_1_3", ul);
            ul = sg_get_unaligned_be16(bp + 12);
            sgj_pr_hr(jsp, "  Seeks >= 1/12 and < 1/6 = %u\n", ul);
            sgj_js_nv_i(jsp, jo3p, "seeks_ge_1_12_and_lt_1_6", ul);
            ul = sg_get_unaligned_be16(bp + 14);
            sgj_pr_hr(jsp, "  Seeks > 0 and < 1/12 = %u\n", ul);
            sgj_js_nv_i(jsp, jo3p, "seeks_ge_0_and_lt_1_12", ul);
            sgj_haj_vi(jsp, jo3p, 2, "Overrun counter",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be16(bp + 20), false);
            sgj_haj_vi(jsp, jo3p, 2, "Underrun counter",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be16(bp + 22), false);
            sgj_haj_vi(jsp, jo3p, 2, "Device cache full read hits",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                      sg_get_unaligned_be32(bp + 24), false);
            sgj_haj_vi(jsp, jo3p, 2, "Device cache partial read hits",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                      sg_get_unaligned_be32(bp + 28), false);
            sgj_haj_vi(jsp, jo3p, 2, "Device cache write hits",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                      sg_get_unaligned_be32(bp + 32), false);
            sgj_haj_vi(jsp, jo3p, 2, "Device cache fast writes",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                      sg_get_unaligned_be32(bp + 36), false);
            sgj_haj_vi(jsp, jo3p, 2, "Device cache read misses",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                      sg_get_unaligned_be32(bp + 40), false);
            break;
        default:
            valid = false;
            snprintf(b, blen, "Unknown HGST/WDC %s", param_c);
            sgj_haj_vi(jsp, jo3p, 2, b, SGJ_SEP_SPACE_EQUAL_SPACE, pc, true);
            break;
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return valid;
}

/* Tape capacity: vendor specific (LTO-5 and LTO-6 ?): 0x31 */
bool
show_tape_capacity_page(const uint8_t * resp, int len,
                        struct opts_t * op, sgj_opaque_p jop)
{
    int k, num, extra;
    uint32_t u;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[144];
    static const int blen = sizeof(b);
    static const char * tc_lp = "Tape capacity log page";

    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed %s\n", __func__, tc_lp);
        return false;
    }
    if ((op->do_hex > 2) || op->do_raw > 1) {
        if (op->do_raw > 1)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
    if (op->verbose || ((0 == op->do_raw) &&
        ((0 == op->do_hex) || (op->do_hex > 3)))) {
        const char * leadin = (op->do_hex > 3) ? "# " : "";

        sgj_pr_hr(jsp, "%s%s  (LTO-5 and LTO-6 specific) [0x31]\n", leadin,
                  tc_lp);
    }
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, tc_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "tape_capacity_log_parameters");
    }

    for (k = num; k > 0; k -= extra, bp += extra) {
        int pc = sg_get_unaligned_be16(bp + 0);

        extra = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw > 0) {
            dStrRaw(bp, extra);
            goto skip;
        } else if (op->do_hex) {
            hex2stdout(bp, extra, op->dstrhex_no_ascii);
            goto skip;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, NULL);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        if (extra != 8)
            continue;
        u = sg_get_unaligned_be32(bp + 4);
        snprintf(b, blen, "  ");

        ccp = NULL;
        switch (pc) {
        case 0x01:
            ccp = "Main partition remaining capacity";
            break;
        case 0x02:
            ccp = "Alternate partition remaining capacity";
            break;
        case 0x03:
            ccp = "Main partition maximum capacity";
            break;
        case 0x04:
            ccp= "Alternate partition maximum capacity";
            break;
        default:
            sgj_pr_hr(jsp, "  unknown %s = 0x%x, contents in hex:\n",
                      param_c, pc);
            hex2str(bp, extra, "    ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "%s\n", b);
            if (jsp->pr_as_json)
                sgj_js_nv_hex_bytes(jsp, jo3p, in_hex, bp, extra);
            break;
        }
        if (ccp) {
            sgj_pr_hr(jsp, "  %s (in MiB): %u\n", ccp, u);
            if (jsp->pr_as_json)
                sgj_js_nv_ihex_nex(jsp, jo3p, sgj_convert2snake(ccp, b, blen),
                                   u, false, "[unit: MibiByte]");
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
skip:
        if (op->filter_given)
            break;
    }
    return true;
}

/* Data compression: originally vendor specific 0x32 (LTO-5), then
 * ssc-4 standardizes it at 0x1b <dc> */
bool
show_data_compression_page(const uint8_t * resp, int len,
                           struct opts_t * op, sgj_opaque_p jop)
{
    bool is_x100, is_pr;
    int k, pl, num, extra, pc, pg_code;
    uint64_t ull;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[512];
    static const int blen = sizeof(b);
    static const char * const dc_lp = "Data compression log page";

    pg_code = resp[0] & 0x3f;
    num = len - 4;
    bp = &resp[0] + 4;
    if (num < 4) {
        pr2serr("%s: badly formed data compression page\n", __func__);
        return false;
    }
    if (op->verbose || ((0 == op->do_raw) &&
        ((0 == op->do_hex) || (op->do_hex > 3)))) {
        const char * leadin = (op->do_hex > 3) ? "# " : "";

        if (0x1b == pg_code)
            sgj_pr_hr(jsp, "%s%s  (ssc-4) [0x1b]\n", leadin, dc_lp);
        else
            sgj_pr_hr(jsp, "%s%s  (LTO-5 specific) [0x%x]\n", leadin, dc_lp,
                       pg_code);
    }
    if ((op->do_hex > 2) || op->do_raw > 1) {
        if (op->do_raw > 1)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, dc_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "data_compression_log_parameters");
    }

    for (k = num; k > 0; k -= extra, bp += extra) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3];
        extra = pl + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                continue;
        }
        if (op->do_raw > 0) {
            dStrRaw(bp, extra);
            break;
        } else if (op->do_hex) {
            hex2stdout(bp, extra, op->dstrhex_no_ascii);
            break;
        }
        if ((0 == pl) || (pl > 8)) {
            pr2serr("badly formed data compression log parameter\n");
            pr2serr("  %s = 0x%x, contents in hex:\n", param_c, pc);
            hex2stderr(bp, extra, op->dstrhex_no_ascii);
            goto skip_para;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }
        /* variable length integer, max length 8 bytes */
        ull = sg_get_unaligned_be(pl - 4, bp + 4);
        ccp = NULL;
        is_x100 = false;
        is_pr = false;

        switch (pc) {
        case 0x00:
            ccp = "Read compression ratio";
            is_x100 = true;
            break;
        case 0x01:
            ccp = "Write compression ratio";
            is_x100 = true;
            break;
        case 0x02:
            ccp = "Megabytes transferred to server";
            break;
        case 0x03:
            ccp = "Bytes transferred to server";
            break;
        case 0x04:
            ccp = "Megabytes read from tape";
            break;
        case 0x05:
            ccp = "Bytes read from tape";
            break;
        case 0x06:
            ccp = "Megabytes transferred from server";
            break;
        case 0x07:
            ccp = "Bytes transferred from server";
            break;
        case 0x08:
            ccp = "Megabytes written to tape";
            break;
        case 0x09:
            ccp = "Bytes written to tape";
            break;
        case 0x100:
            ccp = "Data compression enabled";
            break;
        default:
            sgj_pr_hr(jsp, "  unknown %s = 0x%x, contents in hex:\n", param_c,
                      pc);
            hex2str(bp + 4, pl - 4, "    ", op->h2s_oformat, blen, b);
            sgj_pr_hr(jsp, "%s\n", b);
            is_pr = true;
            break;
        }
        if (! is_pr)
            sgj_pr_hr(jsp, "  %s%s: %" PRIu64 "\n", ccp,
                      (is_x100 ? " x100" : ""), ull);
        if (jsp->pr_as_json) {
            if (NULL == ccp) {
                if (pc >= 0xf000)
                    ccp = vend_spec;
                else
                    ccp = rsv_s;
            }
            if (is_x100)
                sgj_js_nv_ihexstr_nex(jsp, jo3p, param_c_sn, pc, false,
                                      NULL, ccp, "ratio x 100");
            else
                sgj_js_nv_ihexstr(jsp, jo3p, param_c_sn, pc, NULL, ccp);
            sgj_js_nv_i(jsp, jo3p, "data_compression_counter", ull);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
skip_para:
        if (op->filter_given)
            break;
    }
    return true;
}

/* 0x37 */
bool
show_seagate_cache_page(const uint8_t * resp, int len,
                        struct opts_t * op, sgj_opaque_p jop)
{
    bool skip = false;
    int num, pl, pc;
    int bsti = 0;       /* BS filter */
    uint64_t ull;
    const char * ccp;
    const char * jcp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * scs_lp = "Seagate cache statistics log page";

    if (op->verbose || ((0 == op->do_raw) &&
        ((0 == op->do_hex) || (op->do_hex > 3)))) {
        const char * leadin = (op->do_hex > 3) ? "# " : "";

        if (resp[1] > 0) {
            sgj_pr_hr(jsp, "%sSuspicious page 0x37, SPF=0 but subpage=0x%x\n",
                      leadin, resp[1]);
            if (op->verbose)
                sgj_pr_hr(jsp, "%s... try vendor=wdc\n", leadin);
            if (op->do_brief > 0)
                return true;
        } else
            sgj_pr_hr(jsp, "%s%s [0x37]\n", leadin, scs_lp);
    }
    if ((op->do_hex > 2) || op->do_raw > 1) {
        if (op->do_raw > 1)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, scs_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "cache_statistics_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw > 0) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        ccp = NULL;
        jcp = NULL;
        switch (pc) {
        case 0:
            ++bsti;
            if (bsti < 2)
                ccp = "Blocks sent to initiator";
            else
                skip = true;
            break;
        case 1:
            ccp = "Blocks received from initiator";
            break;
        case 2:
            ccp = "Blocks read from cache and sent to initiator";
            break;
        case 3:
            ccp = "Number of read and write commands whose size "
                  "<= segment size";
            jcp = "number_rw_commands_le_segment_size";
            break;
        case 4:
            ccp = "Number of read and write commands whose size "
                  "> segment size";
            jcp = "number_rw_commands_gt_segment_size";
            break;
        default:
            snprintf(b, blen, "Unknown Seagate %s = 0x%x", param_c, pc);
            ccp = b;
            break;
        }
        if (skip)
            skip = false;
        else {
            ull = sg_get_unaligned_be(pl - 4, bp + 4);
            sgj_pr_hr(jsp, "  %s = %" PRIu64 "\n", ccp, ull);
            if (NULL == jcp) {
                sgj_convert2snake(ccp, b, blen);
                jcp = b;
            }
            sgj_js_nv_ihex(jsp, jo3p, jcp, ull);
            if (op->do_pcb)
                sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        }
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* 0x3d,0x3 */
bool
show_seagate_farm_page(const uint8_t * resp, int len,
                       struct opts_t * op, sgj_opaque_p jop)
{
    int num, pl, pc;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[128];
    static const int blen = sizeof(b);
    static const char * sf_lp = "Seagate farm log page";

    if (op->verbose || ((0 == op->do_raw) &&
        ((0 == op->do_hex) || (op->do_hex > 3)))) {
        const char * leadin = (op->do_hex > 3) ? "# " : "";

        sgj_pr_hr(jsp, "%s%s [0x3d,0x3]\n", leadin, sf_lp);
    }
    if ((op->do_hex > 2) || op->do_raw > 1) {
        if (op->do_raw > 1)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, sf_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p, "farm_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw > 0) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
            sgj_js_nv_ihex(jsp, jo3p, param_c_sn, pc);
            sgj_js_nv_ihex(jsp, jo3p, "parameter_length", pl - 4);
        }
        sgj_pr_hr(jsp, "  %s: %d\n", param_c, pc);
        sgj_pr_hr(jsp, "    Parameter length: %d\n", pl - 4);

        // Wow 0 through 82 (inclusive) parameters, many 160 bytes long
        switch (pc) {
        case 0:
            sgj_haj_vs(jsp, jo3p, 4, "name", SGJ_SEP_COLON_1_SPACE,
                       "log header");
            break;
        case 1:
            sgj_haj_vs(jsp, jo3p, 4, "name", SGJ_SEP_COLON_1_SPACE,
                       "Drive Information");
            break;
        case 2:
            sgj_haj_vs(jsp, jo3p, 4, "name", SGJ_SEP_COLON_1_SPACE,
                       "Workload Statistics");
            break;
        case 3:
            sgj_haj_vs(jsp, jo3p, 4, "name", SGJ_SEP_COLON_1_SPACE,
                       "Error Statistics");
            break;
        case 4:
            sgj_haj_vs(jsp, jo3p, 4, "name", SGJ_SEP_COLON_1_SPACE,
                       "Environment Statistics");
            break;
        case 5:
            sgj_haj_vs(jsp, jo3p, 4, "name", SGJ_SEP_COLON_1_SPACE,
                       "Reliability Statistics");
            break;
        case 6:
            sgj_haj_vs(jsp, jo3p, 4, "name", SGJ_SEP_COLON_1_SPACE,
                       "Drive Information Continued");
            break;
        case 7:
            sgj_haj_vs(jsp, jo3p, 4, "name", SGJ_SEP_COLON_1_SPACE,
                       "Environment Information Continued");
            break;
        default:
            break;
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

/* 0x37 */
bool
show_hgst_misc_page(const uint8_t * resp, int len, struct opts_t * op,
                    sgj_opaque_p jop)
{
    bool valid = false;
    int num, pl, pc;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    char b[168];
    static const int blen = sizeof(b);
    static const char * hm_lp = "HGST/WDC miscellaneous log page";

    if (op->verbose || ((0 == op->do_raw) &&
        ((0 == op->do_hex) || (op->do_hex > 3)))) {
        const char * leadin = (op->do_hex > 3) ? "# " : "";

        sgj_pr_hr(jsp, "%s%s [0x37, 0x%x]\n", leadin, hm_lp,
                  op->decod_subpg_code);
    }
    if ((op->do_hex > 2) || op->do_raw > 1) {
        if (op->do_raw > 1)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
    num = len - 4;
    if (num < 0x30) {
        pr2serr("%s too short (%d) < 48\n", hm_lp, num);
        return valid;
    }
    bp = &resp[0] + 4;
    if (jsp->pr_as_json)
        jo2p = sg_log_js_hdr(jsp, jop, hm_lp, resp);

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw > 0) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json && op->do_pcb)
            js_pcb(jsp, jo2p, bp[2]);

        switch (pc) {
        case 0:
            valid = true;
            sgj_haj_vi(jsp, jo2p, 2, "Power on hours",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be32(bp + 4), false);
            sgj_haj_vi(jsp, jo2p, 2, "Total bytes read",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be64(bp + 8), false);
                   // sg_get_unaligned_be64(bp + 8));
            sgj_haj_vi(jsp, jo2p, 2, "Total bytes written",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be64(bp + 16), false);
            sgj_haj_vi(jsp, jo2p, 2, "Max Drive Temp (Celsius)",
                       SGJ_SEP_SPACE_EQUAL_SPACE, bp[24], false);
            sgj_haj_vi(jsp, jo2p, 2, "GList size", SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be16(bp + 25), false);
            sgj_haj_vi(jsp, jo2p, 2, "Number of Information Exceptions",
                       SGJ_SEP_SPACE_EQUAL_SPACE, bp[27], false);
            sgj_haj_vi(jsp, jo2p, 2, "MED EXC", SGJ_SEP_SPACE_EQUAL_SPACE,
                       !! (0x80 & bp[28]), false);
            sgj_haj_vi(jsp, jo2p, 2, "HDW EXC", SGJ_SEP_SPACE_EQUAL_SPACE,
                       !! (0x40 & bp[28]), false);
            sgj_haj_vi(jsp, jo2p, 2, "Total Read Commands",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be64(bp + 29), false);
            sgj_haj_vi(jsp, jo2p, 2, "Total Write Commands",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be64(bp + 37), false);
            sgj_haj_vi(jsp, jo2p, 2, "Flash Correction Count",
                       SGJ_SEP_SPACE_EQUAL_SPACE,
                       sg_get_unaligned_be16(bp + 46), false);
            break;
        default:
            valid = false;
            snprintf(b, blen, "Unknown HGST/WDC %s", param_c);
            sgj_haj_vi(jsp, jo2p, 2, b, SGJ_SEP_SPACE_EQUAL_SPACE, pc, false);
            break;
        }
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return valid;
}

/* 0x3e */
bool
show_seagate_factory_page(const uint8_t * resp, int len,
                          struct opts_t * op, sgj_opaque_p jop)
{
    bool valid = false;
    int num, pl, pc;
    uint64_t ull;
    const char * ccp;
    const uint8_t * bp;
    sgj_state * jsp = &op->json_st;
    sgj_opaque_p jo2p = NULL;
    sgj_opaque_p jo3p = NULL;
    sgj_opaque_p jap = NULL;
    char b[168];
    static const int blen = sizeof(b);
    static const char * shf_lp = "Seagate/Hitachi factory log page";

    if (op->verbose || ((0 == op->do_raw) &&
        ((0 == op->do_hex) || (op->do_hex > 3)))) {
        const char * leadin = (op->do_hex > 3) ? "# " : "";

        sgj_pr_hr(jsp, "%s%s [0x3e]\n", leadin, shf_lp);
    }
    if ((op->do_hex > 2) || op->do_raw > 1) {
        if (op->do_raw > 1)
            dStrRaw(resp, len);
        else
            hex2stdout(resp, len, op->dstrhex_no_ascii);
        return true;
    }
    num = len - 4;
    bp = &resp[0] + 4;
    if (jsp->pr_as_json) {
        jo2p = sg_log_js_hdr(jsp, jop, shf_lp, resp);
        jap = sgj_named_subarray_r(jsp, jo2p,
                                   "factory_log_parameters");
    }

    while (num > 3) {
        pc = sg_get_unaligned_be16(bp + 0);
        pl = bp[3] + 4;
        if (op->filter_given) {
            if (pc != op->filter)
                goto skip;
        }
        if (op->do_raw > 0) {
            dStrRaw(bp, pl);
            goto filter_chk;
        } else if (op->do_hex) {
            hex2stdout(bp, pl, op->dstrhex_no_ascii);
            goto filter_chk;
        }
        if (jsp->pr_as_json) {
            jo3p = sgj_new_unattached_object_r(jsp);
            if (op->do_pcb)
                js_pcb(jsp, jo3p, bp[2]);
        }

        valid = true;
        ccp = NULL;
        switch (pc) {
        case 0:
            ccp = "number of minutes powered up";
            break;
        case 8:
            ccp = "number of minutes until next internal SMART test";
            break;
        default:
            valid = false;
            snprintf(b, blen, "Unknown Seagate/Hitachi %s", param_c);
            break;
        }
        if (valid) {
            ull = sg_get_unaligned_be(pl - 4, bp + 4);
            sgj_haj_vi(jsp, jo3p, 2, ccp, SGJ_SEP_SPACE_EQUAL_SPACE, ull,
                       false);
        } else
            sgj_haj_vi(jsp, jo2p, 2, b, SGJ_SEP_SPACE_EQUAL_SPACE, pc, true);

        if (jsp->pr_as_json)
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo3p);
        if (op->do_pcb)
            sgj_pr_hr(jsp, "        <%s>\n", get_pcb_str(bp[2], b, blen));
filter_chk:
        if (op->filter_given)
            break;
skip:
        num -= pl;
        bp += pl;
    }
    return true;
}

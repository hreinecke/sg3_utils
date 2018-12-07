/*
 * sg_rdac
 *
 * Retrieve / set RDAC options.
 *
 * Copyright (C) 2006-2018 Hannes Reinecke <hare@suse.de>
 *
 * Based on sg_modes.c and sg_emc_trespass.c; credits from there apply.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"


static const char * version_str = "1.17 20180512";

uint8_t mode6_hdr[] = {
    0x75, /* Length */
    0, /* medium */
    0, /* params */
    8, /* Block descriptor length */
};

uint8_t mode10_hdr[] = {
    0x01, 0x18, /* Length */
    0, /* medium */
    0, /* params */
    0, 0, /* reserved */
    0, 0, /* block descriptor length */
};

uint8_t block_descriptor[] = {
    0, /* Density code */
    0, 0, 0, /* Number of blocks */
    0, /* Reserved */
    0, 0x02, 0, /* 512 byte blocks */
};

struct rdac_page_common {
    uint8_t  current_serial[16];
    uint8_t  alternate_serial[16];
    uint8_t  current_mode_msb;
    uint8_t  current_mode_lsb;
    uint8_t  alternate_mode_msb;
    uint8_t  alternate_mode_lsb;
    uint8_t  quiescence;
    uint8_t  options;
};

struct rdac_legacy_page {
    uint8_t  page_code;
    uint8_t  page_length;
    struct rdac_page_common attr;
    uint8_t  lun_table[32];
    uint8_t  lun_table_exp[32];
    unsigned short reserved;
};

struct rdac_expanded_page {
    uint8_t  page_code;
    uint8_t  subpage_code;
    uint8_t  page_length[2];
    struct rdac_page_common attr;
    uint8_t  lun_table[256];
    uint8_t  reserved[2];
};

static int do_verbose = 0;

static void dump_mode_page( uint8_t *page, int len )
{
        int i, k;

        for (k = 0; k < len; k += 16) {

                printf("%x:",k / 16);
                for (i = 0; i < 16; i++) {
                        printf(" %02x", page[k + i]);
                        if (k + i >= len) {
                                printf("\n");
                                break;
                        }
                }
                printf("\n");
        }

}

#define MX_ALLOC_LEN (1024 * 4)
#define RDAC_CONTROLLER_PAGE 0x2c
#define RDAC_CONTROLLER_PAGE_LEN 0x68
#define LEGACY_PAGE 0x00
#define EXPANDED_LUN_SPACE_PAGE 0x01
#define EXPANDED_LUN_SPACE_PAGE_LEN 0x128
#define RDAC_FAIL_ALL_PATHS 0x1
#define RDAC_FAIL_SELECTED_PATHS 0x2
#define RDAC_FORCE_QUIESCENCE 0x2
#define RDAC_QUIESCENCE_TIME 10

static int fail_all_paths(int fd, bool use_6_byte)
{
        struct rdac_legacy_page *rdac_page;
        struct rdac_expanded_page *rdac_page_exp;
        struct rdac_page_common *rdac_common = NULL;
        uint8_t fail_paths_pg[308];

        int res;
        char b[80];

        memset(fail_paths_pg, 0, 308);
        if (use_6_byte) {
                memcpy(fail_paths_pg, mode6_hdr, 4);
                memcpy(fail_paths_pg + 4, block_descriptor, 8);
                rdac_page = (struct rdac_legacy_page *)(fail_paths_pg + 4 + 8);
                rdac_page->page_code = RDAC_CONTROLLER_PAGE;
                rdac_page->page_length = RDAC_CONTROLLER_PAGE_LEN;
                rdac_common = &rdac_page->attr;
        } else {
                memcpy(fail_paths_pg, mode10_hdr, 8);
                rdac_page_exp = (struct rdac_expanded_page *)
                                (fail_paths_pg + 8);
                rdac_page_exp->page_code = RDAC_CONTROLLER_PAGE | 0x40;
                rdac_page_exp->subpage_code = 0x1;
                sg_put_unaligned_be16(EXPANDED_LUN_SPACE_PAGE_LEN,
                                      rdac_page_exp->page_length + 0);
                rdac_common = &rdac_page_exp->attr;
        }

        rdac_common->current_mode_lsb =  RDAC_FAIL_ALL_PATHS;
        rdac_common->quiescence = RDAC_QUIESCENCE_TIME;
        rdac_common->options = RDAC_FORCE_QUIESCENCE;

        if (use_6_byte) {
                res = sg_ll_mode_select6(fd, 1 /* pf */, 0 /* sp */,
                                        fail_paths_pg, 118,
                                        true, (do_verbose ? 2 : 0));
        } else {
                res = sg_ll_mode_select10(fd, 1 /* pf */, 0 /* sp */,
                                        fail_paths_pg, 308,
                                        true, (do_verbose ? 2: 0));
        }

        switch (res) {
        case 0:
                if (do_verbose)
                        pr2serr("fail paths successful\n");
                break;
        default:
                sg_get_category_sense_str(res, sizeof(b), b, do_verbose);
                pr2serr("fail paths failed: %s\n", b);
                break;
        }

        return res;
}

static int fail_this_path(int fd, int lun, bool use_6_byte)
{
        int res;
        struct rdac_legacy_page *rdac_page;
        struct rdac_expanded_page *rdac_page_exp;
        struct rdac_page_common *rdac_common = NULL;
        uint8_t fail_paths_pg[308];
        char b[80];

        if (use_6_byte) {
                if (lun > 31) {
                        pr2serr("must use 10 byte cdb to fail luns over 31\n");
                        return -1;
                }
        } else {        /* 10 byte cdb case */
                if (lun > 255) {
                        pr2serr("lun cannot exceed 255\n");
                        return -1;
                }
        }

        memset(fail_paths_pg, 0, 308);
        if (use_6_byte) {
                memcpy(fail_paths_pg, mode6_hdr, 4);
                memcpy(fail_paths_pg + 4, block_descriptor, 8);
                rdac_page = (struct rdac_legacy_page *)(fail_paths_pg + 4 + 8);
                rdac_page->page_code = RDAC_CONTROLLER_PAGE;
                rdac_page->page_length = RDAC_CONTROLLER_PAGE_LEN;
                rdac_common = &rdac_page->attr;
                memset(rdac_page->lun_table, 0x0, 32);
                rdac_page->lun_table[lun] = 0x81;
        } else {
                memcpy(fail_paths_pg, mode10_hdr, 8);
                rdac_page_exp = (struct rdac_expanded_page *)
                                (fail_paths_pg + 8);
                rdac_page_exp->page_code = RDAC_CONTROLLER_PAGE | 0x40;
                rdac_page_exp->subpage_code = 0x1;
                sg_put_unaligned_be16(EXPANDED_LUN_SPACE_PAGE_LEN,
                                      rdac_page_exp->page_length + 0);
                rdac_common = &rdac_page_exp->attr;
                memset(rdac_page_exp->lun_table, 0x0, 256);
                rdac_page_exp->lun_table[lun] = 0x81;
        }

        rdac_common->current_mode_lsb =  RDAC_FAIL_SELECTED_PATHS;
        rdac_common->quiescence = RDAC_QUIESCENCE_TIME;
        rdac_common->options = RDAC_FORCE_QUIESCENCE;

        if (use_6_byte) {
                res = sg_ll_mode_select6(fd, 1 /* pf */, 0 /* sp */,
                                        fail_paths_pg, 118,
                                        true, (do_verbose ? 2 : 0));
        } else {
                res = sg_ll_mode_select10(fd, 1 /* pf */, 0 /* sp */,
                                        fail_paths_pg, 308,
                                        true, (do_verbose ? 2: 0));
        }

        switch (res) {
        case 0:
                if (do_verbose)
                        pr2serr("fail paths successful\n");
                break;
        default:
                sg_get_category_sense_str(res, sizeof(b), b, do_verbose);
                pr2serr("fail paths page (lun=%d) failed: %s\n", lun, b);
                break;
        }

        return res;
}

static void print_rdac_mode(uint8_t *ptr, bool exp_subpg)
{
        int i, k, bd_len, lun_table_len;
        uint8_t * lun_table = NULL;
        struct rdac_legacy_page *legacy;
        struct rdac_expanded_page *expanded;
        struct rdac_page_common *rdac_ptr = NULL;

        if (exp_subpg) {
                bd_len = ptr[7];
                expanded = (struct rdac_expanded_page *)(ptr + 8 + bd_len);
                rdac_ptr = &expanded->attr;
                lun_table = expanded->lun_table;
                lun_table_len = 256;
        } else {
                bd_len = ptr[3];
                legacy = (struct rdac_legacy_page *)(ptr + 4 + bd_len);
                rdac_ptr = &legacy->attr;
                lun_table = legacy->lun_table;
                lun_table_len = 32;
        }

        printf("RDAC %s page\n", exp_subpg ? "Expanded" : "Legacy");
        printf("  Controller serial: %s\n",
               rdac_ptr->current_serial);
        printf("  Alternate controller serial: %s\n",
               rdac_ptr->alternate_serial);
        printf("  RDAC mode (redundant processor): ");
        switch (rdac_ptr->current_mode_msb) {
        case 0x00:
                printf("alternate controller not present; ");
                break;
        case 0x01:
                printf("alternate controller present; ");
                break;
        default:
                printf("(Unknown controller status 0x%x); ",
                       rdac_ptr->current_mode_msb);
                break;
        }
        switch (rdac_ptr->current_mode_lsb) {
        case 0x0:
                printf("inactive\n");
                break;
        case 0x1:
                printf("active\n");
                break;
        case 0x2:
                printf("Dual active mode\n");
                break;
        default:
                printf("(Unknown mode 0x%x)\n",
                       rdac_ptr->current_mode_lsb);
        }

        printf("  RDAC mode (alternate processor): ");
        switch (rdac_ptr->alternate_mode_msb) {
        case 0x00:
                printf("alternate controller not present; ");
                break;
        case 0x01:
                printf("alternate controller present; ");
                break;
        default:
                printf("(Unknown status 0x%x); ",
                       rdac_ptr->alternate_mode_msb);
                break;
        }
        switch (rdac_ptr->alternate_mode_lsb) {
        case 0x0:
                printf("inactive\n");
                break;
        case 0x1:
                printf("active\n");
                break;
        case 0x2:
                printf("Dual active mode\n");
                break;
        case 0x3:
                printf("Not present\n");
                break;
        case 0x4:
                printf("held in reset\n");
                break;
        default:
                printf("(Unknown mode 0x%x)\n",
                       rdac_ptr->alternate_mode_lsb);
        }
        printf("  Quiescence timeout: %d\n", rdac_ptr->quiescence);
        printf("  RDAC option 0x%x\n", rdac_ptr->options);
        printf("    ALUA: %s\n", (rdac_ptr->options & 0x4 ? "Enabled" :
                                                            "Disabled" ));
        printf("    Force Quiescence: %s\n", (rdac_ptr->options & 0x2 ?
                                              "Enabled" : "Disabled" ));
        printf ("  LUN Table: (p = preferred, a = alternate, u = utm lun)\n");
        printf("         0 1 2 3 4 5 6 7  8 9 a b c d e f\n");
        for (k = 0; k < lun_table_len; k += 16) {
                printf("    0x%x:",k / 16);
                for (i = 0; i < 16; i++) {
                        switch (lun_table[k + i]) {
                        case 0x0:
                                printf(" x");
                                break;
                        case 0x1:
                                printf(" p");
                                break;
                        case 0x2:
                                printf(" a");
                                break;
                        case 0x3:
                                printf(" u");
                                break;
                        default:
                                printf(" ?");
                                break;
                        }
                        if (i == 7) {
                                printf(" ");
                        }
                }
                printf("\n");
        }
}

static void usage()
{
    printf("Usage:  sg_rdac [-6] [-a] [-f=LUN] [-v] [-V] DEVICE\n"
           "  where:\n"
           "    -6        use 6 byte cdbs for mode sense/select\n"
           "    -a        transfer all devices to the controller\n"
           "              serving DEVICE.\n"
           "    -f=LUN    transfer the device at LUN to the\n"
           "              controller serving DEVICE\n"
           "    -v        verbose\n"
           "    -V        print version then exit\n\n"
           " Display/Modify RDAC Redundant Controller Page 0x2c.\n"
           " If [-a] or [-f] is not specified the current settings"
           " are displayed.\n");
}

int main(int argc, char * argv[])
{
        bool fail_all = false;
        bool fail_path = false;
        bool use_6_byte = false;
        int res, fd, k, resid, len, lun = -1;
        int ret = 0;
        char **argptr;
        char * file_name = 0;
        uint8_t rsp_buff[MX_ALLOC_LEN];

        if (argc < 2) {
                usage ();
                return SG_LIB_SYNTAX_ERROR;
        }

        for (k = 1; k < argc; ++k) {
                argptr = argv + k;
                if (!strcmp (*argptr, "-v"))
                        ++do_verbose;
                else if (!strncmp(*argptr, "-f=",3)) {
                        fail_path = true;
                        lun = strtoul(*argptr + 3, NULL, 0);
                }
                else if (!strcmp(*argptr, "-a")) {
                        fail_all = true;
                }
                else if (!strcmp(*argptr, "-6")) {
                        use_6_byte = true;
                }
                else if (!strcmp(*argptr, "-V")) {
                        pr2serr("sg_rdac version: %s\n", version_str);
                        return 0;
                }
                else if (*argv[k] == '-') {
                        pr2serr("Unrecognized switch: %s\n", argv[k]);
                        file_name = 0;
                        break;
                }
                else if (0 == file_name)
                        file_name = argv[k];
                else {
                        pr2serr("too many arguments\n");
                        file_name = 0;
                        break;
                }
        }
        if (0 == file_name) {
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }

        fd = sg_cmds_open_device(file_name, false /* rw */, do_verbose);
        if (fd < 0) {
                pr2serr("open error: %s: %s\n", file_name, safe_strerror(-fd));
                usage();
                ret = sg_convert_errno(-fd);
                goto fini;
        }

        if (fail_all) {
                res = fail_all_paths(fd, use_6_byte);
        } else if (fail_path) {
                res = fail_this_path(fd, lun, use_6_byte);
        } else {
                resid = 0;
                if (use_6_byte)
                        res = sg_ll_mode_sense6(fd, /* DBD */ false,
                                                /* PC */ 0,
                                                0x2c /* page */,
                                                0 /*subpage */,
                                                rsp_buff, 252,
                                                true, do_verbose);
                else
                        res = sg_ll_mode_sense10_v2(fd, /* llbaa */ false,
                                                    /* DBD */ false,
                                                    /* page control */0,
                                                    0x2c, 0x1 /* subpage */,
                                                    rsp_buff, 308, 0, &resid,
                                                    true, do_verbose);

                if (! res) {
                        len = sg_msense_calc_length(rsp_buff, 308, use_6_byte,
                                                    NULL);
                        if (resid > 0) {
                                len = ((308 - resid) < len) ? (308 - resid) :
                                                              len;
                                if (len < 2)
                                        pr2serr("MS(10) residual value (%d) "
                                                "a worry\n", resid);
                        }
                        if (do_verbose && (len > 1))
                                dump_mode_page(rsp_buff, len);
                        print_rdac_mode(rsp_buff, ! use_6_byte);
                } else {
                        if (SG_LIB_CAT_INVALID_OP == res)
                                pr2serr(">>>>>> try again without the '-6' "
                                        "switch for a 10 byte MODE SENSE "
                                        "command\n");
                        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                                pr2serr("mode sense: invalid field in cdb "
                                        "(perhaps subpages or page control "
                                        "(PC) not supported)\n");
                        else {
                                char b[80];

                                sg_get_category_sense_str(res, sizeof(b), b,
                                                          do_verbose);
                                pr2serr("mode sense failed: %s\n", b);
                        }
                }
        }
        ret = res;

        res = sg_cmds_close_device(fd);
        if (res < 0) {
                pr2serr("close error: %s\n", safe_strerror(-res));
                if (0 == ret)
                        ret = sg_convert_errno(res);
        }
fini:
        if (0 == do_verbose) {
                if (! sg_if_can2stderr("sg_rdac failed: ", ret))
                        pr2serr("Some error occurred, try again with '-v' "
                                "or '-vv' for more information\n");
        }
        return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

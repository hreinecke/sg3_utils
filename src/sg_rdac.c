/*
 * sg_rdac
 *
 * Retrieve / set RDAC options.
 *
 * Copyright (C) 2006-2007 Hannes Reinecke <hare@suse.de>
 *
 * Based on sg_modes.c and sg_emc_trespass.c; credits from there apply.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2, or (at your option)
 *  any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "sg_lib.h"
#include "sg_cmds_basic.h"


static char * version_str = "1.06 20070714";

unsigned char mode6_hdr[] = {
    75, /* Length */
    0, /* medium */
    0, /* params */
    8, /* Block descriptor length */
};

unsigned char block_descriptor[] = {
    0, /* Density code */
    0, 0, 0, /* Number of blocks */
    0, /* Reserved */
    0, 0x02, 0, /* 512 byte blocks */
};

struct rdac_legacy_page {
    unsigned char  page_code;
    unsigned char  page_length;
    char           current_serial[16];
    char           alternate_serial[16];
    unsigned char  current_mode_msb;
    unsigned char  current_mode_lsb;
    unsigned char  alternate_mode_msb;
    unsigned char  alternate_mode_lsb;
    unsigned char  quiescence;
    unsigned char  options;
    unsigned char  lun_table[32];
    unsigned char  lun_table_exp[32];
    unsigned short reserved;
};

static int do_verbose = 0;

static void dump_mode_page( unsigned char *page, int len )
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
#define RDAC_FAIL_ALL_PATHS 0x1
#define RDAC_FAIL_SELECTED_PATHS 0x2
#define RDAC_FORCE_QUIESCENCE 0x2
#define RDAC_QUIESCENCE_TIME 10

static int fail_all_paths(int fd)
{
        unsigned char fail_paths_pg[118];
        struct rdac_legacy_page *rdac_page;
        int res;

        memset(fail_paths_pg, 0, 118);
        memcpy(fail_paths_pg, mode6_hdr, 4);
        memcpy(fail_paths_pg + 4, block_descriptor, 8);
        rdac_page = (struct rdac_legacy_page *)(fail_paths_pg + 4 + 8);
        rdac_page->page_code = RDAC_CONTROLLER_PAGE | 0x40;
        rdac_page->page_length = RDAC_CONTROLLER_PAGE_LEN;
        rdac_page->quiescence = RDAC_QUIESCENCE_TIME;
        rdac_page->options = RDAC_FORCE_QUIESCENCE;
        rdac_page->current_mode_lsb = RDAC_FAIL_ALL_PATHS;

        res = sg_ll_mode_select6(fd, 1 /* pf */, 0 /* sp */,
                                 fail_paths_pg, 118,
                                 1, (do_verbose ? 2 : 0));

        switch (res) {
        case 0:
                if (do_verbose)
                        fprintf(stderr, "fail paths successful\n");
                break;
        case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, "fail paths page failed (Invalid opcode)\n");
                break;
        case SG_LIB_CAT_ILLEGAL_REQ:
                fprintf(stderr, "fail paths page failed (illegal request)\n");
                break;
        case SG_LIB_CAT_NOT_READY:
                fprintf(stderr, "fail paths page failed (not ready)\n");
                break;
        case SG_LIB_CAT_UNIT_ATTENTION:
                fprintf(stderr, "fail paths page failed (unit attention)\n");
                break;
        case SG_LIB_CAT_ABORTED_COMMAND:
                fprintf(stderr, "fail paths page failed (aborted command)\n");
                break;
        default:
                if (do_verbose)
                        fprintf(stderr, "fail paths failed\n");
                break;
        }

        return res;
}

static int fail_this_path(int fd, int lun)
{
        unsigned char fail_paths_pg[118];
        struct rdac_legacy_page *rdac_page;
        int res;

        memset(fail_paths_pg, 0, 118);
        memcpy(fail_paths_pg, mode6_hdr, 4);
        memcpy(fail_paths_pg + 4, block_descriptor, 8);
        rdac_page = (struct rdac_legacy_page *)(fail_paths_pg + 4 + 8);
        rdac_page->page_code = RDAC_CONTROLLER_PAGE | 0x40;
        rdac_page->page_length = RDAC_CONTROLLER_PAGE_LEN;
        rdac_page->current_mode_lsb =  RDAC_FAIL_SELECTED_PATHS;
        rdac_page->quiescence = RDAC_QUIESCENCE_TIME;
        rdac_page->options = RDAC_FORCE_QUIESCENCE;
        memset(rdac_page->lun_table, 0x0, 32);
        rdac_page->lun_table[lun] = 0x81;

        res = sg_ll_mode_select6(fd, 1 /* pf */, 0 /* sp */,
                                 fail_paths_pg, 118,
                                 1, (do_verbose ? 2 : 0));

        switch (res) {
        case 0:
                if (do_verbose)
                        fprintf(stderr, "fail paths successful\n");
                break;
        case SG_LIB_CAT_INVALID_OP:
                fprintf(stderr, "fail paths page failed (Invalid opcode)\n");
                break;
        case SG_LIB_CAT_NOT_READY:
                fprintf(stderr, "fail paths page failed (not ready)\n");
                break;
        case SG_LIB_CAT_UNIT_ATTENTION:
                fprintf(stderr, "fail paths page failed (unit attention)\n");
                break;
        case SG_LIB_CAT_ABORTED_COMMAND:
                fprintf(stderr, "fail paths page failed (aborted command)\n");
                break;
        case SG_LIB_CAT_ILLEGAL_REQ:
                fprintf(stderr, "fail lun %d page failed (illegal request)\n",
                        lun);
                break;
        default:
                if (do_verbose)
                        fprintf(stderr, "fail paths failed\n");
                break;
        }

        return res;
}

static void print_rdac_mode( unsigned char *ptr )
{
        struct rdac_legacy_page *rdac_ptr;
        int i, k, bd_len;

        bd_len = ptr[3];

        rdac_ptr = (struct rdac_legacy_page *)(ptr + 4 + bd_len);

        printf("RDAC Legacy page\n");
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
        case 0x02:
                printf("active/active mode; ");
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
        case 0x04:
                printf("held in reset\n");
                break;
        default:
                printf("(Unknown mode 0x%x)\n",
                       rdac_ptr->alternate_mode_lsb);
        }
        printf("  Quiescence timeout: %d\n", rdac_ptr->quiescence);
        printf("  RDAC option 0x%x\n", rdac_ptr->options);
        printf ("  LUN Table:\n");
        for (k = 0; k < 32; k += 8) {
                printf("    %x:",k / 8);
                for (i = 0; i < 8; i++) {
                        switch (rdac_ptr->lun_table[k + i]) {
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
                }
                printf("\n");
        }
}

static void usage()
{
    printf("Usage:  sg_rdac [-a] [-f=LUN] [-v] [-V] DEVICE\n"
           "  where:\n"
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
        unsigned char rsp_buff[MX_ALLOC_LEN];
        char **argptr;
        char * file_name = 0;
        int res, fd, k, lun = -1;
        int fail_all = 0;
        int fail_path = 0;
        int ret = 0;

        if (argc < 2) {
                usage ();
                return SG_LIB_SYNTAX_ERROR;
        }

        for (k = 1; k < argc; ++k) {
                argptr = argv + k;
                if (!strcmp (*argptr, "-v"))
                        ++do_verbose;
                else if (!strncmp(*argptr, "-f=",3)) {
                        ++fail_path;
                        lun = strtoul(*argptr + 3, NULL, 0);
                }
                else if (!strcmp(*argptr, "-a")) {
                        ++fail_all;
                }
                else if (!strcmp(*argptr, "-V")) {
                        fprintf(stderr, "sg_rdac version: %s\n", version_str);
                        return 0;
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
                return SG_LIB_SYNTAX_ERROR;
        }

        fd = sg_cmds_open_device(file_name, 0 /* rw */, do_verbose);
        if (fd < 0) {
                fprintf(stderr, "open error: %s: %s\n", file_name,
                        safe_strerror(-fd));
                usage();
                return SG_LIB_FILE_ERROR;
        }

        if (fail_all) {
                res = fail_all_paths(fd);
        } else if (fail_path) {
                res = fail_this_path(fd, lun);
        } else {
                res = sg_ll_mode_sense6(fd, /*DBD*/ 0, /* page control */0,
                                        0x2c, 0, rsp_buff, 252,
                                        1, do_verbose);

                if (!res) {
                        if (do_verbose)
                                dump_mode_page(rsp_buff, rsp_buff[0]);
                        print_rdac_mode(rsp_buff);
                }
        }
        ret = res;
        if (SG_LIB_CAT_INVALID_OP == res)
                fprintf(stderr, ">>>>>> try again without the '-6' "
                        "switch for a 10 byte MODE SENSE command\n");
        else if (SG_LIB_CAT_ILLEGAL_REQ == res)
                fprintf(stderr, "invalid field in cdb (perhaps subpages "
                        "or page control (PC) not supported)\n");
        else if (SG_LIB_CAT_NOT_READY == res)
                fprintf(stderr, "mode sense failed, device not ready\n");
        else if (res)
                fprintf(stderr," mode sense failed\n");

        res = sg_cmds_close_device(fd);
        if (res < 0) {
                fprintf(stderr, "close error: %s\n", safe_strerror(-res));
                if (0 == ret)
                        return SG_LIB_FILE_ERROR;
        }
        return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

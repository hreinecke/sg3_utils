/*
 * Copyright (c) 2004-2018 Hannes Reinecke and Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_cmds_basic.h"
#include "sg_cmds_extra.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 *  This program accesses a processor device which operates according
 *  to the 'SCSI Accessed Fault-Tolerant Enclosures' (SAF-TE) spec.
 */

static const char * version_str = "0.33 20180628";


#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */
#define EBUFF_SZ 256

#define RB_MODE_DESC 3
#define RWB_MODE_DATA 2
#define RWB_MODE_VENDOR 1
#define RB_DESC_LEN 4

#define SAFTE_CFG_FLAG_DOORLOCK 1
#define SAFTE_CFG_FLAG_ALARM 2
#define SAFTE_CFG_FLAG_CELSIUS 3

struct safte_cfg_t {
    int fans;
    int psupplies;
    int slots;
    int temps;
    int thermostats;
    int vendor_specific;
    int flags;
};

struct safte_cfg_t safte_cfg;

static unsigned int buf_capacity = 64;

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}

/* Buffer ID 0x0: Read Enclosure Configuration (mandatory) */
static int
read_safte_configuration(int sg_fd, uint8_t *rb_buff,
                         unsigned int rb_len, int verbose)
{
    int res;

    if (rb_len < buf_capacity) {
        pr2serr("SCSI BUFFER size too small (%d/%d bytes)\n", rb_len,
                buf_capacity);
        return SG_LIB_CAT_ILLEGAL_REQ;
    }

    if (verbose > 1)
        pr2serr("Use READ BUFFER,mode=vendor_specific,buff_id=0 to fetch "
                "configuration\n");
    res = sg_ll_read_buffer(sg_fd, RWB_MODE_VENDOR, 0, 0,
                            rb_buff, rb_len, true, verbose);
    if (res && res != SG_LIB_CAT_RECOVERED)
        return res;

    safte_cfg.fans = rb_buff[0];
    safte_cfg.psupplies = rb_buff[1];
    safte_cfg.slots = rb_buff[2];
    safte_cfg.temps = rb_buff[4];
    if (rb_buff[3])
        safte_cfg.flags |= SAFTE_CFG_FLAG_DOORLOCK;
    if (rb_buff[5])
        safte_cfg.flags |= SAFTE_CFG_FLAG_ALARM;
    if (rb_buff[6] & 0x80)
        safte_cfg.flags |= SAFTE_CFG_FLAG_CELSIUS;

    safte_cfg.thermostats = rb_buff[6] & 0x0f;
    safte_cfg.vendor_specific = rb_buff[63];

    return 0;
}

static int
print_safte_configuration(void)
{
    printf("Enclosure Configuration:\n");
    printf("\tNumber of Fans: %d\n", safte_cfg.fans);
    printf("\tNumber of Power Supplies: %d\n", safte_cfg.psupplies);
    printf("\tNumber of Device Slots: %d\n", safte_cfg.slots);
    printf("\tNumber of Temperature Sensors: %d\n", safte_cfg.temps);
    printf("\tNumber of Thermostats: %d\n", safte_cfg.thermostats);
    printf("\tVendor unique bytes: %d\n", safte_cfg.vendor_specific);

    return 0;
}

/* Buffer ID 0x01: Read Enclosure Status (mandatory) */
static int
do_safte_encl_status(int sg_fd, int do_hex, int do_raw, int verbose)
{
    int res, i, offset;
    unsigned int rb_len;
    uint8_t *rb_buff;

    rb_len = safte_cfg.fans + safte_cfg.psupplies + safte_cfg.slots +
        safte_cfg.temps + 5 + safte_cfg.vendor_specific;
    rb_buff = (uint8_t *)malloc(rb_len);


    if (verbose > 1)
        pr2serr("Use READ BUFFER,mode=vendor_specific,buff_id=1 to read "
                "enclosure status\n");
    res = sg_ll_read_buffer(sg_fd, RWB_MODE_VENDOR, 1, 0,
                            rb_buff, rb_len, false, verbose);
    if (res && res != SG_LIB_CAT_RECOVERED)
        return res;

    if (do_raw > 1) {
        dStrRaw(rb_buff, buf_capacity);
        return 0;
    }
    if (do_hex > 1) {
        hex2stdout(rb_buff, buf_capacity, 1);
        return 0;
    }
    printf("Enclosure Status:\n");
    offset = 0;
    for (i = 0; i < safte_cfg.fans; i++) {
        printf("\tFan %d status: ", i);
        switch(rb_buff[i]) {
            case 0:
                printf("operational\n");
                break;
            case 1:
                printf("malfunctioning\n");
                break;
            case 2:
                printf("not installed\n");
                break;
            case 80:
                printf("not reportable\n");
                break;
            default:
                printf("unknown\n");
                break;
        }
    }

    offset += safte_cfg.fans;
    for (i = 0; i < safte_cfg.psupplies; i++) {
        printf("\tPower supply %d status: ", i);
        switch(rb_buff[i + offset]) {
            case 0:
                printf("operational / on\n");
                break;
            case 1:
                printf("operational / off\n");
                break;
            case 0x10:
                printf("malfunctioning / on\n");
                break;
            case 0x11:
                printf("malfunctioning / off\n");
                break;
            case 0x20:
                printf("not present\n");
                break;
            case 0x21:
                printf("present\n");
                break;
            case 0x80:
                printf("not reportable\n");
                break;
            default:
                printf("unknown\n");
                break;
        }
    }

    offset += safte_cfg.psupplies;
    for (i = 0; i < safte_cfg.slots; i++) {
        printf("\tDevice Slot %d: SCSI ID %d\n", i, rb_buff[i + offset]);
    }

    offset += safte_cfg.slots;
    if (safte_cfg.flags & SAFTE_CFG_FLAG_DOORLOCK) {
        switch(rb_buff[offset]) {
            case 0x0:
                printf("\tDoor lock status: locked\n");
                break;
            case 0x01:
                printf("\tDoor lock status: unlocked\n");
                break;
            case 0x80:
                printf("\tDoor lock status: not reportable\n");
                break;
        }
    } else {
        printf("\tDoor lock status: not installed\n");
    }

    offset++;
    if (!(safte_cfg.flags & SAFTE_CFG_FLAG_ALARM)) {
        printf("\tSpeaker status: not installed\n");
    } else {
        switch(rb_buff[offset]) {
            case 0x0:
                printf("\tSpeaker status: off\n");
                break;
            case 0x01:
                printf("\tSpeaker status: on\n");
                break;
        }
    }

    offset++;
    for (i = 0; i < safte_cfg.temps; i++) {
        int temp = rb_buff[i + offset];
        int is_celsius = !!(safte_cfg.flags & SAFTE_CFG_FLAG_CELSIUS);

        if (! is_celsius)
            temp -= 10;

        printf("\tTemperature sensor %d: %d deg %c\n", i, temp,
               is_celsius ? 'C' : 'F');
    }

    offset += safte_cfg.temps;
    if (safte_cfg.thermostats) {
        if (rb_buff[offset] & 0x80) {
            printf("\tEnclosure Temperature alert status: abnormal\n");
        } else {
            printf("\tEnclosure Temperature alert status: normal\n");
        }
    }
    return 0;
}

/* Buffer ID 0x02: Read Usage Statistics (optional) */
static int
do_safte_usage_statistics(int sg_fd, int do_hex, int do_raw, int verbose)
{
    int res;
    unsigned int rb_len;
    uint8_t *rb_buff;
    unsigned int minutes;

    rb_len = 16 + safte_cfg.vendor_specific;
    rb_buff = (uint8_t *)malloc(rb_len);

    if (verbose > 1)
        pr2serr("Use READ BUFFER,mode=vendor_specific,buff_id=2 to read "
                "usage statistics\n");
    res = sg_ll_read_buffer(sg_fd, RWB_MODE_VENDOR, 2, 0,
                            rb_buff, rb_len, false, verbose);
    if (res) {
        if (res == SG_LIB_CAT_ILLEGAL_REQ) {
            printf("Usage Statistics:\n\tNot implemented\n");
            return 0;
        }
        if (res != SG_LIB_CAT_RECOVERED) {
            free(rb_buff);
            return res;
        }
    }

    if (do_raw > 1) {
        dStrRaw(rb_buff, buf_capacity);
        return 0;
    }
    if (do_hex > 1) {
        hex2stdout(rb_buff, buf_capacity, 1);
        return 0;
    }
    printf("Usage Statistics:\n");
    minutes = sg_get_unaligned_be32(rb_buff + 0);
    printf("\tPower on Minutes: %u\n", minutes);
    minutes = sg_get_unaligned_be32(rb_buff + 4);
    printf("\tPower on Cycles: %u\n", minutes);

    free(rb_buff);
    return 0;
}

/* Buffer ID 0x03: Read Device Insertions (optional) */
static int
do_safte_slot_insertions(int sg_fd, int do_hex, int do_raw, int verbose)
{
    int res, i;
    unsigned int rb_len;
    uint8_t *rb_buff, slot_status;

    rb_len = safte_cfg.slots * 2;
    rb_buff = (uint8_t *)malloc(rb_len);

    if (verbose > 1)
        pr2serr("Use READ BUFFER,mode=vendor_specific,buff_id=3 to read "
                "device insertions\n");
    res = sg_ll_read_buffer(sg_fd, RWB_MODE_VENDOR, 3, 0,
                            rb_buff, rb_len, false, verbose);
    if (res ) {
        if (res == SG_LIB_CAT_ILLEGAL_REQ) {
                printf("Slot insertions:\n\tNot implemented\n");
                return 0;
        }
        if (res != SG_LIB_CAT_RECOVERED) {
                free(rb_buff);
                return res;
        }
    }

    if (do_raw > 1) {
        dStrRaw(rb_buff, buf_capacity);
        return 0;
    }
    if (do_hex > 1) {
        hex2stdout(rb_buff, buf_capacity, 1);
        return 0;
    }
    printf("Slot insertions:\n");
    for (i = 0; i < safte_cfg.slots; i++) {
        slot_status = sg_get_unaligned_be16(rb_buff + (i * 2));
        printf("\tSlot %d: %d insertions", i, slot_status);
    }
    free(rb_buff);
    return 0;
}

/* Buffer ID 0x04: Read Device Slot Status (mandatory) */
static int
do_safte_slot_status(int sg_fd, int do_hex, int do_raw, int verbose)
{
    int res, i;
    unsigned int rb_len;
    uint8_t *rb_buff, slot_status;

    rb_len = safte_cfg.slots * 4;
    rb_buff = (uint8_t *)malloc(rb_len);

    if (verbose > 1)
        pr2serr("Use READ BUFFER,mode=vendor_specific,buff_id=4 to read "
                "device slot status\n");
    res = sg_ll_read_buffer(sg_fd, RWB_MODE_VENDOR, 4, 0,
                            rb_buff, rb_len, false, verbose);
    if (res && res != SG_LIB_CAT_RECOVERED) {
        free(rb_buff);
        return res;
    }

    if (do_raw > 1) {
        dStrRaw(rb_buff, buf_capacity);
        return 0;
    }
    if (do_hex > 1) {
        hex2stdout(rb_buff, buf_capacity, 1);
        return 0;
    }
    printf("Slot status:\n");
    for (i = 0; i < safte_cfg.slots; i++) {
        slot_status = rb_buff[i * 4 + 3];
        printf("\tSlot %d: ", i);
        if (slot_status & 0x7) {
            if (slot_status & 0x1)
                printf("inserted ");
            if (slot_status & 0x2)
                printf("ready ");
            if (slot_status & 0x4)
                printf("activated ");
            printf("\n");
        } else {
            printf("empty\n");
        }
    }
    free(rb_buff);
    return 0;
}

/* Buffer ID 0x05: Read Global Flags (optional) */
static int
do_safte_global_flags(int sg_fd, int do_hex, int do_raw, int verbose)
{
    int res;
    unsigned int rb_len;
    uint8_t *rb_buff;

    rb_len = 16;
    rb_buff = (uint8_t *)malloc(rb_len);

    if (verbose > 1)
        pr2serr("Use READ BUFFER,mode=vendor_specific,buff_id=5 to read "
                "global flags\n");
    res = sg_ll_read_buffer(sg_fd, RWB_MODE_VENDOR, 5, 0,
                            rb_buff, rb_len, false, verbose);
    if (res ) {
        if (res == SG_LIB_CAT_ILLEGAL_REQ) {
                printf("Global Flags:\n\tNot implemented\n");
                return 0;
        }
        if (res != SG_LIB_CAT_RECOVERED) {
                free(rb_buff);
                return res;
        }
    }

    if (do_raw > 1) {
        dStrRaw(rb_buff, buf_capacity);
        return 0;
    }
    if (do_hex > 1) {
        hex2stdout(rb_buff, buf_capacity, 1);
        return 0;
    }
    printf("Global Flags:\n");
    printf("\tAudible Alarm Control: %s\n",
           rb_buff[0] & 0x1?"on":"off");
    printf("\tGlobal Failure Indicator: %s\n",
           rb_buff[0] & 0x2?"on":"off");
    printf("\tGlobal Warning Indicator: %s\n",
           rb_buff[0] & 0x4?"on":"off");
    printf("\tEnclosure Power: %s\n",
           rb_buff[0] & 0x8?"on":"off");
    printf("\tCooling Failure: %s\n",
           rb_buff[0] & 0x10?"yes":"no");
    printf("\tPower Failure: %s\n",
           rb_buff[0] & 0x20?"yes":"no");
    printf("\tDrive Failure: %s\n",
           rb_buff[0] & 0x40?"yes":"no");
    printf("\tDrive Warning: %s\n",
           rb_buff[0] & 0x80?"yes":"no");
    printf("\tArray Failure: %s\n",
           rb_buff[1] & 0x1?"yes":"no");
    printf("\tArray Warning: %s\n",
           rb_buff[0] & 0x2?"yes":"no");
    printf("\tEnclosure Lock: %s\n",
           rb_buff[0] & 0x4?"on":"off");
    printf("\tEnclosure Identify: %s\n",
           rb_buff[0] & 0x8?"on":"off");

    free(rb_buff);
    return 0;
}

static void
usage()
{
    pr2serr("Usage:  sg_safte [--config] [--devstatus] [--encstatus] "
            "[--flags] [--help]\n"
            "                 [--hex] [--insertions] [--raw] [--usage] "
            "[--verbose]\n"
            "                 [--version] DEVICE\n"
            "  where:\n"
            "    --config|-c         output enclosure configuration\n"
            "    --devstatus|-d      output device slot status\n"
            "    --encstatus|-s      output enclosure status\n"
            "    --flags|-f          output global flags\n"
            "    --help|-h           output command usage message then "
            "exit\n"
            "    --hex|-H            output enclosure config in hex\n"
            "    --insertions|-i     output insertion statistics\n"
            "    --raw|-r            output enclosure config in binary "
            "to stdout\n"
            "    --usage|-u          output usage statistics\n"
            "    --verbose|-v        increase verbosity\n"
            "    --version|-v        output version then exit\n\n"
            "Queries a SAF-TE processor device\n");
}

static struct option long_options[] = {
    {"config", 0, 0, 'c'},
    {"devstatus", 0, 0, 'd'},
    {"encstatus", 0, 0, 's'},
    {"flags", 0, 0, 'f'},
    {"help", 0, 0, 'h'},
    {"hex", 0, 0, 'H'},
    {"insertions", 0, 0, 'i'},
    {"raw", 0, 0, 'r'},
    {"usage", 0, 0, 'u'},
    {"verbose", 0, 0, 'v'},
    {"version", 0, 0, 'V'},
    {0, 0, 0, 0},
};

int
main(int argc, char * argv[])
{
    bool do_insertions = false;
    bool no_hex_raw;
    bool verbose_given = false;
    bool version_given = false;
    int c, ret, peri_type;
    int sg_fd = -1;
    int res = SG_LIB_CAT_OTHER;
    const char * device_name = NULL;
    char ebuff[EBUFF_SZ];
    uint8_t *rb_buff;
    bool do_config = false;
    bool do_status = false;
    bool do_slots = false;
    bool do_flags = false;
    bool do_usage = false;
    int do_hex = 0;
    int do_raw = 0;
    int verbose = 0;
    const char * cp;
    char buff[48];
    char b[80];
    struct sg_simple_inquiry_resp inq_resp;
    const char op_name[] = "READ BUFFER";

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "cdfhHirsuvV?", long_options,
                        &option_index);

        if (c == -1)
            break;

        switch (c) {
            case 'c':
                do_config = true;
                break;
            case 'd':
                do_slots = true;
                break;
            case 'f':
                do_flags = true;
                break;
            case 'h':
            case '?':
                usage();
                return 0;
            case 'H':
                ++do_hex;
                break;
            case 'i':
                do_insertions = true;
                break;
            case 'r':
                ++do_raw;
                break;
            case 's':
                do_status = true;
                break;
            case 'u':
                do_usage = true;
                break;
            case 'v':
                verbose_given = true;
                ++verbose;
                break;
            case 'V':
                version_given = true;
                break;
            default:
                pr2serr("unrecognised option code 0x%x ??\n", c);
                usage();
                return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == device_name) {
            device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n", argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

#ifdef DEBUG
    pr2serr("In DEBUG mode, ");
    if (verbose_given && version_given) {
        pr2serr("but override: '-vV' given, zero verbose and continue\n");
        verbose_given = false;
        version_given = false;
        verbose = 0;
    } else if (! verbose_given) {
        pr2serr("set '-vv'\n");
        verbose = 2;
    } else
        pr2serr("keep verbose=%d\n", verbose);
#else
    if (verbose_given && version_given)
        pr2serr("Not in DEBUG mode, so '-vV' has no special action\n");
#endif
    if (version_given) {
        pr2serr("Version string: %s\n", version_str);
        return 0;
    }

    if (NULL == device_name) {
        pr2serr("Missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }
    if (do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    if ((sg_fd = sg_cmds_open_device(device_name, false /* rw */, verbose))
        < 0) {
        if (verbose) {
            snprintf(ebuff, EBUFF_SZ, "sg_safte: error opening file: %s (rw)",
                     device_name);
            perror(ebuff);
        }
        ret = sg_convert_errno(-sg_fd);
        goto fini;
    }
    no_hex_raw = ((0 == do_hex) && (0 == do_raw));

    if (no_hex_raw) {
        if (0 == sg_simple_inquiry(sg_fd, &inq_resp, true, verbose)) {
            printf("  %.8s  %.16s  %.4s\n", inq_resp.vendor,
                   inq_resp.product, inq_resp.revision);
            peri_type = inq_resp.peripheral_type;
            cp = sg_get_pdt_str(peri_type, sizeof(buff), buff);
            if (strlen(cp) > 0)
                printf("  Peripheral device type: %s\n", cp);
            else
                printf("  Peripheral device type: 0x%x\n", peri_type);
        } else {
            pr2serr("sg_safte: %s doesn't respond to a SCSI INQUIRY\n",
                    device_name);
            return SG_LIB_CAT_OTHER;
        }
    }

    rb_buff = (uint8_t *)malloc(buf_capacity);
    if (!rb_buff)
        goto err_out;

    memset(rb_buff, 0, buf_capacity);

    res = read_safte_configuration(sg_fd, rb_buff, buf_capacity, verbose);
    switch (res) {
    case 0:
    case SG_LIB_CAT_RECOVERED:
        break;
    default:
        goto err_out;
    }
    if (1 == do_raw) {
        dStrRaw(rb_buff, buf_capacity);
        goto finish;
    }
    if (1 == do_hex) {
        hex2stdout(rb_buff, buf_capacity, 1);
        goto finish;
    }

    if (do_config && no_hex_raw)
        print_safte_configuration();

    if (do_status) {
        res = do_safte_encl_status(sg_fd, do_hex, do_raw, verbose);
        switch (res) {
            case 0:
            case SG_LIB_CAT_RECOVERED:
                break;
            default:
                goto err_out;
        }
    }

    if (do_usage) {
        res = do_safte_usage_statistics(sg_fd, do_hex, do_raw, verbose);
        switch (res) {
            case 0:
            case SG_LIB_CAT_RECOVERED:
                break;
            default:
                goto err_out;
        }
    }

    if (do_insertions) {
        res = do_safte_slot_insertions(sg_fd, do_hex, do_raw, verbose);
        switch (res) {
            case 0:
            case SG_LIB_CAT_RECOVERED:
                break;
            default:
                goto err_out;
        }
    }

    if (do_slots) {
        res = do_safte_slot_status(sg_fd, do_hex, do_raw, verbose);
        switch (res) {
            case 0:
            case SG_LIB_CAT_RECOVERED:
                break;
            default:
                goto err_out;
        }
    }

    if (do_flags) {
        res = do_safte_global_flags(sg_fd, do_hex, do_raw, verbose);
        switch (res) {
            case 0:
            case SG_LIB_CAT_RECOVERED:
                break;
            default:
                goto err_out;
        }
    }
finish:
    res = 0;

err_out:
    switch (res) {
    case 0:
    case SG_LIB_CAT_RECOVERED:
        break;
    default:
        sg_get_category_sense_str(res, sizeof(b), b, verbose);
        pr2serr("%s failed: %s\n", op_name, b);
        break;
    }
    ret = res;
fini:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (0 == verbose) {
        if (! sg_if_can2stderr("sg_safte failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

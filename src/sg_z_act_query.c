/*
 * Copyright (c) 2014-2022 Douglas Gilbert.
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
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_pt.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

/* A utility program originally written for the Linux OS SCSI subsystem.
 *
 *
 * This program issues either a SCSI ZONE ACTIVATE command or a ZONE QUERY
 * command to the given SCSI device. Based on zbc2r12.pdf .
 */

static const char * version_str = "1.04 20220729";

#define SG_ZBC_IN_CMDLEN 16
#define Z_ACTIVATE_SA 0x8
#define Z_QUERY_SA 0x9

#define SENSE_BUFF_LEN 64       /* Arbitrary, could be larger */
#define DEF_PT_TIMEOUT 60       /* 60 seconds */
#define DEF_ALLOC_LEN 8192
#define Z_ACT_DESC_LEN 32
#define MAX_ACT_QUERY_BUFF_LEN (16 * 1024 * 1024)

struct opts_t {
    bool do_all;
    bool do_activate;
    bool do_force;
    bool do_query;
    bool do_raw;
    bool maxlen_given;
    uint8_t other_zdid;
    uint16_t max_alloc;
    uint16_t num_zones;
    int hex_count;
    int vb;
    uint64_t st_lba;    /* Zone ID */
    const char * device_name;
    const char * inhex_fn;
};

static struct option long_options[] = {
        {"activate", no_argument, 0, 'A'},
        {"all", no_argument, 0, 'a'},
        {"force", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"hex", no_argument, 0, 'H'},
        {"in", required_argument, 0, 'i'},      /* silent, same as --inhex= */
        {"inhex", required_argument, 0, 'i'},
        {"maxlen", required_argument, 0, 'm'},
        {"num", required_argument, 0, 'n'},
        {"other", required_argument, 0, 'o'},
        {"query", no_argument, 0, 'q'},
        {"raw", no_argument, 0, 'r'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {"zone", required_argument, 0, 'z'},
        {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: "
            "sg_z_act_query [--activate] [--all] [--force] [--help] "
            "[--hex]\n"
            "                      [--inhex=FN] [--maxlen=LEN] [--num=ZS] "
            "[--other=ZDID]\n"
            "                      [--query] [--raw] [--verbose] "
            "[--version]\n"
            "                      [--zone=ID] DEVICE\n");
    pr2serr("  where:\n"
            "    --activate|-A      do ZONE ACTIVATE command (def: ZONE "
            "QUERY)\n"
            "    --all|-a           sets the ALL flag in the cdb\n"
            "    --force|-f         bypass some sanity checks\n"
            "    --help|-h          print out usage message\n"
            "    --hex|-H           print out response in hexadecimal\n"
            "    --inhex=FN|-i FN    decode contents of FN, ignore DEVICE\n"
            "    --maxlen=LEN|-m LEN    LEN place in cdb's allocation "
            "length field\n"
            "                           (def: 8192 (bytes))\n"
            "    --num=ZS|-n ZS     ZS is the number of zones and is placed "
            "in the cdb;\n"
            "                       default value is 1, ignored if --all "
            "given\n"
            "    --other=ZDID|-o ZDID    ZDID is placed in Other zone domain "
            "ID field\n"
            "    --query|-q         do ZONE QUERY command (def: ZONE "
            "QUERY)\n"
            "    --raw|-r           output response in binary, or if "
            "--inhex=FN is\n"
            "                       given, then FN's contents are binary\n"
            "    --verbose|-v       increase verbosity\n"
            "    --version|-V       print version string and exit\n"
            "    --zone=ID|-z ID    ID is the starting LBA of the zone "
            "(def: 0)\n\n"
            "Performs either a SCSI ZONE ACTIVATE command, or a ZONE QUERY "
            "command.\nArguments to options are decimal by default, for hex "
            "use a leading '0x'\nor a trailing 'h'. The default action is to "
            "send a ZONE QUERY command.\n");
}

/* Invokes a ZBC IN command (with either a ZONE ACTIVATE or a ZONE QUERY
 * service action).  Return of 0 -> success, various SG_LIB_CAT_* positive
 * values or -1 -> other errors */
static int
sg_ll_zone_act_query(int sg_fd, const struct opts_t * op, void * resp,
                     int * residp)
{
    uint8_t sa = op->do_activate ? Z_ACTIVATE_SA : Z_QUERY_SA;
    int ret, res, sense_cat;
    struct sg_pt_base * ptvp;
    uint8_t zi_cdb[SG_ZBC_IN_CMDLEN] =
          {SG_ZBC_IN, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0,  0, 0, 0, 0};
    uint8_t sense_b[SENSE_BUFF_LEN] SG_C_CPP_ZERO_INIT;
    char b[64];

    zi_cdb[1] = 0x1f & sa;
    if (op->do_all)
        zi_cdb[1] |= 0x80;

    sg_put_unaligned_be64(op->st_lba, zi_cdb + 2);
    sg_put_unaligned_be16(op->num_zones, zi_cdb + 10);
    sg_put_unaligned_be16(op->max_alloc, zi_cdb + 12);
    zi_cdb[14] = op->other_zdid;
    sg_get_opcode_sa_name(zi_cdb[0], sa, -1, sizeof(b), b);
    if (op->vb) {
        char d[128];

        pr2serr("    %s cdb: %s\n", b,
                sg_get_command_str(zi_cdb, SG_ZBC_IN_CMDLEN, false,
                                   sizeof(d), d));
    }
    ptvp = construct_scsi_pt_obj();
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", b);
        return -1;
    }
    set_scsi_pt_cdb(ptvp, zi_cdb, sizeof(zi_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (uint8_t *)resp, op->max_alloc);
    res = do_scsi_pt(ptvp, sg_fd, DEF_PT_TIMEOUT, op->vb);
    ret = sg_cmds_process_resp(ptvp, b, res, true /* noisy */,
                               op->vb, &sense_cat);
    if (-1 == ret) {
        if (get_scsi_pt_transport_err(ptvp))
            ret = SG_LIB_TRANSPORT_ERROR;
        else
            ret = sg_convert_errno(get_scsi_pt_os_err(ptvp));
    } else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else
        ret = 0;
    if (residp)
        *residp = get_scsi_pt_resid(ptvp);
    destruct_scsi_pt_obj(ptvp);
    return ret;
}

static const char *
zone_condition_str(int zc, char * b, int blen, int vb)
{
    const char * cp;

    if (NULL == b)
        return "zone_condition_str: NULL ptr)";
    switch (zc) {
    case 0:
        cp = "Not write pointer";
        break;
    case 1:
        cp = "Empty";
        break;
    case 2:
        cp = "Implicitly opened";
        break;
    case 3:
        cp = "Explicitly opened";
        break;
    case 4:
        cp = "Closed";
        break;
    case 5:
        cp = "Inactive";
        break;
    case 0xd:
        cp = "Read only";
        break;
    case 0xe:
        cp = "Full";
        break;
    case 0xf:
        cp = "Offline";
        break;
    default:
        cp = NULL;
        break;
    }
    if (cp) {
        if (vb)
            snprintf(b, blen, "%s [0x%x]", cp, zc);
        else
            snprintf(b, blen, "%s", cp);
    } else
        snprintf(b, blen, "Reserved [0x%x]", zc);
    return b;
}

/* The allocation length field in each cdb cannot be less than 64 but the
 * transport could still trim the response. */
static int
decode_z_act_query(const uint8_t * ziBuff, int act_len, uint32_t zar_len,
                   const struct opts_t * op)
{
    uint8_t zt;
    int k, zc, num_desc;
    const uint8_t * bp;
    char b[80];

    if ((uint32_t)act_len < zar_len) {
        num_desc = (act_len >= 64) ? ((act_len - 64) / Z_ACT_DESC_LEN) : 0;
        if (act_len == op->max_alloc) {
            if (op->maxlen_given)
                pr2serr("response length [%u bytes] may be constrained by "
                        "given --maxlen value, try increasing\n", zar_len);
            else
                pr2serr("perhaps --maxlen=%u needs to be used\n", zar_len);
        } else if (op->inhex_fn)
            pr2serr("perhaps %s has been truncated\n", op->inhex_fn);
    } else
        num_desc = (zar_len - 64) / Z_ACT_DESC_LEN;
    if (act_len <= 8)
        return 0;
    if (0x80 & ziBuff[8]) {
        printf("  Nz_valid=1\n");
        if (act_len > 19)
            printf("    Number of zones: %u\n",
                   sg_get_unaligned_be32(ziBuff + 16));
    } else
        printf("  Nz_valid=0\n");
    if (0x40 & ziBuff[8]) {
        printf("  Ziwup_valid=1\n");
        if (act_len > 31)
            printf("    Zone ID with unmet prerequisite: 0x%" PRIx64 "\n",
                   sg_get_unaligned_be64(ziBuff + 24));
    } else
        printf("  Ziwup_valid=0\n");
    printf("  Activated=%d\n", (0x1 & ziBuff[8]));
    if (act_len <= 9)
        return 0;
    printf("  Unmet prerequisites:\n");
    if (0 == ziBuff[9])
        printf("    none\n");
    else {
        if (0x40 & ziBuff[9])
             printf("    security\n");
        if (0x20 & ziBuff[9])
             printf("    mult domn\n");
        if (0x10 & ziBuff[9])
             printf("    rlm rstct\n");
        if (0x8 & ziBuff[9])
             printf("    mult ztyp\n");
        if (0x4 & ziBuff[9])
             printf("    rlm align\n");
        if (0x2 & ziBuff[9])
             printf("    not empty\n");
        if (0x1 & ziBuff[9])
             printf("    not inact\n");
    }
    if (act_len <= 10)
        return 0;
    printf("  Other zone domain ID: %u\n", ziBuff[10]);
    if (act_len <= 11)
        return 0;
    printf("  All: %d\n", (0x1 & ziBuff[11]));

    if (((uint32_t)act_len < zar_len) &&
        ((num_desc * Z_ACT_DESC_LEN) + 64 > act_len)) {
        pr2serr("Skip due to truncated response, try using --num= to a "
                "value less than %d\n", num_desc);
        return SG_LIB_CAT_MALFORMED;
    }
    for (k = 0, bp = ziBuff + 64; k < num_desc; ++k, bp += Z_ACT_DESC_LEN) {
        printf("  Zone activation descriptor: %d\n", k);
        if (op->hex_count) {
            hex2stdout(bp, Z_ACT_DESC_LEN, -1);
            continue;
        }
        zt = bp[0] & 0xf;
        zc = (bp[1] >> 4) & 0xf;
        printf("    Zone type: %s\n", sg_get_zone_type_str(zt, sizeof(b),
               b));
        printf("    Zone condition: %s\n", zone_condition_str(zc, b,
               sizeof(b), op->vb));
        printf("    Zone domain ID: %u\n", bp[2]);
        printf("    Zone range size: %" PRIu64 "\n",
               sg_get_unaligned_be64(bp + 8));
        printf("    Starting zone locator: 0x%" PRIx64 "\n",
               sg_get_unaligned_be64(bp + 16));
    }
    return 0;
}

static void
dStrRaw(const uint8_t * str, int len)
{
    int k;

    for (k = 0; k < len; ++k)
        printf("%c", str[k]);
}


int
main(int argc, char * argv[])
{
    bool no_final_msg = false;
    bool version_given = false;
    int res, c, n, in_len, rlen, act_len;
    int sg_fd = -1;
    int resid = 0;
    int verbose = 0;
    int ret = 0;
    uint32_t zar_len, zarr_len;
    int64_t ll;
    uint8_t * ziBuff = NULL;
    uint8_t * free_zibp = NULL;
    const char * sa_name;
    char b[80];
    struct opts_t opts SG_C_CPP_ZERO_INIT;
    struct opts_t * op = &opts;

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "aAfhHi:m:n:o:qrvVz:", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            op->do_all = true;
            break;
        case 'A':
            op->do_activate = true;
            break;
        case 'f':
            op->do_force = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            ++op->hex_count;
            break;
        case 'i':
            op->inhex_fn = optarg;
            break;
        case 'm':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 0xffff)) {
                pr2serr("--maxlen= expects an argument between 0 and 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->maxlen_given = true;
            op->max_alloc = (uint16_t)n;
            break;
        case 'n':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 0xffff)) {
                pr2serr("--num=ZS expects an argument between 0 and 0xffff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->num_zones = (uint16_t)n;
            break;
        case 'o':
            n = sg_get_num(optarg);
            if ((n < 0) || (n > 0xff)) {
                pr2serr("--other=ZDID expects an argument between 0 and 0xff "
                        "inclusive\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->other_zdid = (uint8_t)n;
            break;
        case 'q':
            op->do_query = true;
            break;
        case 'r':
            op->do_raw = true;
            break;
        case 'v':
            ++op->vb;
            break;
        case 'V':
            version_given = true;
            break;
        case 'z':
            if ((2 == strlen(optarg)) && (0 == memcmp("-1", optarg, 2))) {
                op->st_lba = UINT64_MAX;
                break;
            }
            ll = sg_get_llnum(optarg);
            if (-1 == ll) {
                pr2serr("bad argument to '--zone=ID'\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            op->st_lba = (uint64_t)ll;  /* Zone ID is starting LBA */
            break;
        default:
            pr2serr("unrecognised option code 0x%x ??\n\n", c);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }
    if (optind < argc) {
        if (NULL == op->device_name) {
            op->device_name = argv[optind];
            ++optind;
        }
        if (optind < argc) {
            for (; optind < argc; ++optind)
                pr2serr("Unexpected extra argument: %s\n",
                        argv[optind]);
            usage();
            return SG_LIB_SYNTAX_ERROR;
        }
    }

    if (version_given) {
        pr2serr("version: %s\n", version_str);
        return 0;
    }

    if ((! op->do_all) && (0 == op->num_zones))
        op->num_zones = 1;
    if (op->do_activate && op->do_query){
        pr2serr("only one of these options: --activate and --query may be "
                "given\n\n");
        usage();
        return SG_LIB_CONTRADICT;
    }
    sa_name = op->do_activate ? "Zone activate" : "Zone query";
    if (op->device_name && op->inhex_fn) {
        pr2serr("ignoring DEVICE, best to give DEVICE or --inhex=FN, but "
                "not both\n");
        op->device_name = NULL;
    }
    if (op->max_alloc < 4) {
        if (op->max_alloc > 0)
            pr2serr("Won't accept --maxlen= of 1, 2 or 3, using %d "
                    "instead\n", DEF_ALLOC_LEN);
        op->max_alloc = DEF_ALLOC_LEN;
    }
    ziBuff = (uint8_t *)sg_memalign(op->max_alloc, 0, &free_zibp, op->vb > 3);
    if (NULL == ziBuff) {
        pr2serr("unable to sg_memalign %d bytes\n", op->max_alloc);
        return sg_convert_errno(ENOMEM);
    }

    if (NULL == op->device_name) {
        if (op->inhex_fn) {
            if ((ret = sg_f2hex_arr(op->inhex_fn, op->do_raw, false, ziBuff,
                                    &in_len, op->max_alloc))) {
                if (SG_LIB_LBA_OUT_OF_RANGE == ret) {
                    no_final_msg = true;
                    pr2serr("... decode what we have, --maxlen=%d needs to "
                            "be increased\n", op->max_alloc);
                } else
                    goto the_end;
            }
            if (verbose > 2)
                pr2serr("Read %d [0x%x] bytes of user supplied data\n",
                        in_len, in_len);
            if (op->do_raw)
                op->do_raw = false;    /* can interfere on decode */
            if (in_len < 4) {
                pr2serr("--inhex=%s only decoded %d bytes (needs 4 at "
                        "least)\n", op->inhex_fn, in_len);
                ret = SG_LIB_SYNTAX_ERROR;
                goto the_end;
            }
            res = 0;
            goto start_response;
        } else {
            pr2serr("missing device name!\n\n");
            usage();
            ret = SG_LIB_FILE_ERROR;
            no_final_msg = true;
            goto the_end;
        }
    } else
        in_len = 0;

    if (op->do_raw) {
        if (sg_set_binary_mode(STDOUT_FILENO) < 0) {
            perror("sg_set_binary_mode");
            return SG_LIB_FILE_ERROR;
        }
    }

    sg_fd = sg_cmds_open_device(op->device_name, false /* rw */, verbose);
    if (sg_fd < 0) {
        int err = -sg_fd;
        if (verbose)
            pr2serr("open error: %s: %s\n", op->device_name,
                    safe_strerror(err));
        ret = sg_convert_errno(err);
        goto the_end;
    }

    res = sg_ll_zone_act_query(sg_fd, op, ziBuff, &resid);
    ret = res;
    if (res) {
        if (SG_LIB_CAT_INVALID_OP == res)
            pr2serr("%s command not supported\n", sa_name);
        else {
            sg_get_category_sense_str(res, sizeof(b), b, verbose);
            pr2serr("%s command: %s\n", sa_name, b);
        }
    }

start_response:
    if (0 == res) {
        if ((resid < 0) || (resid > op->max_alloc)) {
            pr2serr("Unexpected resid=%d\n", resid);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        rlen = op->inhex_fn ? in_len : (op->max_alloc - resid);
        if (rlen < 4) {
            pr2serr("Decoded response length (%d) too short\n", rlen);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        zar_len = sg_get_unaligned_be32(ziBuff + 0) + 64;
        zarr_len = sg_get_unaligned_be32(ziBuff + 4) + 64;
        if ((zar_len > MAX_ACT_QUERY_BUFF_LEN) ||
            (zarr_len > MAX_ACT_QUERY_BUFF_LEN) || (zarr_len > zar_len)) {
            if (! op->do_force) {
                pr2serr("zar or zarr length [%u/%u bytes] seems wild, use "
                        "--force override\n", zar_len, zarr_len);
                return SG_LIB_CAT_MALFORMED;
            }
        }
        if (zarr_len > (uint32_t)rlen) {
            pr2serr("zarr response length is %u bytes, but system "
                    "reports %d bytes received??\n", zarr_len, rlen);
            if (op->do_force)
                act_len = rlen;
            else {
                pr2serr("Exiting, use --force to override\n");
                ret = SG_LIB_CAT_MALFORMED;
                goto the_end;
            }
        } else
            act_len = zarr_len;
        if (op->do_raw) {
            dStrRaw(ziBuff, act_len);
            goto the_end;
        }
        if (op->hex_count && (2 != op->hex_count)) {
            hex2stdout(ziBuff, act_len, ((1 == op->hex_count) ? 1 : -1));
            goto the_end;
        }
        printf("%s response:\n", sa_name);
        if (act_len < 64) {
            pr2serr("Zone length [%d] too short (perhaps after truncation\n)",
                    act_len);
            ret = SG_LIB_CAT_MALFORMED;
            goto the_end;
        }
        ret = decode_z_act_query(ziBuff, act_len, zar_len, op);
    } else if (SG_LIB_CAT_INVALID_OP == res)
        pr2serr("%s command not supported\n", sa_name);
    else {
        sg_get_category_sense_str(res, sizeof(b), b, op->vb);
        pr2serr("%s command: %s\n", sa_name, b);
    }

the_end:
    if (sg_fd >= 0) {
        res = sg_cmds_close_device(sg_fd);
        if (res < 0) {
            pr2serr("close error: %s\n", safe_strerror(-res));
            if (0 == ret)
                ret = sg_convert_errno(-res);
        }
    }
    if (free_zibp)
        free(free_zibp);
    if ((0 == verbose) && (! no_final_msg)) {
        if (! sg_if_can2stderr("sg_z_act_query failed: ", ret))
            pr2serr("Some error occurred, try again with '-v' "
                    "or '-vv' for more information\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

/*
 * Copyright (c) 2018 Douglas Gilbert
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * This program issues a NVMe Identify command (controller or namespace)
 * or a Device self-test command via the "SCSI" pass-through interface of
 * this packages sg_utils library. That interface is primarily shown in
 * the ../include/sg_pt.h header file.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#define __STDC_FORMAT_MACROS 1
#include <inttypes.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_pt.h"
#include "sg_pt_nvme.h"
#include "sg_cmds_basic.h"
#include "sg_unaligned.h"
#include "sg_pr2serr.h"

static const char * version_str = "1.00 20180118";


#define ME "sg_tst_nvme: "

#define SENSE_BUFF_LEN 32       /* Arbitrary, only need 16 bytes for NVME
                                 * (and SCSI at least 18) currently */


#define INQUIRY_CMD     0x12    /* SCSI command to get VPD page 0x83 */
#define INQUIRY_CMDLEN  6

#define VPD_DEVICE_ID  0x83

#define DEF_TIMEOUT_SECS 60


static struct option long_options[] = {
    {"ctl", no_argument, 0, 'c'},
    {"dev-id", no_argument, 0, 'd'},
    {"dev_id", no_argument, 0, 'd'},
    {"help", no_argument, 0, 'h'},
    {"long", no_argument, 0, 'l'},
    {"nsid", required_argument, 0, 'n'},
    {"self-test", required_argument, 0, 's'},
    {"self_test", required_argument, 0, 's'},
    {"to-ms", required_argument, 0, 't'},
    {"to_ms", required_argument, 0, 't'},
    {"verbose", no_argument, 0, 'v'},
    {"version", no_argument, 0, 'V'},
    {0, 0, 0, 0},
};


static void
usage()
{
    pr2serr("Usage: sg_tst_nvme [--ctl] [dev-id] [--help] [--long] "
            "[--nsid=ID]\n"
            "                   [--self-test=ST] [--to-ms=TO] [--verbose] "
            "[--version]\n"
            "                   DEVICE\n"
            "  where:\n"
            "    --ctl|-c             do Identify controller command\n"
            "    --dev-id|-d          do SCSI INQUIRY for device "
            " identification\n"
            "                         VPD page (0x83) via own SNTL\n"
            "    --help|-h            print out usage message\n"
            "    --long|-l            add more detail to decoded output\n"
            "    --nsid=ID| -n ID     do Identify namespace with nsid set to "
            "ID; if ID\n"
            "                         is 0 then try to get nsid from "
            "DEVICE.\n"
            "                         Can also be used with self-test (def: "
            "0)\n"
            "    --self-test=ST|-s ST    do (or abort) device self-test, ST "
            "can be:\n"
            "                              0:  do nothing\n"
            "                              1:  do short (background) "
            "self-test\n"
            "                              2:  do long self-test\n"
            "                              15: abort self-test in "
            "progress\n"
            "                         if nsid is 0 then test controller "
            "only\n"
            "                         if nsid is 0xffffffff then test "
            "controller and\n"
            "                         all namespaces\n"
            "    --to-ms=TO|-t TO     command timeout in milliseconds (def: "
            "60,000)\n"
            "    --verbose|-v         increase verbosity\n"
            "    --version|-V         print version string then exit\n\n"
            "Performs a NVME Identify or Device self-test Admin command on "
            "DEVICE.\nCan also simulate a SCSI device identification VPD "
            "page [0x83] via\na local SNTL. --nsid= accepts '-1' for "
            "0xffffffff .\n"
         );
}

static void
show_nvme_id_ctl(const uint8_t *dinp, const char *dev_name, int do_long)
{
    bool got_fguid;
    uint8_t ver_min, ver_ter, mtds;
    uint16_t ver_maj, oacs, oncs;
    uint32_t k, ver, max_nsid, npss, j, n, m;
    uint64_t sz1, sz2;
    const uint8_t * up;

    max_nsid = sg_get_unaligned_le32(dinp + 516); /* NN */
    printf("Identify controller for %s:\n", dev_name);
    printf("  Model number: %.40s\n", (const char *)(dinp + 24));
    printf("  Serial number: %.20s\n", (const char *)(dinp + 4));
    printf("  Firmware revision: %.8s\n", (const char *)(dinp + 64));
    ver = sg_get_unaligned_le32(dinp + 80);
    ver_maj = (ver >> 16);
    ver_min = (ver >> 8) & 0xff;
    ver_ter = (ver & 0xff);
    printf("  Version: %u.%u", ver_maj, ver_min);
    if ((ver_maj > 1) || ((1 == ver_maj) && (ver_min > 2)) ||
        ((1 == ver_maj) && (2 == ver_min) && (ver_ter > 0)))
        printf(".%u\n", ver_ter);
    else
        printf("\n");
    oacs = sg_get_unaligned_le16(dinp + 256);
    if (0x1ff & oacs) {
        printf("  Optional admin command support:\n");
        if (0x100 & oacs)
            printf("    Doorbell buffer config\n");
        if (0x80 & oacs)
            printf("    Virtualization management\n");
        if (0x40 & oacs)
            printf("    NVMe-MI send and NVMe-MI receive\n");
        if (0x20 & oacs)
            printf("    Directive send and directive receive\n");
        if (0x10 & oacs)
            printf("    Device self-test\n");
        if (0x8 & oacs)
            printf("    Namespace management and attachment\n");
        if (0x4 & oacs)
            printf("    Firmware download and commit\n");
        if (0x2 & oacs)
            printf("    Format NVM\n");
        if (0x1 & oacs)
            printf("    Security send and receive\n");
    } else
        printf("  No optional admin command support\n");
    oncs = sg_get_unaligned_le16(dinp + 256);
    if (0x7f & oncs) {
        printf("  Optional NVM command support:\n");
        if (0x40 & oncs)
            printf("    Timestamp feature\n");
        if (0x20 & oncs)
            printf("    Reservations\n");
        if (0x10 & oncs)
            printf("    Save and Select fields non-zero\n");
        if (0x8 & oncs)
            printf("    Write zeroes\n");
        if (0x4 & oncs)
            printf("    Dataset management\n");
        if (0x2 & oncs)
            printf("    Write uncorrectable\n");
        if (0x1 & oncs)
            printf("    Compare\n");
    } else
        printf("  No optional NVM command support\n");
    printf("  PCI vendor ID VID/SSVID: 0x%x/0x%x\n",
           sg_get_unaligned_le16(dinp + 0),
           sg_get_unaligned_le16(dinp + 2));
    printf("  IEEE OUI Identifier: 0x%x\n",
           sg_get_unaligned_le24(dinp + 73));
    got_fguid = ! sg_all_zeros(dinp + 112, 16);
    if (got_fguid) {
        printf("  FGUID: 0x%02x", dinp[112]);
        for (k = 1; k < 16; ++k)
            printf("%02x", dinp[112 + k]);
        printf("\n");
    } else if (do_long)
        printf("  FGUID: 0x0\n");
    printf("  Controller ID: 0x%x\n", sg_get_unaligned_le16(dinp + 78));
    if (do_long) {
        printf("  Management endpoint capabilities, over a PCIe port: %d\n",
               !! (0x2 & dinp[255]));
        printf("  Management endpoint capabilities, over a SMBus/I2C port: "
               "%d\n", !! (0x1 & dinp[255]));
    }
    printf("  Number of namespaces: %u\n", max_nsid);
    sz1 = sg_get_unaligned_le64(dinp + 280);  /* lower 64 bits */
    sz2 = sg_get_unaligned_le64(dinp + 288);  /* upper 64 bits */
    if (sz2)
        printf("  Total NVM capacity: huge ...\n");
    else if (sz1)
        printf("  Total NVM capacity: %" PRIu64 " bytes\n", sz1);
    mtds = dinp[77];
    printf("  Maximum data transfer size: ");
    if (mtds)
        printf("%u pages\n", 1U << mtds);
    else
        printf("<unlimited>\n");

    if (do_long) {
        const char * const non_op = "does not process I/O";
        const char * const operat = "processes I/O";
        const char * cp;

        printf("  Total NVM capacity: 0 bytes\n");
        npss = dinp[263] + 1;
        up = dinp + 2048;
        for (k = 0; k < npss; ++k, up += 32) {
            n = sg_get_unaligned_le16(up + 0);
            n *= (0x1 & up[3]) ? 1 : 100;    /* unit: 100 microWatts */
            j = n / 10;                      /* unit: 1 milliWatts */
            m = j % 1000;
            j /= 1000;
            cp = (0x2 & up[3]) ? non_op : operat;
            printf("  Power state %u: Max power: ", k);
            if (0 == j) {
                m = n % 10;
                n /= 10;
                printf("%u.%u milliWatts, %s\n", n, m, cp);
            } else
                printf("%u.%03u Watts, %s\n", j, m, cp);
            n = sg_get_unaligned_le32(up + 4);
            if (0 == n)
                printf("    [ENLAT], ");
            else
                printf("    ENLAT=%u, ", n);
            n = sg_get_unaligned_le32(up + 8);
            if (0 == n)
                printf("[EXLAT], ");
            else
                printf("EXLAT=%u, ", n);
            n = 0x1f & up[12];
            printf("RRT=%u, ", n);
            n = 0x1f & up[13];
            printf("RRL=%u, ", n);
            n = 0x1f & up[14];
            printf("RWT=%u, ", n);
            n = 0x1f & up[15];
            printf("RWL=%u\n", n);
        }
    }
}

static const char * rperf[] = {"Best", "Better", "Good", "Degraded"};

static void
show_nvme_id_ns(const uint8_t * dinp, int do_long)
{
    bool got_eui_128 = false;
    uint32_t u, k, off, num_lbaf, flbas, flba_info, md_size, lb_size;
    uint64_t ns_sz, eui_64;

    num_lbaf = dinp[25] + 1;  /* spec says this is "0's based value" */
    flbas = dinp[26] & 0xf;   /* index of active LBA format (for this ns) */
    ns_sz = sg_get_unaligned_le64(dinp + 0);
    eui_64 = sg_get_unaligned_be64(dinp + 120);  /* N.B. big endian */
    if (! sg_all_zeros(dinp + 104, 16))
        got_eui_128 = true;
    printf("    Namespace size/capacity: %" PRIu64 "/%" PRIu64
           " blocks\n", ns_sz, sg_get_unaligned_le64(dinp + 8));
    printf("    Namespace utilization: %" PRIu64 " blocks\n",
           sg_get_unaligned_le64(dinp + 16));
    if (got_eui_128) {          /* N.B. big endian */
        printf("    NGUID: 0x%02x", dinp[104]);
        for (k = 1; k < 16; ++k)
            printf("%02x", dinp[104 + k]);
        printf("\n");
    } else if (do_long)
        printf("    NGUID: 0x0\n");
    if (eui_64)
        printf("    EUI-64: 0x%" PRIx64 "\n", eui_64); /* N.B. big endian */
    printf("    Number of LBA formats: %u\n", num_lbaf);
    printf("    Index LBA size: %u\n", flbas);
    for (k = 0, off = 128; k < num_lbaf; ++k, off += 4) {
        printf("    LBA format %u support:", k);
        if (k == flbas)
            printf(" <-- active\n");
        else
            printf("\n");
        flba_info = sg_get_unaligned_le32(dinp + off);
        md_size = flba_info & 0xffff;
        lb_size = flba_info >> 16 & 0xff;
        if (lb_size > 31) {
            pr2serr("%s: logical block size exponent of %u implies a LB "
                    "size larger than 4 billion bytes, ignore\n", __func__,
                    lb_size);
            continue;
        }
        lb_size = 1U << lb_size;
        ns_sz *= lb_size;
        ns_sz /= 500*1000*1000;
        if (ns_sz & 0x1)
            ns_sz = (ns_sz / 2) + 1;
        else
            ns_sz = ns_sz / 2;
        u = (flba_info >> 24) & 0x3;
        printf("      Logical block size: %u bytes\n", lb_size);
        printf("      Approximate namespace size: %" PRIu64 " GB\n", ns_sz);
        printf("      Metadata size: %u bytes\n", md_size);
        printf("      Relative performance: %s [0x%x]\n", rperf[u], u);
    }
}

/* Invokes a NVMe Admin command via sg_utils library pass-through that will
 * potentially fetch data from the device (din). Returns 0 -> success,
 * various SG_LIB_* positive values or negated errno values.
 * SG_LIB_NVME_STATUS is returned if the NVMe status is non-zero. */
static int
nvme_din_admin_cmd(int sg_fd, const uint8_t *cmdp, uint32_t cmd_len,
                   const char *cmd_str, bool internal_nsid, uint8_t *dip,
                   int di_len, int timeout_ms, uint16_t *sct_scp,
                   int verbose)
{
    int res, k;
    uint16_t sct_sc;
    uint32_t result, clen;
    struct sg_pt_base * ptvp;
    unsigned char sense_b[SENSE_BUFF_LEN];
    uint8_t ucmd[128];
    char b[32];

    snprintf(b, sizeof(b), "%s", cmd_str);
    clen = (cmd_len > sizeof(ucmd)) ? sizeof(ucmd) : cmd_len;
    memcpy(ucmd, cmdp, clen);
    ptvp = construct_scsi_pt_obj_with_fd(sg_fd, verbose);
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", b);
        return -ENOMEM;
    }
    if (internal_nsid)
        sg_put_unaligned_le32(get_pt_nvme_nsid(ptvp), ucmd + SG_NVME_PT_NSID);
    if (verbose > 1) {
       pr2serr("    %s cdb:\n", b);
       hex2stderr(ucmd, clen, -1);
    }
    set_scsi_pt_cdb(ptvp, ucmd, clen);
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    if (dip && (di_len > 0))
        set_scsi_pt_data_in(ptvp, dip, di_len);
    res = do_scsi_pt(ptvp, -1, -timeout_ms, verbose);
    if (res < 0)
        goto err_out;   /* OS error (Unix: negated errno) */

    if ((verbose > 2) && dip && di_len) {
        k = get_scsi_pt_resid(ptvp);
        pr2serr("    Data in buffer [%d bytes]:\n", di_len - k);
        if (di_len > k)
            hex2stderr(dip, di_len - k, -1);
        if (verbose > 3)
            pr2serr("    do_scsi_pt(nvme): res=%d resid=%d\n", res, k);
    }
    sct_sc = get_scsi_pt_status_response(ptvp);
    result = get_pt_result(ptvp);
    k = get_scsi_pt_sense_len(ptvp);
    if (verbose) {
        pr2serr("Status: 0x%x [SCT<<8 + SC], Result: 0x%x, Completion Q:\n",
                sct_sc, result);
        if (k > 0)
            hex2stderr(sense_b, k, -1);
    }
    if (sct_scp)
        *sct_scp = sct_sc;
err_out:
    destruct_scsi_pt_obj(ptvp);
    return res;
}

/* Invokes a SCSI INQUIRY command and yields the response. Returns 0 when
 * successful, various SG_LIB_CAT_* positive values or -1 -> other errors.
 * The CMDDT field is obsolete in the INQUIRY cdb (since spc3r16 in 2003) so
 * an argument to set it has been removed (use the REPORT SUPPORTED OPERATION
 * CODES command instead). Adds the ability to set the command abort timeout
 * and the ability to report the residual count. If timeout_secs is zero
 * the default command abort timeout (60 seconds) is used.
 * If residp is non-NULL then the residual value is written where residp
 * points. A residual value of 0 implies mx_resp_len bytes have be written
 * where resp points. If the residual value equals mx_resp_len then no
 * bytes have been written. */
static int
sg_scsi_inquiry(int sg_fd, bool evpd, int pg_op, void * resp,
                int mx_resp_len, int timeout_secs, int * residp,
                bool noisy, int verbose)
{
    int res, ret, k, sense_cat, resid;
    unsigned char inq_cdb[INQUIRY_CMDLEN] = {INQUIRY_CMD, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    unsigned char * up;
    struct sg_pt_base * ptvp;

    if (evpd)
        inq_cdb[1] |= 1;
    inq_cdb[2] = (unsigned char)pg_op;
    sg_put_unaligned_be16((uint16_t)mx_resp_len, inq_cdb + 3);
    if (verbose > 1) {
        pr2serr("    INQUIRY cdb: ");
        for (k = 0; k < INQUIRY_CMDLEN; ++k)
            pr2serr("%02x ", inq_cdb[k]);
        pr2serr("\n");
    }
    if (resp && (mx_resp_len > 0)) {
        up = (unsigned char *)resp;
        up[0] = 0x7f;   /* defensive prefill */
        if (mx_resp_len > 4)
            up[4] = 0;
    }
    if (timeout_secs == 0)
        timeout_secs = DEF_TIMEOUT_SECS;
    ptvp = construct_scsi_pt_obj_with_fd(sg_fd, verbose);
    if (NULL == ptvp) {
        pr2serr("%s: out of memory\n", __func__);
        if (residp)
            *residp = 0;
        return -1;
    }
    set_scsi_pt_cdb(ptvp, inq_cdb, sizeof(inq_cdb));
    set_scsi_pt_sense(ptvp, sense_b, sizeof(sense_b));
    set_scsi_pt_data_in(ptvp, (unsigned char *)resp, mx_resp_len);
    res = do_scsi_pt(ptvp, -1, timeout_secs, verbose);
    ret = sg_cmds_process_resp(ptvp, "inquiry", res, mx_resp_len, sense_b,
                               noisy, verbose, &sense_cat);
    resid = get_scsi_pt_resid(ptvp);
    if (residp)
        *residp = resid;
    destruct_scsi_pt_obj(ptvp);
    if (-1 == ret)
        ;
    else if (-2 == ret) {
        switch (sense_cat) {
        case SG_LIB_CAT_RECOVERED:
        case SG_LIB_CAT_NO_SENSE:
            ret = 0;
            break;
        default:
            ret = sense_cat;
            break;
        }
    } else if (ret < 4) {
        if (verbose)
            pr2serr("%s: got too few bytes (%d)\n", __func__, ret);
        ret = SG_LIB_CAT_MALFORMED;
    } else
        ret = 0;

    if (resid > 0) {
        if (resid > mx_resp_len) {
            pr2serr("INQUIRY resid (%d) should never exceed requested "
                    "len=%d\n", resid, mx_resp_len);
            return ret ? ret : SG_LIB_CAT_MALFORMED;
        }
        /* zero unfilled section of response buffer */
        memset((unsigned char *)resp + (mx_resp_len - resid), 0, resid);
    }
    return ret;
}

int
main(int argc, char * argv[])
{
    bool do_dev_id_vpd = false;
    bool do_id_ctl = false;
    bool do_id_ns = false;
    bool do_self_test = false;
    bool flagged = false;
    int sg_fd, res, c, n, resid, off, len, ln;
    int do_long = 0;
    int self_test = 0;
    int ret = 1;
    int timeout_ms = DEF_TIMEOUT_SECS * 1000;
    int vb = 0;
    uint32_t nsid = 0;
    uint32_t pg_sz = sg_get_page_size();
    int64_t ll;
    uint8_t * al_buff = NULL;
    uint8_t * free_al_buff = NULL;
    uint8_t * bp;
    const char * device_name = NULL;
    const char * cp;
    char cmd_name[32];
    char b[2048];

    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "cdhln:s:t:vV", long_options,
                       &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'c':
            strcpy(cmd_name, "Identify(ctl)");
            do_id_ctl = true;
            break;
        case 'd':
            strcpy(cmd_name, "INQUIRY(vpd=0x83)");
            do_dev_id_vpd = true;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'l':
            ++do_long;
            break;
        case 'n':
            if ((2 == strlen(optarg)) && (0 == memcmp("-1", optarg, 2))) {
                nsid = 0xffffffff;      /* treat '-1' as (2**32 - 1) */
                break;
            }
            ll = sg_get_llnum(optarg);
            if ((ll < 0) || (ll > UINT32_MAX)) {
                pr2serr("bad argument to '--nsid', accept 0 to 0xffffffff\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            strcpy(cmd_name, "Identify(ns)");
            nsid = (uint32_t)ll;
            do_id_ns = true;
            break;
        case 's':
            self_test = sg_get_num(optarg);
            if (self_test < 0) {
                pr2serr("bad argument to '--self-test=', expect 0 or "
                        "higher\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            strcpy(cmd_name, "Device self-test");
            do_self_test = true;
            break;
        case 't':
            timeout_ms = sg_get_num(optarg);
            if (timeout_ms < 0) {
                pr2serr("bad argument to '--to-ms=', expect 0 or higher\n");
                return SG_LIB_SYNTAX_ERROR;
            }
            break;
        case 'v':
            ++vb;
            break;
        case 'V':
            pr2serr(ME "version: %s\n", version_str);
            return 0;
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

    if (NULL == device_name) {
        pr2serr("missing device name!\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    }

    if (do_self_test && do_id_ns)
        do_id_ns = false;       /* self-test with DW10 set to nsid */
    n = (int)do_id_ctl + (int)do_id_ns + (int)do_dev_id_vpd +
        (int)do_self_test;
    if (n > 1) {
        pr2serr("can only have one of --ctl, --dev-id, --nsid= and "
                "--self-test=\n\n");
        usage();
        return SG_LIB_SYNTAX_ERROR;
    } else if (0 == n)
        do_id_ctl = true;


    al_buff = sg_memalign(pg_sz, pg_sz, &free_al_buff, vb > 3);
    if (NULL == al_buff) {
        pr2serr("out of memory allocating page sized buffer\n");
        return -ENOMEM;
    }
    sg_fd = sg_cmds_open_device(device_name, false /* rw */, vb);
    if (sg_fd < 0) {
        pr2serr(ME "open error: %s: %s\n", device_name, safe_strerror(-sg_fd));
        ret = SG_LIB_FILE_ERROR;
        flagged = true;
        goto err_out;
    }
    n = check_pt_file_handle(sg_fd, device_name, vb);
    if (n < 0) {
        pr2serr("check_pt_file_handle error: %s: %s\n", device_name,
                safe_strerror(-n));
        flagged = true;
        goto err_out;
    }
    cp = NULL;
    switch (n) {
    case 0:
        cp = "Unidentified device (SATA disk ?)";
        break;
    case 1:
        cp = "SCSI char device (e.g. in Linux: sg or bsg device)";
        break;
    case 2:
        cp = "SCSI block device (e.g. in FreeBSD: /dev/da0)";
        break;
    case 3:
        cp = "NVMe char device (e.g. in Linux: /dev/nvme0)";
        break;
    case 4:
        cp = "NVMe block device (e.g. in FreeBSD: /dev/nvme0ns1)";
        break;
    default:
        pr2serr("Strange value from check_pt_file_handle() --> %d\n", n);
        break;
    }
    if (cp && (vb || (do_long > 0)))
        pr2serr("%s\n", cp);

    /* Ignore the above check and do what has been asked on command line */
    resid = 0;
    if (do_dev_id_vpd) {
        ret = sg_scsi_inquiry(sg_fd, true /* evpd */, VPD_DEVICE_ID, al_buff,
                              pg_sz, timeout_ms / 1000, &resid, true, vb);
        if (ret) {
            pr2serr("SCSI INQUIRY to SNTL for device id vpage failed, "
                    "try again with -vv option added\n");
            goto err_out;
        }
        len = pg_sz - resid;
        if (len < 4) {
            pr2serr("Something wrong with data-in, len=%d (resid=%d)\n",
                    len, resid);
            goto err_out;
        }
        for (off = -1, bp = al_buff + 4, ln = len - 4;
             0 == sg_vpd_dev_id_iter(bp, ln, &off, -1, -1, -1); ) {
            n = sg_get_designation_descriptor_str("    ", bp + off,
                    bp[off + 3] + 4, do_long > 0, do_long > 1, sizeof(b), b);
            if (n > 0)
                printf("%s", b);
        }

    } else { /* NVME Identify or Device self-test */
        uint16_t sct_sc;
        struct sg_nvme_passthru_cmd n_cmd;

        memset(&n_cmd, 0, sizeof(n_cmd));
        if (do_self_test) {
            n_cmd.opcode = 0x14;   /* Device self-test */
            n_cmd.nsid = nsid;
            n_cmd.cdw10 = self_test;
            if (0 == nsid)
                printf("Starting Device self-test for controller only\n");
            else if (0xffffffff == nsid)
                printf("Starting Device self-test for controller and all "
                       "namespaces\n");
            else
                printf("Starting Device self-test for controller and "
                       "namespace %u\n", nsid);
        } else {
            n_cmd.opcode = 0x6;   /* Identify */
            if (do_id_ctl)
                n_cmd.cdw10 = 0x1;      /* Controller */
            else {
                n_cmd.cdw10 = 0x0;      /* Namespace */
                n_cmd.nsid = nsid;
            }
        }
        ret = nvme_din_admin_cmd(sg_fd, (const uint8_t *)&n_cmd,
                                 sizeof(n_cmd), cmd_name, (0 == nsid),
                                 al_buff, pg_sz, timeout_ms, &sct_sc, vb);
        if (ret < 0)
            goto err_out;
        if (sct_sc > 0) {
            sg_get_nvme_cmd_status_str(sct_sc, sizeof(b), b);
            pr2serr("%s: %s\n", cmd_name, b);
            flagged = true;
            goto err_out;
        }
        if (do_id_ctl)
            show_nvme_id_ctl(al_buff, device_name, do_long);
        else if (do_id_ns)
            show_nvme_id_ns(al_buff, do_long);
    }
    ret = 0;

err_out:
    if (free_al_buff)
        free(free_al_buff);
    res = sg_cmds_close_device(sg_fd);
    if (res < 0) {
        pr2serr("close error: %s\n", safe_strerror(-res));
        if (0 == ret)
            return SG_LIB_FILE_ERROR;
    }
    if (ret && (0 == vb) && (! flagged)) {
        if (SG_LIB_CAT_INVALID_OP == ret)
            pr2serr("%s command not supported\n", cmd_name);
        else if (SG_LIB_NVME_STATUS == ret)
            pr2serr("%s completed with a NVME non-zero status\n", cmd_name);
        else if (ret > 0)
            pr2serr("%s, exit status %d\n", cmd_name, ret);
        else if (ret < 0)
            pr2serr("Some error occurred\n");
    }
    return (ret >= 0) ? ret : SG_LIB_CAT_OTHER;
}

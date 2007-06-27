/*
 * Copyright (c) 2004-2005 Douglas Gilbert.
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
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sg_include.h"
#include "sg_lib.h"
#include "sg_cmds.h"

/* A utility program for the Linux OS SCSI subsystem.
 *
 * This program outputs information provided by a SCSI "Get Configuration"
   command [0x46] which is only defined for CD/DVDs (in MMC-2,3,4,5).

*/

static char * version_str = "0.15 20050309";


#define SENSE_BUFF_LEN 32       /* Arbitrary, could be larger */
#define DEF_TIMEOUT 60000       /* 60,000 millisecs == 60 seconds */

#define GET_CONFIG_CMD 0x46
#define GET_CONFIG_CMD_LEN 10
#define MX_ALLOC_LEN 8192

#define NAME_BUFF_SZ 64

#define EBUFF_SZ 256

#define ME "sg_get_config: "


static unsigned char resp_buffer[MX_ALLOC_LEN];
static char ebuff[EBUFF_SZ];

static struct option long_options[] = {
        {"brief", 0, 0, '1'},
        {"help", 0, 0, 'h'},
        {"hex", 0, 0, 'H'},
        {"inner-hex", 0, 0, 'i'},
        {"list", 0, 0, 'l'},
        {"rt", 1, 0, 'r'},
        {"starting", 1, 0, 's'},
        {"verbose", 0, 0, 'v'},
        {"version", 0, 0, 'V'},
        {0, 0, 0, 0},
};

/* Returns 0 when successful, SG_LIB_CAT_INVALID_OP if command not
   supported, SG_LIB_CAT_ILLEGAL_REQ if field in cdb not supported,
   else -1 */
static int sg_ll_get_config(int sg_fd, int rt, int starting, void * resp,
                            int mx_resp_len, int noisy, int verbose)
{
    int res, k;
    unsigned char gcCmdBlk[GET_CONFIG_CMD_LEN] = {GET_CONFIG_CMD, 0, 0, 0, 
                                                  0, 0, 0, 0, 0, 0};
    unsigned char sense_b[SENSE_BUFF_LEN];
    struct sg_io_hdr io_hdr;

    if ((rt < 0) || (rt > 3)) {
        fprintf(stderr, "Bad rt value: %d\n", rt);
        return -1;
    }
    gcCmdBlk[1] = (rt & 0x3);
    if ((starting < 0) || (starting > 0xffff)) {
        fprintf(stderr, "Bad starting field number: 0x%x\n", starting);
        return -1;
    }
    gcCmdBlk[2] = (unsigned char)((starting >> 8) & 0xff);
    gcCmdBlk[3] = (unsigned char)(starting & 0xff);
    if ((mx_resp_len < 0) || (mx_resp_len > 0xffff)) {
        fprintf(stderr, "Bad mx_resp_len: 0x%x\n", starting);
        return -1;
    }
    gcCmdBlk[7] = (unsigned char)((mx_resp_len >> 8) & 0xff);
    gcCmdBlk[8] = (unsigned char)(mx_resp_len & 0xff);

    if (verbose) {
        fprintf(stderr, "    Get Configuration cdb: ");
        for (k = 0; k < GET_CONFIG_CMD_LEN; ++k)
            fprintf(stderr, "%02x ", gcCmdBlk[k]);
        fprintf(stderr, "\n");
    }
    memset(&io_hdr, 0, sizeof(struct sg_io_hdr));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(gcCmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_b);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = mx_resp_len;
    io_hdr.dxferp = resp;
    io_hdr.cmdp = gcCmdBlk;
    io_hdr.sbp = sense_b;
    io_hdr.timeout = DEF_TIMEOUT;

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("SG_IO (get config) error");
        return -1;
    }
    res = sg_err_category3(&io_hdr);
    switch (res) {
    case SG_LIB_CAT_RECOVERED:
        sg_chk_n_print3("Get config, continuing", &io_hdr);
        /* fall through */
    case SG_LIB_CAT_CLEAN:
        if (verbose && io_hdr.resid)
            fprintf(stderr, "      get config: resid=%d\n", io_hdr.resid);
        return 0;
    case SG_LIB_CAT_INVALID_OP:
    case SG_LIB_CAT_ILLEGAL_REQ:
        if (verbose > 1)
            sg_chk_n_print3("get config error", &io_hdr);
        return res;
    default:
        if (verbose | noisy) {
            snprintf(ebuff, EBUFF_SZ, "get config error, rt=%d, "
                     "starting=0x%x ", rt, starting);
            sg_chk_n_print3(ebuff, &io_hdr);
        }
        return -1;
    }
}

static void usage()
{
    fprintf(stderr,
            "Usage: 'sg_get_config [--brief] [--help] [--hex] [--inner-hex] "
            "[--list]\n"
            "                      [--rt=<num>] [--starting=<num>] "
            "[--verbose]\n"
            "                      [--version] <device>'\n"
            " where --brief | -b     only give feature names of <device> "
            "(don't decode)\n"
            "       --help | -h      output usage message\n"
            "       --hex | -H       output response in hex\n"
            "       --inner-hex | -i  decode to feature name, then output "
            "features in hex\n"
            "       --list | -l      list all known features + profiles "
            "(ignore <device>)\n"
            "       --rt=<num> | -r <num>\n"
            "                 0 -> all feature descriptors (regardless "
            "of currency)\n"
            "                 1 -> all current feature descriptors\n"
            "                 2 -> only feature descriptor matching "
            "'starting'\n"
            "       --starting=<num> | -s <num>  starting from feature "
            "<num>\n"
            "       --verbose | -v   verbose\n"
            "       --version | -V   output version string\n");
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
    /* 0xa */ "graphics [0xa]",
    "graphics [0xb]",
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

static const char * get_ptype_str(int scsi_ptype)
{
    int num = sizeof(scsi_ptype_strs) / sizeof(scsi_ptype_strs[0]);

    return (scsi_ptype < num) ? scsi_ptype_strs[scsi_ptype] : "";
}

struct code_desc {
        int code;
        const char * desc;
};

static struct code_desc profile_desc_arr[] = {
        {0x0, "No current profile"},
        {0x1, "Non-removable disk"},
        {0x2, "Removable disk"},
        {0x3, "Magneto optical erasable"},
        {0x4, "Optical write once"},
        {0x5, "AS-MO"},
        {0x8, "CD-ROM"},
        {0x9, "CD-R"},
        {0xa, "CD-RW"},
        {0x10, "DVD-ROM"},
        {0x11, "DVD-R sequential recording"},
        {0x12, "DVD-RAM"},
        {0x13, "DVD-RW restricted overwrite"},
        {0x14, "DVD-RW restricted recording"},
        {0x15, "DVD-R dual layer sequental recording"},
        {0x16, "DVD-R dual layer layer jump recording"},
        {0x1a, "DVD+RW"},
        {0x1b, "DVD+R"},
        {0x20, "DDCD-ROM"},
        {0x21, "DDCD-R"},
        {0x22, "DDCD-RW"},
        {0x2b, "DVD+R double layer"},
        {0x40, "BD-ROM"},
        {0x41, "BD-R sequential recording"},
        {0x42, "BD-R random recording (RRM)"},
        {0x43, "BD-RE"},
        {0xffff, "Non-conforming profile"},
};

static const char * get_profile_str(int profile_num, char * buff)
{
    int k, num;

    num = sizeof(profile_desc_arr) / sizeof(profile_desc_arr[0]);
    for (k = 0; k < num; ++k) {
        if (profile_desc_arr[k].code == profile_num) {
            strcpy(buff, profile_desc_arr[k].desc);
            return buff;
        }
    }
    snprintf(buff, 64, "0x%x", profile_num);
    return buff;
}

static struct code_desc feature_desc_arr[] = {
        {0x0, "Profile list"},
        {0x1, "Core"},
        {0x2, "Morphing"},
        {0x3, "Removable media"},
        {0x4, "Write Protect"},
        {0x10, "Random readable"},
        {0x1d, "Multi-read"},
        {0x1e, "CD read"},
        {0x1f, "DVD read"},
        {0x20, "Random writable"},
        {0x21, "Incremental streaming writable"},
        {0x22, "Sector erasable"},
        {0x23, "Formattable"},
        {0x24, "Hardware defect management"},
        {0x25, "Write once"},
        {0x26, "Restricted overwrite"},
        {0x27, "CD-RW CAV write"},
        {0x28, "MRW"},
        {0x29, "Enhanced defect reporting"},
        {0x2a, "DVD+RW"},
        {0x2b, "DVD+R"},
        {0x2c, "Rigid restricted overwrite"},
        {0x2d, "CD track-at-once"},
        {0x2e, "CD mastering (session at once)"},
        {0x2f, "DVD-R/-RW write"},
        {0x30, "Double density CD read"},
        {0x31, "Double density CD-R write"},
        {0x32, "Double density CD-RW write"},
        {0x33, "Layer jump recording"},
        {0x37, "CD-RW media write support"},
        {0x38, "BD-R Pseudo-overwrite (POW)"},
        {0x3b, "DVD+R double layer"},
        {0x40, "BD read"},
        {0x41, "BD write"},
        {0x100, "Power management"},
        {0x101, "SMART"},
        {0x102, "Embedded changer"},
        {0x103, "CD audio external play"},
        {0x104, "Microcode upgrade"},
        {0x105, "Timeout"},
        {0x106, "DVD CSS"},
        {0x107, "Real time streaming"},
        {0x108, "Logical unit serial number"},
        {0x109, "Media serial number"},
        {0x10a, "Disc control blocks"},
        {0x10b, "DVD CPRM"},
        {0x10c, "Firmware information"},
        {0x110, "VCPS"},
};

static const char * get_feature_str(int feature_num, char * buff)
{
    int k, num;

    num = sizeof(feature_desc_arr) / sizeof(feature_desc_arr[0]);
    for (k = 0; k < num; ++k) {
        if (feature_desc_arr[k].code == feature_num) {
            strcpy(buff, feature_desc_arr[k].desc);
            return buff;
        }
    }
    snprintf(buff, 64, "0x%x", feature_num);
    return buff;
}

static void decode_feature(int feature, unsigned char * ucp, int len)
{
    int k, num, n, profile;
    char buff[128];
    const char * cp;

    cp = "";
    switch (feature) {
    case 0:     /* Profile list */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 2), !!(ucp[2] & 1),
               feature);
        printf("    available profiles [ordered from most advanced to "
               "least]:\n");
        for (k = 4; k < len; k += 4) {
            profile = (ucp[k] << 8) + ucp[k + 1];
            printf("      profile: %s , currentP=%d\n",
                   get_profile_str(profile, buff), !!(ucp[k + 2] & 1));
        }
        break;
    case 1:     /* Core */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 2), !!(ucp[2] & 1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
        switch (num) {
        case 0: cp = "unspecified"; break;
        case 1: cp = "SCSI family"; break;
        case 2: cp = "ATAPI"; break;
        case 3: cp = "IEEE 1394 - 1995"; break;
        case 4: cp = "IEEE 1394A"; break;
        case 5: cp = "Fibre channel"; break;
        case 6: cp = "IEEE 1394B"; break;
        case 7: cp = "serial ATAPI"; break;
        case 8: cp = "USB (both 1 and 2)"; break;
        case 0xffff: cp = "vendor unique"; break;
        default:
            snprintf(buff, sizeof(buff), "[0x%x]", num);
            cp = buff;
            break;
        }
        printf("      Physical interface standard: %s", cp);
        if (len > 8)
            printf(", DBE=%d\n", !!(ucp[8] & 1));
        else
            printf("\n");
        break;
    case 2:     /* Morphing */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 2), !!(ucp[2] & 1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      OCEvent=%d, ASYNC=%d\n", !!(ucp[4] & 2),
               !!(ucp[4] & 1));
        break;
    case 3:     /* Removable medium */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 2), !!(ucp[2] & 1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = (ucp[4] >> 5) & 0x7;
        switch (num) {
        case 0: cp = "Caddy/slot type"; break;
        case 1: cp = "Tray type"; break;
        case 2: cp = "Pop-up type"; break;
        case 4: cp = "Embedded changer with individually changeable discs";
            break;
        case 5: cp = "Embedded changer using a magazine"; break;
        default:
            snprintf(buff, sizeof(buff), "[0x%x]", num);
            cp = buff;
            break;
        }
        printf("      Loading mechanism: %s\n", cp);
        printf("      Eject=%d, Prevent jumper=%d, Lock=%d\n",
               !!(ucp[4] & 0x8), !!(ucp[4] & 0x4), !!(ucp[4] & 0x1));
        break;
    case 4:     /* Write protect */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      WDCB=%d, SPWP=%d, SSWPP=%d\n", !!(ucp[4] & 0x4),
               !!(ucp[4] & 0x2), !!(ucp[4] & 0x1));
        break;
    case 0x10:     /* Random readable */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 12) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
        printf("      Logical block size=0x%x, blocking=0x%x, PP=%d\n",
               num, ((ucp[8] << 8) + ucp[9]), !!(ucp[10] & 0x1));
        break;
    case 0x1d:     /* Multi-read */
    case 0x1f:     /* DVD read */
    case 0x22:     /* Sector erasable */
    case 0x26:     /* Restricted overwrite */
    case 0x27:     /* CDRW CAV write */
    case 0x38:     /* BD-R pseudo-overwrite (POW) */
    case 0x100:    /* Power management */
    case 0x104:    /* Firmware upgrade */
    case 0x109:    /* Media serial number */
    case 0x110:    /* VCPS */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        break;
    case 0x1e:     /* CD read */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      DAP=%d, C2 flags=%d, CD-Text=%d\n", !!(ucp[4] & 0x80),
               !!(ucp[4] & 0x2), !!(ucp[4] & 0x1));
        break;
    case 0x20:     /* Random writable */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 16) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
        n = (ucp[8] << 24) + (ucp[9] << 16) + (ucp[10] << 8) + ucp[11];
        printf("      Last lba=0x%x, Logical block size=0x%x, blocking=0x%x,"
               " PP=%d\n", num, n, ((ucp[12] << 8) + ucp[13]),
               !!(ucp[14] & 0x1));
        break;
    case 0x21:     /* Incremental streaming writable */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Data block types supported=0x%x, BUF=%d\n",
               ((ucp[4] << 8) + ucp[5]), !!(ucp[6] & 0x1));
        num = ucp[7];
        printf("      Number of link sizes=%d\n", num);
        for (k = 0; k < num; ++k)
            printf("        %d\n", ucp[8 + k]);
        break;
    case 0x23:     /* Formattable */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len > 4)
            printf("      BD-RE: RENoSA=%d, Expand=%d, QCert=%d, Cert=%d\n",
                   !!(ucp[4] & 0x8), !!(ucp[4] & 0x4), !!(ucp[4] & 0x2),
                   !!(ucp[4] & 0x1));
        if (len > 8)
            printf("      BD-R: RRM=%d\n", !!(ucp[8] & 0x1));
        break;
    case 0x24:     /* Hardware defect management */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len > 4)
            printf("      SSA=%d\n", !!(ucp[4] & 0x80));
        break;
    case 0x25:     /* Write once */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 12) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        num = (ucp[4] << 24) + (ucp[5] << 16) + (ucp[6] << 8) + ucp[7];
        printf("      Logical block size=0x%x, blocking=0x%x, PP=%d\n",
               num, ((ucp[8] << 8) + ucp[9]), !!(ucp[10] & 0x1));
        break;
    case 0x28:     /* MRW */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len > 4)
            printf("      Write=%d\n", !!(ucp[4] & 0x1));
        break;
    case 0x29:     /* Enhanced defect reporting */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      DRT-DM=%d, number of DBI cache zones=0x%x, number of "
               "entries=0x%x\n", !!(ucp[4] & 0x1), ucp[5],
               ((ucp[6] << 8) + ucp[7]));
        break;
    case 0x2a:     /* DVD+RW */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Write=%d, Quick start=%d, Close only=%d\n",
               !!(ucp[4] & 0x1), !!(ucp[5] & 0x2), !!(ucp[5] & 0x1));
        break;
    case 0x2b:     /* DVD+R */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Write=%d\n", !!(ucp[4] & 0x1));
        break;
    case 0x2c:     /* Rigid restricted overwrite */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      DSDG=%d, DSDR=%d, Intermediate=%d, Blank=%d\n",
               !!(ucp[4] & 0x8), !!(ucp[4] & 0x4), !!(ucp[4] & 0x2),
               !!(ucp[4] & 0x1));
        break;
    case 0x2d:     /* CD Track at once */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      BUF=%d, R-W raw=%d, R-W pack=%d, Test write=%d\n",
               !!(ucp[4] & 0x40), !!(ucp[4] & 0x10), !!(ucp[4] & 0x8),
               !!(ucp[4] & 0x4));
        printf("      CD-RW=%d, R-W sub-code=%d\n",
               !!(ucp[4] & 0x2), !!(ucp[4] & 0x1));
        break;
    case 0x2e:     /* CD mastering (session at once) */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      BUF=%d, SAO=%d, Raw MS=%d, Raw=%d\n",
               !!(ucp[4] & 0x40), !!(ucp[4] & 0x20), !!(ucp[4] & 0x10),
               !!(ucp[4] & 0x8));
        printf("      Test write=%d, CD-RW=%d, R-W=%d\n",
               !!(ucp[4] & 0x4), !!(ucp[4] & 0x2), !!(ucp[4] & 0x1));
        printf("      Maximum cue sheet length=0x%x\n",
               (ucp[5] << 16) + (ucp[6] << 8) + ucp[7]);
        break;
    case 0x2f:     /* DVD-R/-RW write */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      BUF=%d, Dual-R=%d, Test write=%d, DVD-RW=%d\n",
               !!(ucp[4] & 0x40), !!(ucp[4] & 0x8), !!(ucp[4] & 0x4),
               !!(ucp[4] & 0x2));
        break;
    case 0x37:     /* CD-RW media write support */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      CD-RW media sub-type support (bitmask)=0x%x\n", ucp[5]);
        break;
    case 0x3b:     /* DVD+R double layer */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Write=%d\n", !!(ucp[4] & 0x1));
        break;
    case 0x40:     /* BD Read */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 32) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Bitmaps for BD-RE read support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", (ucp[8] << 8) + ucp[9],
               (ucp[10] << 8) + ucp[11],
               (ucp[12] << 8) + ucp[13],
               (ucp[14] << 8) + ucp[15]);
        printf("      Bitmaps for BD-R read support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", (ucp[16] << 8) + ucp[17],
               (ucp[18] << 8) + ucp[19],
               (ucp[20] << 8) + ucp[21],
               (ucp[22] << 8) + ucp[23]);
        printf("      Bitmaps for BD-ROM read support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", (ucp[24] << 8) + ucp[25],
               (ucp[26] << 8) + ucp[27],
               (ucp[28] << 8) + ucp[29],
               (ucp[30] << 8) + ucp[31]);
        break;
    case 0x41:     /* BD Write */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 32) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Bitmaps for BD-RE write support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", (ucp[8] << 8) + ucp[9],
               (ucp[10] << 8) + ucp[11],
               (ucp[12] << 8) + ucp[13],
               (ucp[14] << 8) + ucp[15]);
        printf("      Bitmaps for BD-R write support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", (ucp[16] << 8) + ucp[17],
               (ucp[18] << 8) + ucp[19],
               (ucp[20] << 8) + ucp[21],
               (ucp[22] << 8) + ucp[23]);
        printf("      Bitmaps for BD-ROM write support:\n");
        printf("        Class 0=0x%x, Class 1=0x%x, Class 2=0x%x, "
               "Class 3=0x%x\n", (ucp[24] << 8) + ucp[25],
               (ucp[26] << 8) + ucp[27],
               (ucp[28] << 8) + ucp[29],
               (ucp[30] << 8) + ucp[31]);
        break;
    case 0x101:    /* SMART */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      PP=%d\n", !!(ucp[4] & 0x1));
        break;
    case 0x102:    /* Embedded changer */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      SCC=%d, SDP=%d, highest slot number=%d\n",
               !!(ucp[4] & 0x10), !!(ucp[4] & 0x4), (ucp[7] & 0x1f));
        break;
    case 0x103:    /* CD audio external play */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      Scan=%d, SCM=%d, SV=%d, number of volume levels=%d\n",
               !!(ucp[4] & 0x4), !!(ucp[4] & 0x2), !!(ucp[4] & 0x1),
               (ucp[6] << 8) + ucp[7]);
        break;
    case 0x105:    /* Timeout */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len > 7) {
            printf("      Group 3=%d, unit length=%d\n",
                   !!(ucp[4] & 0x1), (ucp[6] << 8) + ucp[7]);
        }
        break;
    case 0x106:    /* DVD CSS */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      CSS version=%d\n", ucp[7]);
        break;
    case 0x107:    /* Real time streaming */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      RBCB=%d, SCS=%d, MP2A=%d, WSPD=%d, SW=%d\n",
               !!(ucp[4] & 0x10), !!(ucp[4] & 0x8), !!(ucp[4] & 0x4),
               !!(ucp[4] & 0x2), !!(ucp[4] & 0x1));
        break;
    case 0x108:    /* Logical unit serial number */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        num = len - 4;
        n = sizeof(buff) - 1;
        n = ((num < n) ? num : n);
        strncpy(buff, (const char *)(ucp + 4), n);
        buff[n] = '\0';
        printf("      Logical unit serial number: %s\n", buff);
        break;
    case 0x10a:    /* Disc control blocks */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        printf("      Disc control blocks:\n");
        for (k = 4; k < len; k += 4) {
            printf("        0x%x\n", (ucp[k] << 24) + (ucp[k + 1] << 16) +
                   (ucp[k + 2] << 8) + ucp[k + 3]);
        }
        break;
    case 0x10b:    /* DVD CPRM */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 8) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      CPRM version=%d\n", ucp[7]);
        break;
    case 0x10c:    /* firmware information */
        printf("    version=%d, persist=%d, current=%d [0x%x]\n",
               ((ucp[2] >> 2) & 0xf), !!(ucp[2] & 0x2), !!(ucp[2] & 0x1),
               feature);
        if (len < 20) {
            printf("      additional length [%d] too short\n", len - 4);
            break;
        }
        printf("      %.2s%.2s/%.2s/%.2s %.2s:%.2s:%.2s\n", ucp + 4,
               ucp + 6, ucp + 8, ucp + 10, ucp + 12, ucp + 14, ucp + 16);
        break;
    default:
        printf("    Unknown feature [0x%x], version=%d persist=%d, "
               "current=%d\n", feature, ((ucp[2] >> 2) & 0xf),
               !!(ucp[2] & 0x2), !!(ucp[2] & 0x1));
        dStrHex((const char *)ucp, len, 1);
        break;
    }
}

static void decode_config(unsigned char * resp, int max_resp_len, int len,
                          int brief, int inner_hex)
{
    int k, curr_profile, extra, feature;
    unsigned char * ucp;
    char buff[128];

    if (max_resp_len < len) {
        printf("<<<warning: response to long for buffer, resp_len=%d>>>\n",
               len);
            len = max_resp_len;
    }
    if (len < 8) {
        printf("response length too short: %d\n", len);
        return;
    }
    curr_profile = (resp[6] << 8) + resp[7];
    if (0 == curr_profile)
        printf("No current profile\n");
    else
        printf("Current profile: %s\n", get_profile_str(curr_profile, buff));
    printf("Features%s:\n", (brief ? " (in brief)" : ""));
    ucp = resp + 8;
    len -= 8;
    for (k = 0; k < len; k += extra, ucp += extra) {
        extra = 4 + ucp[3];
        feature = (ucp[0] << 8) + ucp[1];
        printf("  %s feature\n", get_feature_str(feature, buff));
        if (brief)
            continue;
        if (inner_hex) {
            dStrHex((const char *)ucp, extra, 1);
            continue;
        }
        if (0 != (extra % 4))
        printf("    additional length [%d] not a multiple of 4, ignore\n",
               extra - 4);
        else
            decode_feature(feature, ucp, extra);
    }
}

static void list_known(int brief)
{
    int k, num;

    num = sizeof(feature_desc_arr) / sizeof(feature_desc_arr[0]);
    printf("Known features:\n");
    for (k = 0; k < num; ++k)
        printf("  %s [0x%x]\n", feature_desc_arr[k].desc,
               feature_desc_arr[k].code);
    if (! brief) {
        printf("Known profiles:\n");
        num = sizeof(profile_desc_arr) / sizeof(profile_desc_arr[0]);
        for (k = 0; k < num; ++k)
            printf("  %s [0x%x]\n", profile_desc_arr[k].desc,
                   profile_desc_arr[k].code);
    }
}


int main(int argc, char * argv[])
{
    int sg_fd, res, c, len;
    int peri_type = 0;
    int brief = 0;
    int hex = 0;
    int inner_hex = 0;
    int list = 0;
    int rt = 0;
    int starting = 0;
    int verbose = 0;
    char device_name[256];
    const char * cp;
    struct sg_simple_inquiry_resp inq_resp;
    int ret = 1;

    memset(device_name, 0, sizeof device_name);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "bhHilr:s:vV", long_options,
                        &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'b':
            brief = 1;
            break;
        case 'h':
        case '?':
            usage();
            return 0;
        case 'H':
            hex = 1;
            break;
        case 'i':
            inner_hex = 1;
            break;
        case 'l':
            list = 1;
            break;
        case 'r':
            rt = sg_get_num(optarg);
            if ((rt < 0) || (rt > 3)) {
                fprintf(stderr, "bad argument to '--rt'\n");
                return 1;
            }
            break;
        case 's':
            starting = sg_get_num(optarg);
            if ((starting < 0) || (starting > 0xffff)) {
                fprintf(stderr, "bad argument to '--starting'\n");
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

    if (list) {
        list_known(brief);
        return 0;
    }
    if (0 == device_name[0]) {
        fprintf(stderr, "missing device name!\n");
        usage();
        return 1;
    }
    if ((sg_fd = open(device_name, O_RDONLY | O_NONBLOCK)) < 0) {
        snprintf(ebuff, EBUFF_SZ, ME "error opening file: %s (ro)",
                 device_name);
        perror(ebuff);
        return 1;
    }
    if (0 == sg_simple_inquiry(sg_fd, &inq_resp, 1, verbose)) {
        printf("  %.8s  %.16s  %.4s\n", inq_resp.vendor, inq_resp.product,
               inq_resp.revision);
        peri_type = inq_resp.peripheral_type;
        cp = get_ptype_str(peri_type);
        if (strlen(cp) > 0)
            printf("  Peripheral device type: %s\n", cp);
        else
            printf("  Peripheral device type: 0x%x\n", peri_type);
    } else {
        printf(ME "%s doesn't respond to a SCSI INQUIRY\n", device_name);
        return 1;
    }
    close(sg_fd);

    sg_fd = open(device_name, O_RDWR | O_NONBLOCK);
    if (sg_fd < 0) {
        perror(ME "open error (rw)");
        return 1;
    }

    res = sg_ll_get_config(sg_fd, rt, starting, resp_buffer, 
                              sizeof(resp_buffer), 1, verbose);
    if (0 == res) {
        ret = 0;
        len = (resp_buffer[0] << 24) + (resp_buffer[1] << 16) +
              (resp_buffer[2] << 8) + resp_buffer[3] + 4;
        if (hex) {
            if (len > (int)sizeof(resp_buffer))
                len = sizeof(resp_buffer);
            dStrHex((const char *)resp_buffer, len, 0);
        } else
            decode_config(resp_buffer, sizeof(resp_buffer), len, brief,
                          inner_hex);
    } else if (SG_LIB_CAT_INVALID_OP == res)
        fprintf(stderr, "Get Configuration command not supported\n");
    else if (SG_LIB_CAT_ILLEGAL_REQ == res)
        fprintf(stderr, "field in Get Configuration command illegal\n");
    else
        fprintf(stderr, "Get Configuration command failed\n");

    res = close(sg_fd);
    if (res < 0) {
        perror(ME "close error");
        return 1;
    }
    return ret;
}


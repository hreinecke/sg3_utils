/*
 * Copyright (c) 2022-2023 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include "sg_json_sg_lib.h"
#include "sg_pr2serr.h"

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_unaligned.h"
#include "sg_json_builder.h"


static const char * dtsp = "descriptor too short";
static const char * sksvp = "sense-key specific valid";
static const char * ddep = "designation_descriptor_error";
static const char * naa_exp = "Network Address Authority";
static const char * aoi_exp = "IEEE-Administered Organizational Identifier";

bool
sgj_js_designation_descriptor(sgj_state * jsp, sgj_opaque_p jop,
                              const uint8_t * ddp, int dd_len)
{
    int p_id, piv, c_set, assoc, desig_type, d_id, naa;
    int n, aoi, vsi, dlen;
    uint64_t ull;
    const uint8_t * ip;
    char e[80];
    char b[256];
    const char * cp;
    const char * naa_sp;
    sgj_opaque_p jo2p;
    static const int blen = sizeof(b);
    static const int elen = sizeof(e);

    if (dd_len < 4) {
        sgj_js_nv_s(jsp, jop, ddep, "too short");
        return false;
    }
    dlen = ddp[3];
    if (dlen > (dd_len - 4)) {
        snprintf(e, elen, "too long: says it is %d bytes, but given %d "
                 "bytes\n", dlen, dd_len - 4);
        sgj_js_nv_s(jsp, jop, ddep, e);
        return false;
    }
    ip = ddp + 4;
    p_id = ((ddp[0] >> 4) & 0xf);
    c_set = (ddp[0] & 0xf);
    piv = ((ddp[1] & 0x80) ? 1 : 0);
    assoc = ((ddp[1] >> 4) & 0x3);
    desig_type = (ddp[1] & 0xf);
    cp = sg_get_desig_assoc_str(assoc);
    if (assoc == 3)
        cp = "Reserved [0x3]";    /* should not happen */
    sgj_js_nv_ihexstr(jsp, jop, "association", assoc, NULL, cp);
    cp = sg_get_desig_type_str(desig_type);
    if (NULL == cp)
        cp = "unknown";
    sgj_js_nv_ihexstr(jsp, jop, "designator_type", desig_type,
                       NULL, cp);
    cp = sg_get_desig_code_set_str(c_set);
    if (NULL == cp)
        cp = "unknown";
    sgj_js_nv_ihexstr(jsp, jop, "code_set", desig_type,
                      NULL, cp);
    sgj_js_nv_ihex_nex(jsp, jop, "piv", piv, false,
                       "Protocol Identifier Valid");
    sg_get_trans_proto_str(p_id, elen, e);
    sgj_js_nv_ihexstr(jsp, jop, "protocol_identifier", p_id, NULL, e);
    switch (desig_type) {
    case 0: /* vendor specific */
        sgj_js_nv_hex_bytes(jsp, jop, "vendor_specific_hexbytes", ip, dlen);
        break;
    case 1: /* T10 vendor identification */
        n = (dlen < 8) ? dlen : 8;
        snprintf(b, blen, "%.*s", n, ip);
        sgj_js_nv_s(jsp, jop, "t10_vendor_identification", b);
        b[0] = '\0';
        if (dlen > 8)
            snprintf(b, blen, "%.*s", dlen - 8, ip + 8);
        sgj_js_nv_s(jsp, jop, "vendor_specific_identifier", b);
        break;
    case 2: /* EUI-64 based */
        sgj_js_nv_i(jsp, jop, "eui_64_based_designator_length", dlen);
        ull = sg_get_unaligned_be64(ip);
        switch (dlen) {
        case 8:
            sgj_js_nv_ihex(jsp, jop, "ieee_identifier", ull);
            break;
        case 12:
            sgj_js_nv_ihex(jsp, jop, "ieee_identifier", ull);
            sgj_js_nv_ihex(jsp, jop, "directory_id",
                            sg_get_unaligned_be32(ip + 8));
            break;
        case 16:
            sgj_js_nv_ihex(jsp, jop, "identifier_extension", ull);
            sgj_js_nv_ihex(jsp, jop, "ieee_identifier",
                            sg_get_unaligned_be64(ip + 8));
            break;
        default:
            sgj_js_nv_s(jsp, jop, "eui_64", "decoding failed");
            break;
        }
        break;
    case 3: /* NAA <n> */
        if (jsp->pr_hex)
            sgj_js_nv_hex_bytes(jsp, jop, "full_naa_hexbytes", ip, dlen);
        naa = (ip[0] >> 4) & 0xff;
        switch (naa) {
        case 2:
            naa_sp = "IEEE Extended";
            sgj_js_nv_ihexstr_nex(jsp, jop, "naa", naa, false, NULL, naa_sp,
                                  naa_exp);
            d_id = (((ip[0] & 0xf) << 8) | ip[1]);
            sgj_js_nv_ihex(jsp, jop, "vendor_specific_identifier_a", d_id);
            aoi = sg_get_unaligned_be24(ip + 2);
            sgj_js_nv_ihex_nex(jsp, jop, "aoi", aoi, true, aoi_exp);
            vsi = sg_get_unaligned_be24(ip + 5);
            sgj_js_nv_ihex(jsp, jop, "vendor_specific_identifier_b", vsi);
            break;
        case 3:
            naa_sp = "Locally Assigned";
            sgj_js_nv_ihexstr_nex(jsp, jop, "naa", naa, false, NULL, naa_sp,
                                  naa_exp);
            ull = sg_get_unaligned_be64(ip + 0) & 0xfffffffffffffffULL;
            sgj_js_nv_ihex(jsp, jop, "locally_administered_value", ull);
            break;
        case 5:
            naa_sp = "IEEE Registered";
            sgj_js_nv_ihexstr_nex(jsp, jop, "naa", naa, false, NULL, naa_sp,
                                  naa_exp);
            aoi = (sg_get_unaligned_be32(ip + 0) >> 4) & 0xffffff;
            sgj_js_nv_ihex_nex(jsp, jop, "aoi", aoi, true, aoi_exp);
            ull = sg_get_unaligned_be48(ip + 2) & 0xfffffffffULL;
            sgj_js_nv_ihex(jsp, jop, "vendor_specific_identifier", ull);
            break;
        case 6:
            naa_sp = "IEEE Registered Extended";
            sgj_js_nv_ihexstr_nex(jsp, jop, "naa", naa, false, NULL, naa_sp,
                                  naa_exp);
            aoi = (sg_get_unaligned_be32(ip + 0) >> 4) & 0xffffff;
            sgj_js_nv_ihex_nex(jsp, jop, "aoi", aoi, true, aoi_exp);
            ull = sg_get_unaligned_be48(ip + 2) & 0xfffffffffULL;
            sgj_js_nv_ihex(jsp, jop, "vendor_specific_identifier", ull);
            ull = sg_get_unaligned_be64(ip + 8);
            sgj_js_nv_ihex(jsp, jop, "vendor_specific_identifier_extension",
                           ull);
            break;
        default:
            snprintf(b, blen, "unknown NAA value=0x%x", naa);
            sgj_js_nv_ihexstr_nex(jsp, jop, "naa", naa, true, NULL, b,
                                  naa_exp);
            sgj_js_nv_hex_bytes(jsp, jop, "full_naa_hexbytes", ip, dlen);
            break;
        }
        break;
    case 4: /* Relative target port */
        if (jsp->pr_hex)
            sgj_js_nv_hex_bytes(jsp, jop, "relative_target_port_hexbytes",
                                ip, dlen);
        sgj_js_nv_ihex(jsp, jop, "relative_target_port_identifier",
                       sg_get_unaligned_be16(ip + 2));
        break;
    case 5: /* (primary) Target port group */
        if (jsp->pr_hex)
            sgj_js_nv_hex_bytes(jsp, jop, "target_port_group_hexbytes",
                                ip, dlen);
        sgj_js_nv_ihex(jsp, jop, "target_port_group",
                       sg_get_unaligned_be16(ip + 2));
        break;
    case 6: /* Logical unit group */
        if (jsp->pr_hex)
            sgj_js_nv_hex_bytes(jsp, jop, "logical_unit_group_hexbytes",
                                ip, dlen);
        sgj_js_nv_ihex(jsp, jop, "logical_unit_group",
                       sg_get_unaligned_be16(ip + 2));
        break;
    case 7: /* MD5 logical unit identifier */
        sgj_js_nv_hex_bytes(jsp, jop, "md5_logical_unit_hexbytes",
                            ip, dlen);
        break;
    case 8: /* SCSI name string */
        if (jsp->pr_hex)
            sgj_js_nv_hex_bytes(jsp, jop, "scsi_name_string_hexbytes",
                                ip, dlen);
        snprintf(b, blen, "%.*s", dlen, ip);
        sgj_js_nv_s(jsp, jop, "scsi_name_string", b);
        break;
    case 9: /* Protocol specific port identifier */
        if (jsp->pr_hex)
            sgj_js_nv_hex_bytes(jsp, jop,
                                "protocol_specific_port_identifier_hexbytes",
                                ip, dlen);
        if (TPROTO_UAS == p_id) {
            jo2p = sgj_named_subobject_r(jsp, jop,
                                        "usb_target_port_identifier");
            sgj_js_nv_ihex(jsp, jo2p, "device_address", 0x7f & ip[0]);
            sgj_js_nv_ihex(jsp, jo2p, "interface_number", ip[2]);
        } else if (TPROTO_SOP == p_id) {
            jo2p = sgj_named_subobject_r(jsp, jop, "pci_express_routing_id");
            sgj_js_nv_ihex(jsp, jo2p, "routing_id",
                           sg_get_unaligned_be16(ip + 0));
        } else
            sgj_js_nv_s(jsp, jop, "protocol_specific_port_identifier",
                        "decoding failure");

        break;
    case 0xa: /* UUID identifier */
        if (jsp->pr_hex)
            sgj_js_nv_hex_bytes(jsp, jop, "uuid_hexbytes", ip, dlen);
        sg_t10_uuid_desig2str(ip, dlen, c_set, false, true, NULL, blen, b);
        n = strlen(b);
        if ((n > 0) && ('\n' == b[n - 1]))
            b[n - 1] = '\0';
        sgj_js_nv_s(jsp, jop, "uuid", b);
        break;
    default: /* reserved */
        sgj_js_nv_hex_bytes(jsp, jop, "reserved_designator_hexbytes",
                            ip, dlen);
        break;
    }
    return true;
}

static void
sgj_progress_indication(sgj_state * jsp, sgj_opaque_p jop,
                        uint16_t prog_indic, bool is_another)
{
    uint32_t progress, pr, rem;
    sgj_opaque_p jo2p;
    char b[64];

    if (is_another)
        jo2p = sgj_named_subobject_r(jsp, jop, "another_progress_indication");
    else
        jo2p = sgj_named_subobject_r(jsp, jop, "progress_indication");
    if (NULL == jo2p)
        return;
    progress = prog_indic;
    sgj_js_nv_i(jsp, jo2p, "i", progress);
    snprintf(b, sizeof(b), "%x", progress);
    sgj_js_nv_s(jsp, jo2p, "hex", b);
    progress *= 100;
    pr = progress / 65536;
    rem = (progress % 65536) / 656;
    snprintf(b, sizeof(b), "%d.02%d%%\n", pr, rem);
    sgj_js_nv_s(jsp, jo2p, "percentage", b);
}

static bool
sgj_decode_sks(sgj_state * jsp, sgj_opaque_p jop, const uint8_t * dp, int dlen,
               int sense_key)
{
    switch (sense_key) {
    case SPC_SK_ILLEGAL_REQUEST:
        if (dlen < 3) {
            sgj_js_nv_s(jsp, jop, "illegal_request_sks", dtsp);
            return false;
        }
        sgj_js_nv_ihex_nex(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                           sksvp);
        sgj_js_nv_ihex_nex(jsp, jop, "c_d", !! (dp[0] & 0x40), false,
                           "c: cdb; d: data-out");
        sgj_js_nv_ihex_nex(jsp, jop, "bpv", !! (dp[0] & 0x8), false,
                           "bit pointer (index) valid");
        sgj_js_nv_i(jsp, jop, "bit_pointer", dp[0] & 0x7);
        sgj_js_nv_ihex(jsp, jop, "field_pointer",
                       sg_get_unaligned_be16(dp + 1));
        break;
    case SPC_SK_HARDWARE_ERROR:
    case SPC_SK_MEDIUM_ERROR:
    case SPC_SK_RECOVERED_ERROR:
        if (dlen < 3) {
            sgj_js_nv_s(jsp, jop, "actual_retry_count_sks", dtsp);
            return false;
        }
        sgj_js_nv_ihex_nex(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                           sksvp);
        sgj_js_nv_ihex(jsp, jop, "actual_retry_count",
                       sg_get_unaligned_be16(dp + 1));
        break;
    case SPC_SK_NO_SENSE:
    case SPC_SK_NOT_READY:
        if (dlen < 7) {
            sgj_js_nv_s(jsp, jop, "progress_indication_sks", dtsp);
            return false;
        }
        sgj_js_nv_ihex_nex(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                           sksvp);
        sgj_progress_indication(jsp, jop, sg_get_unaligned_be16(dp + 1),
                                false);
        break;
    case SPC_SK_COPY_ABORTED:
        if (dlen < 7) {
            sgj_js_nv_s(jsp, jop, "segment_indication_sks", dtsp);
            return false;
        }
        sgj_js_nv_ihex_nex(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                           sksvp);
        sgj_js_nv_ihex_nex(jsp, jop, "sd", !! (dp[0] & 0x20), false,
                           "field pointer relative to: 1->segment "
                           "descriptor, 0->parameter list");
        sgj_js_nv_ihex_nex(jsp, jop, "bpv", !! (dp[0] & 0x8), false,
                           "bit pointer (index) valid");
        sgj_js_nv_i(jsp, jop, "bit_pointer", dp[0] & 0x7);
        sgj_js_nv_ihex(jsp, jop, "field_pointer",
                       sg_get_unaligned_be16(dp + 1));
        break;
    case SPC_SK_UNIT_ATTENTION:
        if (dlen < 7) {
            sgj_js_nv_s(jsp, jop, "segment_indication_sks", dtsp);
            return false;
        }
        sgj_js_nv_ihex_nex(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                           sksvp);
        sgj_js_nv_i(jsp, jop, "overflow", !! (dp[0] & 0x80));
        break;
    default:
        sgj_js_nv_ihex(jsp, jop, "unexpected_sense_key", sense_key);
        return false;
    }
    return true;
}

#define TPGS_STATE_OPTIMIZED 0x0
#define TPGS_STATE_NONOPTIMIZED 0x1
#define TPGS_STATE_STANDBY 0x2
#define TPGS_STATE_UNAVAILABLE 0x3
#define TPGS_STATE_OFFLINE 0xe
#define TPGS_STATE_TRANSITIONING 0xf

static int
decode_tpgs_state(int st, char * b, int blen)
{
    switch (st) {
    case TPGS_STATE_OPTIMIZED:
        return sg_scnpr(b, blen, "active/optimized");
    case TPGS_STATE_NONOPTIMIZED:
        return sg_scnpr(b, blen, "active/non optimized");
    case TPGS_STATE_STANDBY:
        return sg_scnpr(b, blen, "standby");
    case TPGS_STATE_UNAVAILABLE:
        return sg_scnpr(b, blen, "unavailable");
    case TPGS_STATE_OFFLINE:
        return sg_scnpr(b, blen, "offline");
    case TPGS_STATE_TRANSITIONING:
        return sg_scnpr(b, blen, "transitioning between states");
    default:
        return sg_scnpr(b, blen, "unknown: 0x%x", st);
    }
}

static bool
sgj_uds_referral_descriptor(sgj_state * jsp, sgj_opaque_p jop,
                            const uint8_t * dp, int alen)
{
    int dlen = alen - 2;
    int k, j, g, f, aas;
    uint64_t ull;
    const uint8_t * tp;
    sgj_opaque_p jap, jo2p, ja2p, jo3p;
    char c[40];

    sgj_js_nv_ihex_nex(jsp, jop, "not_all_r", (dp[2] & 0x1), false,
                       "Not all referrals");
    dp += 4;
    jap = sgj_named_subarray_r(jsp, jop,
                               "user_data_segment_referral_descriptor_list");
    for (k = 0, f = 1; (k + 4) < dlen; k += g, dp += g, ++f) {
        int ntpgd = dp[3];

        jo2p = sgj_new_unattached_object_r(jsp);
        g = (ntpgd * 4) + 20;
        sgj_js_nv_ihex(jsp, jo2p, "number_of_target_port_group_descriptors",
                       ntpgd);
        if ((k + g) > dlen) {
            sgj_js_nv_i(jsp, jo2p, "truncated_descriptor_dlen", dlen);
            sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
            return false;
        }
        ull = sg_get_unaligned_be64(dp + 4);
        sgj_js_nv_ihex(jsp, jo2p, "first_user_date_sgment_lba", ull);
        ull = sg_get_unaligned_be64(dp + 12);
        sgj_js_nv_ihex(jsp, jo2p, "last_user_date_sgment_lba", ull);
        ja2p = sgj_named_subarray_r(jsp, jo2p,
                                    "target_port_group_descriptor_list");
        for (j = 0; j < ntpgd; ++j) {
            jo3p = sgj_new_unattached_object_r(jsp);
            tp = dp + 20 + (j * 4);
            aas = tp[0] & 0xf;
            decode_tpgs_state(aas, c, sizeof(c));
            sgj_js_nv_ihexstr(jsp, jo3p, "asymmetric_access_state", aas,
                              NULL, c);
            sgj_js_nv_ihex(jsp, jo3p, "target_port_group",
                           sg_get_unaligned_be16(tp + 2));
            sgj_js_nv_o(jsp, ja2p, NULL /* name */, jo3p);
        }
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    return true;
}

/* Copy of static array in sg_lib.c */
static const char * dd_usage_reason_str_arr[] = {
    "Unknown",
    "resend this and further commands to:",
    "resend this command to:",
    "new subsidiary lu added to this administrative lu:",
    "administrative lu associated with a preferred binding:",
   };

static bool
sgj_js_sense_descriptors(sgj_state * jsp, sgj_opaque_p jop,
                         const struct sg_scsi_sense_hdr * sshp,
                         const uint8_t * sbp, int sb_len)
{
    bool processed = true;
    int add_sb_len, desc_len, k, dt, sense_key, n, sds;
    uint16_t sct_sc;
    uint64_t ull;
    const uint8_t * descp;
    const char * cp;
    sgj_opaque_p jap, jo2p, jo3p;
    char b[80];
    static const int blen = sizeof(b);
    static const char * parsing = "parsing_error";
#if 0
    static const char * eccp = "Extended copy command";
    static const char * ddp = "destination device";
#endif

    add_sb_len = sshp->additional_length;
    add_sb_len = (add_sb_len < sb_len) ? add_sb_len : sb_len;
    sense_key = sshp->sense_key;
    jap = sgj_named_subarray_r(jsp, jop, "sense_data_descriptor_list");

    for (descp = sbp, k = 0; (k < add_sb_len);
         k += desc_len, descp += desc_len) {
        int add_d_len = (k < (add_sb_len - 1)) ? descp[1] : -1;

        jo2p = sgj_new_unattached_object_r(jsp);
        if ((k + add_d_len + 2) > add_sb_len)
            add_d_len = add_sb_len - k - 2;
        desc_len = add_d_len + 2;
        processed = true;
        dt = descp[0];
        switch (dt) {
        case 0:
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt,
                              NULL, "Information");
            if (add_d_len >= 10) {
                int valid = !! (0x80 & descp[2]);
                sgj_js_nv_ihexstr(jsp, jo2p, "valid", valid, NULL,
                                  valid ? "as per T10" : "Vendor specific");
                sgj_js_nv_ihex(jsp, jo2p, "information",
                               sg_get_unaligned_be64(descp + 4));
            } else {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 1:
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt,
                              NULL, "Command specific");
            if (add_d_len >= 10) {
                sgj_js_nv_ihex(jsp, jo2p, "command_specific_information",
                               sg_get_unaligned_be64(descp + 4));
            } else {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 2:         /* Sense Key Specific */
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "Sense key specific");
            processed = sgj_decode_sks(jsp, jo2p, descp + 4, desc_len - 4,
                                       sense_key);
            break;
        case 3:
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "Field replaceable unit code");
            if (add_d_len >= 2)
                sgj_js_nv_ihex(jsp, jo2p, "field_replaceable_unit_code",
                               descp[3]);
            else {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 4:
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "Stream commands");
            if (add_d_len >= 2) {
                sgj_js_nv_i(jsp, jo2p, "filemark", !! (descp[3] & 0x80));
                sgj_js_nv_ihex_nex(jsp, jo2p, "eom", !! (descp[3] & 0x40),
                                   false, "End Of Medium");
                sgj_js_nv_ihex_nex(jsp, jo2p, "ili", !! (descp[3] & 0x20),
                                   false, "Incorrect Length Indicator");
            } else {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 5:
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "Block commands");
            if (add_d_len >= 2)
                sgj_js_nv_ihex_nex(jsp, jo2p, "ili", !! (descp[3] & 0x20),
                                   false, "Incorrect Length Indicator");
            else {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 6:
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "OSD object identification");
            sgj_js_nv_s(jsp, jo2p, parsing, "Unsupported");
            processed = false;
            break;
        case 7:
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "OSD response integrity check value");
            sgj_js_nv_s(jsp, jo2p, parsing, "Unsupported");
            break;
        case 8:
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "OSD attribute identification");
            sgj_js_nv_s(jsp, jo2p, parsing, "Unsupported");
            processed = false;
            break;
        case 9:         /* this is defined in SAT (SAT-2) */
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "ATA status return");
            if (add_d_len >= 12) {
                sgj_js_nv_i(jsp, jo2p, "extend", !! (descp[2] & 1));
                sgj_js_nv_ihex(jsp, jo2p, "error", descp[3]);
                sgj_js_nv_ihex(jsp, jo2p, "count",
                               sg_get_unaligned_be16(descp + 4));
                ull = ((uint64_t)descp[10] << 40) |
                       ((uint64_t)descp[8] << 32) |
                       (descp[6] << 24) |
                       (descp[11] << 16) |
                       (descp[9] << 8) |
                       descp[7];
                sgj_js_nv_ihex(jsp, jo2p, "lba", ull);
                sgj_js_nv_ihex(jsp, jo2p, "device", descp[12]);
                sgj_js_nv_ihex(jsp, jo2p, "status", descp[13]);
            } else {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 0xa:
           /* Added in SPC-4 rev 17, became 'Another ...' in rev 34 */
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "Another progress indication");
            if (add_d_len < 6) {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
                break;
            }
            sgj_js_nv_ihex(jsp, jo2p, "another_sense_key", descp[2]);
            sgj_js_nv_ihex(jsp, jo2p, "another_additional_sense_code",
                           descp[3]);
            sgj_js_nv_ihex(jsp, jo2p,
                           "another_additional_sense_code_qualifier",
                           descp[4]);
            sgj_progress_indication(jsp, jo2p,
                                    sg_get_unaligned_be16(descp + 6), true);
            break;
        case 0xb:       /* Added in SPC-4 rev 23, defined in SBC-3 rev 22 */
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "User data segment referral");
            if (add_d_len < 2) {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
                break;
            }
            if (! sgj_uds_referral_descriptor(jsp, jo2p, descp, add_d_len)) {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 0xc:       /* Added in SPC-4 rev 28 */
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "Forwarded sense data");
            if (add_d_len < 2) {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
                break;
            }
            sgj_js_nv_ihex_nex(jsp, jo2p, "fsdt", !! (0x80 & descp[2]),
                               false, "Forwarded Sense Data Truncated");
            sds = (0x7 & descp[2]);
            if (sds < 1)
                snprintf(b, blen, "%s [%d]", "Unknown", sds);
            else if (sds > 9)
                snprintf(b, blen, "%s [%d]", "Reserved", sds);
            else {
                n = 0;
                n += sg_scnpr(b + n, blen - n, "EXTENDED COPY command copy %s",
                              (sds == 1) ? "source" : "destination");
                if (sds > 1)
                    sg_scnpr(b + n, blen - n, " %d", sds - 1);
            }
            sgj_js_nv_ihexstr(jsp, jo2p, "sense_data_source",
                              (0x7 & descp[2]), NULL, b);
            jo3p = sgj_named_subobject_r(jsp, jo2p, "forwarded_sense_data");
            sgj_js_sense(jsp, jo3p, descp + 4, desc_len - 4);
            break;
        case 0xd:       /* Added in SBC-3 rev 36d */
            /* this descriptor combines descriptors 0, 1, 2 and 3 */
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "Direct-access block device");
            if (add_d_len < 28) {
                sgj_js_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
                break;
            }
            sgj_js_nv_i(jsp, jo2p, "valid", (0x80 & descp[2]));
            sgj_js_nv_ihex_nex(jsp, jo2p, "ili", !! (0x20 & descp[2]),
                               false, "Incorrect Length Indicator");
            processed = sgj_decode_sks(jsp, jo2p, descp + 4, desc_len - 4,
                                       sense_key);
            sgj_js_nv_ihex(jsp, jo2p, "field_replaceable_unit_code",
                           descp[7]);
            sgj_js_nv_ihex(jsp, jo2p, "information",
                           sg_get_unaligned_be64(descp + 8));
            sgj_js_nv_ihex(jsp, jo2p, "command_specific_information",
                           sg_get_unaligned_be64(descp + 16));
            break;
        case 0xe:       /* Added in SPC-5 rev 6 (for Bind/Unbind) */
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "Device designation");
            n = descp[3];
            cp = (n < (int)SG_ARRAY_SIZE(dd_usage_reason_str_arr)) ?
                  dd_usage_reason_str_arr[n] : "Unknown (reserved)";
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_usage_reason",
                              n, NULL, cp);
            jo3p = sgj_named_subobject_r(jsp, jo2p,
                                         "device_designation_descriptor");
            sgj_js_designation_descriptor(jsp, jo3p, descp + 4, desc_len - 4);
            break;
        case 0xf:       /* Added in SPC-5 rev 10 (for Write buffer) */
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "Microcode activation");
            if (add_d_len < 6) {
                sgj_js_nv_s(jsp, jop, parsing, dtsp);
                processed = false;
                break;
            }
            sgj_js_nv_ihex(jsp, jo2p, "microcode_activation_time",
                           sg_get_unaligned_be16(descp + 6));
            break;
        case 0xde:       /* NVME Status Field; vendor (sg3_utils) specific */
            sgj_js_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                              "NVME status (sg3_utils)");
            if (add_d_len < 6) {
                sgj_js_nv_s(jsp, jop, parsing, dtsp);
                processed = false;
                break;
            }
            sgj_js_nv_ihex_nex(jsp, jo2p, "dnr", !! (0x80 & descp[5]),
                               false, "Do not retry");
            sgj_js_nv_ihex_nex(jsp, jo2p, "m", !! (0x40 & descp[5]),
                               false, "More");
            sct_sc = sg_get_unaligned_be16(descp + 6);
            sgj_js_nv_ihexstr_nex
                (jsp, jo2p, "sct_sc", sct_sc, true, NULL,
                 sg_get_nvme_cmd_status_str(sct_sc, blen, b),
                 "Status Code Type (upper 8 bits) and Status Code");
            break;
        default:
            if (dt >= 0x80)
                sgj_js_nv_ihex(jsp, jo2p, "vendor_specific_descriptor_type",
                               dt);
            else
                sgj_js_nv_ihex(jsp, jo2p, "unknown_descriptor_type", dt);
            sgj_js_nv_hex_bytes(jsp, jo2p, "descriptor_hexbytes",
                                descp, desc_len);
            processed = false;
            break;
        }
        sgj_js_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    return processed;
}

#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d  /* corresponding ASC is 0 */

/* Fetch sense information */
bool
sgj_js_sense(sgj_state * jsp, sgj_opaque_p jop, const uint8_t * sbp,
             int sb_len)
{
    bool descriptor_format = false;
    bool sdat_ovfl = false;
    bool ret = true;
    bool valid_info_fld;
    int len, n;
    uint32_t info;
    uint8_t resp_code;
    const char * ebp = NULL;
    char ebuff[64];
    char b[256];
    struct sg_scsi_sense_hdr ssh;
    static int blen = sizeof(b);
    static int elen = sizeof(ebuff);

    if ((NULL == sbp) || (sb_len < 1)) {
        snprintf(ebuff, elen, "sense buffer empty\n");
        ebp = ebuff;
        ret = false;
        goto fini;
    }
    resp_code = 0x7f & sbp[0];
    valid_info_fld = !!(sbp[0] & 0x80);
    len = sb_len;
    if (! sg_scsi_normalize_sense(sbp, sb_len, &ssh)) {
        ebp = "unable to normalize sense buffer";
        ret = false;
        goto fini;
    }
    /* We have been able to normalize the sense buffer */
    switch (resp_code) {
    case 0x70:      /* fixed, current */
        ebp = "Fixed format, current";
        len = (sb_len > 7) ? (sbp[7] + 8) : sb_len;
        len = (len > sb_len) ? sb_len : len;
        sdat_ovfl = (len > 2) ? !!(sbp[2] & 0x10) : false;
        break;
    case 0x71:      /* fixed, deferred */
        /* error related to a previous command */
        ebp = "Fixed format, <<<deferred>>>";
        len = (sb_len > 7) ? (sbp[7] + 8) : sb_len;
        len = (len > sb_len) ? sb_len : len;
        sdat_ovfl = (len > 2) ? !!(sbp[2] & 0x10) : false;
        break;
    case 0x72:      /* descriptor, current */
        descriptor_format = true;
        ebp = "Descriptor format, current";
        sdat_ovfl = (sb_len > 4) ? !!(sbp[4] & 0x80) : false;
        break;
    case 0x73:      /* descriptor, deferred */
        descriptor_format = true;
        ebp = "Descriptor format, <<<deferred>>>";
        sdat_ovfl = (sb_len > 4) ? !!(sbp[4] & 0x80) : false;
        break;
    default:
        sg_scnpr(ebuff, elen, "Unknown code: 0x%x", resp_code);
        ebp = ebuff;
        break;
    }
    sgj_js_nv_ihexstr(jsp, jop, "response_code", resp_code, NULL, ebp);
    sgj_js_nv_b(jsp, jop, "descriptor_format", descriptor_format);
    sgj_js_nv_ihex_nex(jsp, jop, "sdat_ovfl", sdat_ovfl, false,
                       "Sense data overflow");
    sgj_js_nv_ihexstr(jsp, jop, "sense_key", ssh.sense_key, NULL,
                      sg_lib_sense_key_desc[ssh.sense_key]);
    sgj_js_nv_ihex(jsp, jop, "additional_sense_code", ssh.asc);
    sgj_js_nv_ihex(jsp, jop, "additional_sense_code_qualifier", ssh.ascq);
    sgj_js_nv_s(jsp, jop, "additional_sense_str",
                sg_get_additional_sense_str(ssh.asc, ssh.ascq, false,
                                             blen, b));
    if (descriptor_format) {
        if (len > 8) {
            ret = sgj_js_sense_descriptors(jsp, jop, &ssh, sbp + 8, len - 8);
            if (ret == false) {
                ebp = "unable to decode sense descriptor";
                goto fini;
            }
        }
    } else if ((len > 12) && (0 == ssh.asc) &&
               (ASCQ_ATA_PT_INFO_AVAILABLE == ssh.ascq)) {
        /* SAT ATA PASS-THROUGH fixed format */
        sgj_js_nv_ihex(jsp, jop, "error", sbp[3]);
        sgj_js_nv_ihex(jsp, jop, "status", sbp[4]);
        sgj_js_nv_ihex(jsp, jop, "device", sbp[5]);
        sgj_js_nv_i(jsp, jop, "extend", !! (0x80 & sbp[8]));
        sgj_js_nv_i(jsp, jop, "count_upper_nonzero", !! (0x40 & sbp[8]));
        sgj_js_nv_i(jsp, jop, "lba_upper_nonzero", !! (0x20 & sbp[8]));
        sgj_js_nv_i(jsp, jop, "log_index", (0xf & sbp[8]));
        sgj_js_nv_i(jsp, jop, "lba", sg_get_unaligned_le24(sbp + 9));
    } else if (len > 2) {   /* fixed format */
        sgj_js_nv_i(jsp, jop, "valid", valid_info_fld);
        sgj_js_nv_i(jsp, jop, "filemark", !! (sbp[2] & 0x80));
        sgj_js_nv_ihex_nex(jsp, jop, "eom", !! (sbp[2] & 0x40),
                           false, "End Of Medium");
        sgj_js_nv_ihex_nex(jsp, jop, "ili", !! (sbp[2] & 0x20),
                           false, "Incorrect Length Indicator");
        info = sg_get_unaligned_be32(sbp + 3);
        sgj_js_nv_ihex(jsp, jop, "information", info);
        sgj_js_nv_ihex(jsp, jop, "additional_sense_length", sbp[7]);
        if (sb_len > 11) {
            info = sg_get_unaligned_be32(sbp + 8);
            sgj_js_nv_ihex(jsp, jop, "command_specific_information", info);
        }
        if (sb_len > 14)
            sgj_js_nv_ihex(jsp, jop, "field_replaceable_unit_code", sbp[14]);
        if (sb_len > 17)
            sgj_decode_sks(jsp, jop, sbp + 15, sb_len - 15, ssh.sense_key);
        n =  sbp[7];
        n = (sb_len > n) ? n : sb_len;
        sgj_js_nv_ihex(jsp, jop, "number_of_bytes_beyond_18",
                       (n > 18) ? n - 18 : 0);
    } else {
        snprintf(ebuff, sizeof(ebuff), "sb_len=%d too short", sb_len);
        ebp = ebuff;
        ret = false;
    }
fini:
    if ((! ret) && ebp)
        sgj_js_nv_s(jsp, jop, "sense_decode_error", ebp);
    return ret;
}

void
sgj_js2file(sgj_state * jsp, sgj_opaque_p jop, int exit_status, FILE * fp)
{
    const char * estr = NULL;
    char d[128];
    static const int dlen = sizeof(d);

    if (sg_exit2str(exit_status, jsp->verbose, dlen, d)) {
        if (strlen(d) > 0)
            estr = d;
    }
    sgj_js2file_estr(jsp, jop, exit_status, estr, fp);
}

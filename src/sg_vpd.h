#ifndef SG_VPD_H
#define SG_VPD_H

/*
 * Copyright (c) 2022 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdint.h>
#include <stdbool.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "sg_lib.h"
#include "sg_pr2serr.h"

#ifdef __cplusplus
extern "C" {
#endif

/* These two structures are duplicates of those of the same name in
 * sg_vpd_vendor.c . <<< Take care that both are the same. >>> */
struct opts_t {
    bool do_all;
    bool do_enum;
    bool do_force;
    bool do_long;
    bool do_quiet;
    bool page_given;
    bool verbose_given;
    bool version_given;
    int do_hex;
    int do_ident;
    int do_raw;
    int examine;
    int maxlen;
    int vend_prod_num;
    int verbose;
    int vpd_pn;
    const char * device_name;
    const char * page_str;
    const char * inhex_fn;
    const char * vend_prod;
    sgj_state json_st;
};

struct svpd_values_name_t {
    int value;       /* VPD page number */
    int subvalue;    /* to differentiate if value+pdt are not unique */
    int pdt;         /* peripheral device type id, -1 is the default */
                     /* (all or not applicable) value */
    const char * acron;
    const char * name;
};

void svpd_enumerate_vendor(int vend_prod_num);
int svpd_count_vendor_vpds(int vpd_pn, int vend_prod_num);
int svpd_decode_vendor(int sg_fd, struct opts_t * op, int off);
const struct svpd_values_name_t * svpd_find_vendor_by_acron(const char * ap);
int svpd_find_vp_num_by_acron(const char * vp_ap);
const struct svpd_values_name_t * svpd_find_vendor_by_num(int page_num,
                                                          int vend_prod_num);
int vpd_fetch_page(int sg_fd, uint8_t * rp, int page, int mxlen,
                   bool qt, int vb, int * rlenp);
void dup_sanity_chk(int sz_opts_t, int sz_values_name_t);

extern uint8_t * rsp_buff;


#ifdef __cplusplus
}
#endif

#endif  /* end of SG_VPD_H */

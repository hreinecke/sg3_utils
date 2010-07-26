#ifndef SG_LIB_DATA_H
#define SG_LIB_DATA_H

/*
 * Copyright (c) 2007-2010 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

/*
 * This header file contains some structure declarations and array name
 * declarations which are defined in the sg_lib_data.c .
 * Typically this header does not need to be exposed to users of the
 * sg_lib interface declared in sg_libs.h .
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Commands with service actions that change the command name */
#define SG_MAINTENANCE_IN 0xa3
#define SG_MAINTENANCE_OUT 0xa4
#define SG_PERSISTENT_RESERVE_IN 0x5e
#define SG_PERSISTENT_RESERVE_OUT 0x5f
#define SG_SERVICE_ACTION_IN_12 0xab
#define SG_SERVICE_ACTION_OUT_12 0xa9
#define SG_SERVICE_ACTION_IN_16 0x9e
#define SG_SERVICE_ACTION_OUT_16 0x9f
#define SG_VARIABLE_LENGTH_CMD 0x7f



struct sg_lib_value_name_t {
    int value;
    int peri_dev_type; /* 0 -> SPC and/or PDT_DISK, >0 -> PDT */
    const char * name;
};

struct sg_lib_asc_ascq_t {
    unsigned char asc;          /* additional sense code */
    unsigned char ascq;         /* additional sense code qualifier */
    const char * text;
};

struct sg_lib_asc_ascq_range_t {
    unsigned char asc;  /* additional sense code (ASC) */
    unsigned char ascq_min;     /* ASCQ minimum in range */
    unsigned char ascq_max;     /* ASCQ maximum in range */
    const char * text;
};


extern const char * sg_lib_version_str;

extern struct sg_lib_value_name_t sg_lib_normal_opcodes[];
extern struct sg_lib_value_name_t sg_lib_maint_in_arr[];
extern struct sg_lib_value_name_t sg_lib_maint_out_arr[];
extern struct sg_lib_value_name_t sg_lib_pr_in_arr[];
extern struct sg_lib_value_name_t sg_lib_pr_out_arr[];
extern struct sg_lib_value_name_t sg_lib_serv_in12_arr[];
extern struct sg_lib_value_name_t sg_lib_serv_out12_arr[];
extern struct sg_lib_value_name_t sg_lib_serv_in16_arr[];
extern struct sg_lib_value_name_t sg_lib_serv_out16_arr[];
extern struct sg_lib_value_name_t sg_lib_variable_length_arr[];
extern struct sg_lib_asc_ascq_range_t sg_lib_asc_ascq_range[];
extern struct sg_lib_asc_ascq_t sg_lib_asc_ascq[];
extern const char * sg_lib_sense_key_desc[];
extern const char * sg_lib_pdt_strs[];
extern const char * sg_lib_transport_proto_strs[];


#ifdef __cplusplus
}
#endif

#endif

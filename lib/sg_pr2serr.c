/*
 * Copyright (c) 2022 Douglas Gilbert.
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

#include "sg_pr2serr.h"
#include "sg_json_builder.h"

/*
 * #define json_serialize_mode_multiline     0
 * #define json_serialize_mode_single_line   1
 * #define json_serialize_mode_packed        2
 *
 * #define json_serialize_opt_CRLF                    (1 << 1)
 * #define json_serialize_opt_pack_brackets           (1 << 2)
 * #define json_serialize_opt_no_space_after_comma    (1 << 3)
 * #define json_serialize_opt_no_space_after_colon    (1 << 4)
 * #define json_serialize_opt_use_tabs                (1 << 5)
 */


static const json_serialize_opts def_out_settings = {
    json_serialize_mode_multiline,      /* one of serialize_mode_* */
    0,                                  /* serialize_opt_* OR-ed together */
    4                                   /* indent size */
};

/* Users of the sg_pr2serr.h header need this function definition */
int
pr2serr(const char * fmt, ...)
{
    va_list args;
    int n;

    va_start(args, fmt);
    n = vfprintf(stderr, fmt, args);
    va_end(args);
    return n;
}

void
sg_json_init_state(sg_json_state * jstp)
{
    jstp->pr_as_json = true;
    jstp->pr_pretty = true;
    jstp->pr_sorted = false;
    jstp->pr_output = false;
    jstp->pr_implemented = false;
    jstp->pr_unimplemented = false;
    jstp->pr_format = 0;
    jstp->verbose = 0;
    jstp->pr_indent_size = 4;
    jstp->basep = NULL;
    jstp->outputp = NULL;
    jstp->userp = NULL;
}

sg_json_opaque_p
sg_json_start(const char * util_name, const char * ver_str, int argc,
              char *argv[], sg_json_state * jstp)
{
    int k;
    json_value * jvp = json_object_new(0);
    json_value * jv2p;
    json_value * jap = json_array_new(0);

    if ((NULL == jvp) || (NULL == jap)) {
        if (jvp)
            json_builder_free(jvp);
        if (jap)
            json_builder_free(jap);
        return NULL;
    }
    jstp->basep = jvp;
    json_array_push(jap, json_integer_new(1));
    json_array_push(jap, json_integer_new(0));
    json_object_push(jvp, "json_format_version", jap);
    jap = json_array_new(0);
    for (k = 0; k < argc; ++k)
        json_array_push(jap, json_string_new(argv[k]));
    jv2p = json_object_push(jvp, util_name, json_object_new(0));
    if (ver_str)
        json_object_push(jv2p, "version_date", json_string_new(ver_str));
    else
        json_object_push(jv2p, "version_date", json_string_new("0.0"));
    json_object_push(jv2p, "argv", jap);
    if (jstp->pr_output)
        jstp->outputp = json_object_push(jv2p, "output", json_array_new(0));
    return jvp;
}

void
sgj_pr2file(sg_json_opaque_p jop, sg_json_state * jstp, FILE * fp)
{
    size_t len;
    char * b;
    json_value * jvp = (json_value *)jop;
    json_serialize_opts out_settings;

    memcpy(&out_settings, &def_out_settings, sizeof(out_settings));
    if (jstp->pr_indent_size != def_out_settings.indent_size)
        out_settings.indent_size = jstp->pr_indent_size;
    if (! jstp->pr_pretty)
        out_settings.mode = json_serialize_mode_single_line;

    len = json_measure_ex(jvp, out_settings);
    if (len < 1)
        return;
    if (jstp->verbose > 3)
        fprintf(fp, "%s: serialization length: %zu bytes\n", __func__, len);
    b = calloc(len, 1);
    if (NULL == b) {
        if (jstp->verbose > 3)
            pr2serr("%s: unable to get %zu bytes on heap\n", __func__, len);
        return;
    }
    json_serialize_ex(b, jvp, out_settings);
    if (jstp->verbose > 3)
        fprintf(fp, "json serialized:\n");
    fprintf(fp, "%s\n", b);
}

void
sg_json_free(sg_json_opaque_p jop)
{
    json_value * jvp = (json_value *)jop;

    json_builder_free(jvp);
}

void
sgj_pr_hr(sg_json_state * jsp, const char * fmt, ...)
{
    va_list args;

    if (jsp->pr_as_json && jsp->pr_output) {
        size_t len;
        char b[256];

        va_start(args, fmt);
        len = vsnprintf(b, sizeof(b), fmt, args);
        if ((len > 0) && (len < sizeof(b))) {
            const char * cp = b;

            if (b[len - 1] == '\n') {
                b[len - 1] = '\0';
                --len;
            }
            if ((len > 0) && ('\n' == b[0]))
                ++cp;
            json_array_push(jsp->outputp, json_string_new(cp));
        }
        va_end(args);
    } else if (jsp->pr_as_json) {
        va_start(args, fmt);
        va_end(args);
    } else {
        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
    }
}

sg_json_opaque_p
sgj_new_named_object(sg_json_state * jsp, sg_json_opaque_p jop,
		     const char * name)
{
    sg_json_opaque_p resp = NULL;

    if (jsp->pr_as_json)
        resp = json_object_push(jop, name, json_object_new(0));
    return resp;
}

sg_json_opaque_p
sgj_new_named_array(sg_json_state * jsp, sg_json_opaque_p jop,
		    const char * name)
{
    sg_json_opaque_p resp = NULL;

    if (jsp->pr_as_json)
        resp = json_object_push(jop, name, json_array_new(0));
    return resp;
}

sg_json_opaque_p
sgj_add_array_element(sg_json_state * jsp, sg_json_opaque_p jap,
		      sg_json_opaque_p ejop)
{
    if (jsp->pr_as_json)
	return json_array_push(jap, ejop);
    else
	return NULL;
}

/* Newly created object is un-attached */
sg_json_opaque_p
sgj_new_object(sg_json_state * jsp)
{
    return jsp->pr_as_json ? json_object_new(0) : NULL;
}

sg_json_opaque_p
sgj_add_name_vs(sg_json_state * jsp, sg_json_opaque_p jop, const char * name,
		const char * value)
{
    if (jsp->pr_as_json)
	return json_object_push(jop, name, json_string_new(value));
    else
	return NULL;
}

sg_json_opaque_p
sgj_add_name_vi(sg_json_state * jsp, sg_json_opaque_p jop, const char * name,
		int64_t value)
{
    if (jsp->pr_as_json)
	return json_object_push(jop, name, json_integer_new(value));
    else
	return NULL;
}

sg_json_opaque_p
sgj_add_name_vb(sg_json_state * jsp, sg_json_opaque_p jop, const char * name,
		bool value)
{
    if (jsp->pr_as_json)
	return json_object_push(jop, name, json_boolean_new(value));
    else
	return NULL;
}

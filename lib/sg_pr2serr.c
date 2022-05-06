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
#include <ctype.h>

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

/* local copy of snprntf() variant */
static int
scnpr(char * cp, int cp_max_len, const char * fmt, ...)
{
    va_list args;
    int n;

    if (cp_max_len < 2)
        return 0;
    va_start(args, fmt);
    n = vsnprintf(cp, cp_max_len, fmt, args);
    va_end(args);
    return (n < cp_max_len) ? n : (cp_max_len - 1);
}

bool
sgj_init_state(sgj_state * jstp, const char * j_optarg)
{
    bool bad_arg = false;
    bool prev_exclam = false;
    bool negate;
    int k, c;

    jstp->pr_as_json = true;
    jstp->pr_pretty = true;
    jstp->pr_header = true;
    jstp->pr_sorted = false;
    jstp->pr_output = false;
    jstp->pr_implemented = false;
    jstp->pr_unimplemented = false;
    jstp->pr_format = 0;
    jstp->first_bad_char = 0;
    jstp->verbose = 0;
    jstp->pr_indent_size = 4;
    jstp->basep = NULL;
    jstp->outputp = NULL;
    jstp->userp = NULL;

   if (j_optarg) {
        for (k = 0; j_optarg[k]; ++k) {
            c = j_optarg[k];
            negate = false;
            switch (c) {
            case '!':
                negate = true;
                break;
            case '~':
                negate = true;
                break;
            case 'N':
                negate = true;
                break;
            case '0':
            case '2':
                jstp->pr_indent_size = 2;
                break;
            case '3':
                jstp->pr_indent_size = 3;
                break;
            case '4':
                jstp->pr_indent_size = 4;
                break;
            case '8':
                jstp->pr_indent_size = 8;
                break;
            case 'c':
                jstp->pr_pretty = false;
                break;
            case 'g':
                jstp->pr_format = 'g';
                break;
            case 'h':
                jstp->pr_header = ! prev_exclam;
                break;
            case 'i':
                jstp->pr_implemented = true;
                break;
            case 'o':
                jstp->pr_output = true;
                break;
            case 's':
                jstp->pr_sorted = true;
                break;
            case 'u':
                jstp->pr_unimplemented = true;
                break;
            case 'v':
                ++jstp->verbose;
                break;
            case 'y':
                jstp->pr_format = 'g';
                break;
            default:
                bad_arg = true;
                if (0 == jstp->first_bad_char)
                    jstp->first_bad_char = c;
                break;
            }
            prev_exclam = negate ? !prev_exclam : false;
        }
    }
    return ! bad_arg;
}

sgj_opaque_p
sgj_start(const char * util_name, const char * ver_str, int argc,
          char *argv[], sgj_state * jstp)
{
    int k;
    json_value * jvp = json_object_new(0);
    json_value * jv2p = NULL;
    json_value * jap = NULL;


    if (NULL == jvp)
        return NULL;
    if (NULL == jstp)
        return jvp;

    jstp->basep = jvp;
    if (jstp->pr_header) {
        jap = json_array_new(0);
        if  (NULL == jap) {
            json_builder_free(jvp);
            return NULL;
        }
        /* assume rest of json_*_new() calls succeed */
        json_array_push(jap, json_integer_new(1));
        json_array_push(jap, json_integer_new(0));
        json_object_push(jvp, "json_format_version", jap);
        if (util_name) {
            jap = json_array_new(0);
            for (k = 0; k < argc; ++k)
                json_array_push(jap, json_string_new(argv[k]));
            jv2p = json_object_push(jvp, "utility_invoked",
                                    json_object_new(0));
            json_object_push(jv2p, "name", json_string_new(util_name));
            if (ver_str)
                json_object_push(jv2p, "version_date",
                                 json_string_new(ver_str));
            else
                json_object_push(jv2p, "version_date", json_string_new("0.0"));
            json_object_push(jv2p, "argv", jap);
        }
    } else {
        if (jstp->pr_output && util_name)
            jv2p = json_object_push(jvp, "utility_invoked",
                                    json_object_new(0));
    }
    if (jstp->pr_output && jv2p)
        jstp->outputp = json_object_push(jv2p, "output", json_array_new(0));
    return jvp;
}

void
sgj_pr2file(sgj_state * jstp, sgj_opaque_p jop, int exit_status, FILE * fp)
{
    size_t len;
    char * b;
    json_value * jvp = (json_value *)(jop ? jop : jstp->basep);
    json_serialize_opts out_settings;

    if (NULL == jvp) {
        fprintf(fp, "%s: all NULL pointers ??\n", __func__);
        return;
    }
    if ((NULL == jop) && jstp->pr_header)
         json_object_push(jvp, "exit_status", json_integer_new(exit_status));

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
sgj_finish(sgj_state * jsp)
{
    if (jsp && jsp->basep) {
        json_builder_free(jsp->basep);
        jsp->basep = NULL;
        jsp->outputp = NULL;
        jsp->userp = NULL;
    }
}

void
sgj_free_unattached(sgj_opaque_p jop)
{
    if (jop)
        json_builder_free(jop);
}

void
sgj_pr_hr(sgj_state * jsp, const char * fmt, ...)
{
    va_list args;

    if (jsp->pr_as_json && jsp->pr_output) {
        size_t len;
        char b[256];

        va_start(args, fmt);
        len = vsnprintf(b, sizeof(b), fmt, args);
        if ((len > 0) && (len < sizeof(b))) {
            const char * cp = b;

            /* remove up to two trailing linefeeds */
            if (b[len - 1] == '\n') {
                --len;
                if (b[len - 1] == '\n')
                    --len;
                b[len] = '\0';
            }
            /* remove leading linefeed, if present */
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

/* jop will 'own' returned value (if non-NULL) */
sgj_opaque_p
sgj_new_named_object(sgj_state * jsp, sgj_opaque_p jop, const char * name)
{
    sgj_opaque_p resp = NULL;

    if (jsp && jsp->pr_as_json)
        resp = json_object_push((jop ? jop : jsp->basep), name,
                                json_object_new(0));
    return resp;
}

/* jop will 'own' returned value (if non-NULL) */
sgj_opaque_p
sgj_new_named_array(sgj_state * jsp, sgj_opaque_p jop, const char * name)
{
    sgj_opaque_p resp = NULL;

    if (jsp && jsp->pr_as_json)
        resp = json_object_push((jop ? jop : jsp->basep), name,
                                json_array_new(0));
    return resp;
}

/* jap will 'own' ua_jop (if returned value is non-NULL) */
sgj_opaque_p
sgj_add_array_element(sgj_state * jsp, sgj_opaque_p jap, sgj_opaque_p ua_jop)
{
    if (jsp && ua_jop && jsp->pr_as_json)
        return json_array_push(jap, ua_jop);
    else
        return NULL;
}

/* Newly created object is un-attached to jsp->basep tree */
sgj_opaque_p
sgj_new_unattached_object(sgj_state * jsp)
{
    return (jsp && jsp->pr_as_json) ? json_object_new(0) : NULL;
}

/* Newly created array is un-attached to jsp->basep tree */
sgj_opaque_p
sgj_new_unattached_array(sgj_state * jsp)
{
    return (jsp && jsp->pr_as_json) ? json_array_new(0) : NULL;
}

sgj_opaque_p
sgj_add_name_vs(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                const char * value)
{
    if (jsp && jsp->pr_as_json)
        return json_object_push((jop ? jop : jsp->basep), name,
                                json_string_new(value));
    else
        return NULL;
}

sgj_opaque_p
sgj_add_name_vi(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                int64_t value)
{
    if (jsp && jsp->pr_as_json)
        return json_object_push((jop ? jop : jsp->basep), name,
                                json_integer_new(value));
    else
        return NULL;
}

sgj_opaque_p
sgj_add_name_vb(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                bool value)
{
    if (jsp && jsp->pr_as_json)
        return json_object_push((jop ? jop : jsp->basep), name,
                                json_boolean_new(value));
    else
        return NULL;
}

sgj_opaque_p
sgj_add_name_obj(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                 sgj_opaque_p ua_jop)
{
    if (jsp && jsp->pr_as_json && ua_jop)
        return json_object_push((jop ? jop : jsp->basep), name, ua_jop);
    else
        return NULL;
}

void
sgj_add_name_pair_ihex(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                       uint64_t value)
{
    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    else {
        sgj_opaque_p jo2p =
                 sgj_new_named_object(jsp, (jop ? jop : jsp->basep), name);
        char b[64];

        if (NULL == jo2p)
            return;
        sgj_add_name_vi(jsp, jo2p, "i", (int64_t)value);
        snprintf(b, sizeof(b), "%" PRIx64, value);
        sgj_add_name_vs(jsp, jo2p, "hex", b);
    }
}

void
sgj_add_name_pair_istr(sgj_state * jsp, sgj_opaque_p jop,
                       const char * name, int64_t value, const char * str)
{
    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    else {
        sgj_opaque_p jo2p =
                 sgj_new_named_object(jsp, (jop ? jop : jsp->basep), name);
        if (NULL == jo2p)
            return;
        sgj_add_name_vi(jsp, jo2p, "i", (int64_t)value);
        if (str)
        sgj_add_name_vs(jsp, jo2p, "string", str);
    }
}

/* Returns number of characters placed in 'out' excluding trailing NULL */
static int
sgj_jsonify_name(const char * in, char * out, int maxlen_out)
{
    bool prev_underscore = false;
    int c, k, j, inlen;

    if (maxlen_out < 2) {
        if (maxlen_out == 1)
            out[0] = '\0';
        return 0;
    }
    inlen = strlen(in);
    for (k = 0, j = 0; (k < inlen) && (j < maxlen_out); ++k) {
        c = in[k];
        if (isalnum(c)) {
            out[j++] = isupper(c) ? tolower(c) : c;
            prev_underscore = false;
        } else if ((j > 0) && (! prev_underscore)) {
            out[j++] = '_';
            prev_underscore = true;
        }
        /* else we are skipping character 'c' */
    }
    if (j == maxlen_out)
        out[--j] = '\0';
    /* trim of trailing underscores (might have been spaces) */
    for (k = j - 1; k >= 0; --k) {
        if (out[k] != '_')
            break;
    }
    if (k < 0)
        k = 0;
    else
        ++k;
    out[k] = '\0';
    return k;
}

static void
sgj_pr_twin_xx(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
               const char * name, enum sgj_separator_t sep, json_value * jvp)
{
    bool eaten = false;
    bool as_json = (jsp && jsp->pr_as_json);
    int n;
    json_type jtype = jvp ? jvp->type : json_none;
    char b[256];
    char jname[96];
    static const int blen = sizeof(b);

    if (leadin_sp > 128)
        leadin_sp = 128;
    for (n = 0; n < leadin_sp; ++n)
        b[n] = ' ';
    b[n] = '\0';
    if (NULL == name) {
        switch (jtype) {
        case json_string:
            scnpr(b + n, blen - n, "%s", jvp->u.string.ptr);
            break;
        case json_integer:
            scnpr(b + n, blen - n, "%" PRIi64, jvp->u.integer);
            break;
        case json_boolean:
            scnpr(b + n, blen - n, "%s", jvp->u.boolean ? "true" : "false");
            break;
        case json_none:
        default:
            break;
        }
        printf("%s\n", b);
        if (NULL == jop) {
            if (as_json && jsp->pr_output) {
                eaten = true;
                json_array_push(jsp->outputp, jvp ? jvp : json_null_new());
            }
        } else {        /* assume jop points to named array */
            if (as_json) {
                eaten = true;
                json_array_push(jop, jvp ? jvp : json_null_new());
            }
        }
        if (jvp && (! eaten))
            json_builder_free(jvp);
        return;
    }
    n += scnpr(b + n, blen - n, "%s", name);
    if (as_json) {
        int k;

        if (NULL == jop)
            jop = jsp->basep;
        k = sgj_jsonify_name(name, jname, sizeof(jname));
        if (k > 0) {
            eaten = true;
            json_object_push(jop, jname, jvp ? jvp : json_null_new());
        }
    }
    if (jvp && ((as_json && jsp->pr_output) || (! as_json))) {
        switch (sep) {
        case SGJ_SEP_NONE:
            break;
        case SGJ_SEP_SPACE_1:
            n += scnpr(b + n, blen - n, " ");
            break;
        case SGJ_SEP_SPACE_2:
            n += scnpr(b + n, blen - n, "  ");
            break;
        case SGJ_SEP_SPACE_3:
            n += scnpr(b + n, blen - n, "   ");
            break;
        case SGJ_SEP_SPACE_4:
            n += scnpr(b + n, blen - n, "    ");
            break;
        case SGJ_SEP_EQUAL_NO_SPACE:
            n += scnpr(b + n, blen - n, "=");
            break;
        case SGJ_SEP_EQUAL_1_SPACE:
            n += scnpr(b + n, blen - n, "= ");
            break;
        case SGJ_SEP_COLON_NO_SPACE:
            n += scnpr(b + n, blen - n, ":");
            break;
        case SGJ_SEP_COLON_1_SPACE:
            n += scnpr(b + n, blen - n, ": ");
            break;
        default:
            break;
        }
        switch (jtype) {
        case json_string:
            n += scnpr(b + n, blen - n, "%s", jvp->u.string.ptr);
            break;
        case json_integer:
            n += scnpr(b + n, blen - n, "%" PRIi64, jvp->u.integer);
            break;
        case json_boolean:
            n += scnpr(b + n, blen - n, "%s",
                       jvp->u.boolean ? "true" : "false");
            break;
        case json_none:
        default:
            break;
        }
    }
    if (as_json && jsp->pr_output)
        json_array_push(jsp->outputp, json_string_new(b));
    else if (! as_json)
        printf("%s\n", b);
    if (jvp && (! eaten))
        json_builder_free(jvp);
}

void
sgj_pr_twin_vs(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
               const char * name, enum sgj_separator_t sep,
               const char * value)
{
    json_value * jvp;

    /* make json_value even if jsp->pr_as_json is false */
    jvp = value ? json_string_new(value) : NULL;
    sgj_pr_twin_xx(jsp, jop, leadin_sp, name, sep, jvp);
}

void
sgj_pr_twin_vi(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
               const char * name, enum sgj_separator_t sep, int64_t value)
{
    json_value * jvp;

    jvp = json_integer_new(value);
    sgj_pr_twin_xx(jsp, jop, leadin_sp, name, sep, jvp);
}

void
sgj_pr_twin_vb(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
               const char * name, enum sgj_separator_t sep, bool value)
{
    json_value * jvp;

    jvp = json_boolean_new(value);
    sgj_pr_twin_xx(jsp, jop, leadin_sp, name, sep, jvp);
}

#if 0
void
sgj_pr_hr_line_vs(sgj_state * jsp, sgj_opaque_p jop, const char * hr_line,
                  const char * name, const char * value)
{
}
#endif

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

/* Comment out next line to remove dependency on sg_lib.h */
#define SG_PRSE_SENSE_DECODE 1

#ifdef SG_PRSE_SENSE_DECODE
#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_unaligned.h"
#endif


#define sgj_opts_ev "SG3_UTILS_JSON_OPTS"

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

static bool
sgj_parse_opts(sgj_state * jsp, const char * j_optarg)
{
    bool bad_arg = false;
    bool prev_negate = false;
    bool negate;
    int k, c;

    for (k = 0; j_optarg[k]; ++k) {     /* step over leading whitespace */
        if (! isspace(j_optarg[k]))
            break;
    }
    for ( ; j_optarg[k]; ++k) {
        c = j_optarg[k];
        negate = false;
        switch (c) {
        case '=':
            if (0 == k)
                break;  /* allow and ignore leading '=' */
            bad_arg = true;
            if (0 == jsp->first_bad_char)
                jsp->first_bad_char = c;
            break;
        case '!':
        case '~':
        case '-':       /* '-' is probably most practical negation symbol */
            negate = true;
            break;
        case '0':
        case '2':
            jsp->pr_indent_size = 2;
            break;
        case '3':
            jsp->pr_indent_size = 3;
            break;
        case '4':
            jsp->pr_indent_size = 4;
            break;
        case '8':
            jsp->pr_indent_size = 8;
            break;
        case 'a':       /* abbreviated name expansion */
            jsp->pr_ane = ! prev_negate;
            break;
        case 'e':
            jsp->pr_exit_status = ! prev_negate;
            break;
        case 'g':
            jsp->pr_format = 'g';
            break;
        case 'h':
            jsp->pr_hex = ! prev_negate;
            break;
        case 'l':
            jsp->pr_leadin = ! prev_negate;
            break;
        case 'o':
            jsp->pr_output = ! prev_negate;
            break;
        case 'p':
            jsp->pr_pretty = ! prev_negate;
            break;
        case 's':
            jsp->pr_string = ! prev_negate;
            break;
        case 'v':
            ++jsp->verbose;
            break;
        case 'y':
            jsp->pr_format = 'g';
            break;
        default:
            bad_arg = true;
            if (0 == jsp->first_bad_char)
                jsp->first_bad_char = c;
            break;
        }
        prev_negate = negate ? ! prev_negate : false;
    }
    return ! bad_arg;
}

static void
sgj_def_opts(sgj_state * jsp)
{
    jsp->pr_as_json = true;
    jsp->pr_ane = false;
    jsp->pr_exit_status = true;
    jsp->pr_hex = false;
    jsp->pr_leadin = true;
    jsp->pr_output = false;
    jsp->pr_pretty = true;
    jsp->pr_string = true;
    jsp->pr_format = 0;
    jsp->first_bad_char = 0;
    jsp->verbose = 0;
    jsp->pr_indent_size = 4;
}

bool
sgj_init_state(sgj_state * jsp, const char * j_optarg)
{
    const char * cp;

    sgj_def_opts(jsp);
    jsp->basep = NULL;
    jsp->outputp = NULL;
    jsp->userp = NULL;

    cp = getenv(sgj_opts_ev);
    if (cp) {
        if (! sgj_parse_opts(jsp, cp)) {
            pr2ws("error parsing %s environment variable, ignore\n",
                  sgj_opts_ev);
            sgj_def_opts(jsp);
        }
    }
    return j_optarg ? sgj_parse_opts(jsp, j_optarg) : true;
}

sgj_opaque_p
sgj_start(const char * util_name, const char * ver_str, int argc,
          char *argv[], sgj_state * jsp)
{
    int k;
    json_value * jvp = json_object_new(0);
    json_value * jv2p = NULL;
    json_value * jap = NULL;


    if (NULL == jvp)
        return NULL;
    if (NULL == jsp)
        return jvp;

    jsp->basep = jvp;
    if (jsp->pr_leadin) {
        jap = json_array_new(0);
        if  (NULL == jap) {
            json_builder_free((json_value *)jvp);
            return NULL;
        }
        /* assume rest of json_*_new() calls succeed */
        json_array_push((json_value *)jap, json_integer_new(1));
        json_array_push((json_value *)jap, json_integer_new(0));
        json_object_push((json_value *)jvp, "json_format_version",
                         (json_value *)jap);
        if (util_name) {
            jap = json_array_new(0);
            for (k = 0; k < argc; ++k)
                json_array_push((json_value *)jap, json_string_new(argv[k]));
            jv2p = json_object_push((json_value *)jvp, "utility_invoked",
                                    json_object_new(0));
            json_object_push((json_value *)jv2p, "name",
                             json_string_new(util_name));
            if (ver_str)
                json_object_push((json_value *)jv2p, "version_date",
                                 json_string_new(ver_str));
            else
                json_object_push((json_value *)jv2p, "version_date",
                                 json_string_new("0.0"));
            json_object_push((json_value *)jv2p, "argv", jap);
        }
    } else {
        if (jsp->pr_output && util_name)
            jv2p = json_object_push((json_value *)jvp, "utility_invoked",
                                    json_object_new(0));
    }
    if (jsp->pr_output && jv2p)
        jsp->outputp = json_object_push((json_value *)jv2p, "output",
                                        json_array_new(0));
    return jvp;
}

void
sgj_pr2file(sgj_state * jsp, sgj_opaque_p jop, int exit_status, FILE * fp)
{
    size_t len;
    char * b;
    json_value * jvp = (json_value *)(jop ? jop : jsp->basep);
    json_serialize_opts out_settings;

    if (NULL == jvp) {
        fprintf(fp, "%s: all NULL pointers ??\n", __func__);
        return;
    }
    if ((NULL == jop) && jsp->pr_exit_status)
         json_object_push(jvp, "exit_status", json_integer_new(exit_status));

    memcpy(&out_settings, &def_out_settings, sizeof(out_settings));
    if (jsp->pr_indent_size != def_out_settings.indent_size)
        out_settings.indent_size = jsp->pr_indent_size;
    if (! jsp->pr_pretty)
        out_settings.mode = json_serialize_mode_single_line;

    len = json_measure_ex(jvp, out_settings);
    if (len < 1)
        return;
    if (jsp->verbose > 3)
        fprintf(fp, "%s: serialization length: %zu bytes\n", __func__, len);
    b = (char *)calloc(len, 1);
    if (NULL == b) {
        if (jsp->verbose > 3)
            pr2serr("%s: unable to get %zu bytes on heap\n", __func__, len);
        return;
    }
    json_serialize_ex(b, jvp, out_settings);
    if (jsp->verbose > 3)
        fprintf(fp, "json serialized:\n");
    fprintf(fp, "%s\n", b);
}

void
sgj_finish(sgj_state * jsp)
{
    if (jsp && jsp->basep) {
        json_builder_free((json_value *)jsp->basep);
        jsp->basep = NULL;
        jsp->outputp = NULL;
        jsp->userp = NULL;
    }
}

void
sgj_free_unattached(sgj_opaque_p jop)
{
    if (jop)
        json_builder_free((json_value *)jop);
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
            json_array_push((json_value *)jsp->outputp, json_string_new(cp));
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

    if (jsp && jsp->pr_as_json && name)
        resp = json_object_push((json_value *)(jop ? jop : jsp->basep), name,
                                json_object_new(0));
    return resp;
}

/* jop will 'own' returned value (if non-NULL) */
sgj_opaque_p
sgj_new_named_array(sgj_state * jsp, sgj_opaque_p jop, const char * name)
{
    sgj_opaque_p resp = NULL;

    if (jsp && jsp->pr_as_json && name)
        resp = json_object_push((json_value *)(jop ? jop : jsp->basep), name,
                                json_array_new(0));
    return resp;
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
sgj_add_nv_s(sgj_state * jsp, sgj_opaque_p jop, const char * name,
             const char * value)
{
    if (jsp && jsp->pr_as_json && value) {
        if (name)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    name, json_string_new(value));
        else
            return json_array_push((json_value *)(jop ? jop : jsp->basep),
                                   json_string_new(value));
    } else
        return NULL;
}

sgj_opaque_p
sgj_add_nv_i(sgj_state * jsp, sgj_opaque_p jop, const char * name,
             int64_t value)
{
    if (jsp && jsp->pr_as_json) {
        if (name)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    name, json_integer_new(value));
        else
            return json_array_push((json_value *)(jop ? jop : jsp->basep),
                                   json_integer_new(value));
    }
    else
        return NULL;
}

sgj_opaque_p
sgj_add_nv_b(sgj_state * jsp, sgj_opaque_p jop, const char * name, bool value)
{
    if (jsp && jsp->pr_as_json) {
        if (name)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    name, json_boolean_new(value));
        else
            return json_array_push((json_value *)(jop ? jop : jsp->basep),
                                   json_boolean_new(value));
    } else
        return NULL;
}

/* jop will 'own' ua_jop (if returned value is non-NULL) */
sgj_opaque_p
sgj_add_nv_o(sgj_state * jsp, sgj_opaque_p jop, const char * name,
             sgj_opaque_p ua_jop)
{
    if (jsp && jsp->pr_as_json && ua_jop) {
        if (name)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    name, (json_value *)ua_jop);
        else
            return json_array_push((json_value *)(jop ? jop : jsp->basep),
                                   (json_value *)ua_jop);
    } else
        return NULL;
}

void
sgj_add_nv_ihex(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                uint64_t value)
{
    if ((NULL == jsp) || (NULL == name) || (! jsp->pr_as_json))
        return;
    else if (jsp->pr_hex)  {
        sgj_opaque_p jo2p =
                 sgj_new_named_object(jsp, jop, name);
        char b[64];

        if (NULL == jo2p)
            return;
        sgj_add_nv_i(jsp, jo2p, "i", (int64_t)value);
        snprintf(b, sizeof(b), "%" PRIx64, value);
        sgj_add_nv_s(jsp, jo2p, "hex", b);
    } else
        sgj_add_nv_i(jsp, jop, name, (int64_t)value);
}

static const char * sc_mn_s = "meaning";

void
sgj_add_nv_istr(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                int64_t val_i, const char * str_name, const char * val_s)
{
    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    else if (jsp->pr_string) {
        sgj_opaque_p jo2p =
                 sgj_new_named_object(jsp, jop, name);
        if (NULL == jo2p)
            return;
        sgj_add_nv_i(jsp, jo2p, "i", (int64_t)val_i);
        if (val_s)
            sgj_add_nv_s(jsp, jo2p, str_name ? str_name : sc_mn_s, val_s);
    } else
        sgj_add_nv_i(jsp, jop, name, val_i);
}

void
sgj_add_nv_ihexstr(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                   int64_t val_i, const char * str_name, const char * val_s)
{
    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    if ((! jsp->pr_hex) && (! jsp->pr_string))
        sgj_add_nv_i(jsp, jop, name, val_i);
    else {
        char b[64];
        sgj_opaque_p jo2p =
                 sgj_new_named_object(jsp, jop, name);

        if (NULL == jo2p)
            return;
        if (jsp->pr_string) {
            sgj_add_nv_i(jsp, jo2p, "i", (int64_t)val_i);
            if (jsp->pr_hex) {
                snprintf(b, sizeof(b), "%" PRIx64, val_i);
                sgj_add_nv_s(jsp, jo2p, "hex", b);
            }
            if (val_s)
                sgj_add_nv_s(jsp, jo2p, str_name ? str_name : sc_mn_s, val_s);
        } else if (jsp->pr_hex) {
            sgj_add_nv_i(jsp, jo2p, "i", (int64_t)val_i);
            snprintf(b, sizeof(b), "%" PRIx64, val_i);
            sgj_add_nv_s(jsp, jo2p, "hex", b);
        }
    }
}

static const char * sc_ane_s = "abbreviated_name_expansion";

void
sgj_add_nv_ihex_ane(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                    int64_t val_i, bool want_hex, const char * ane_s)
{
    bool as_hex = jsp->pr_hex && want_hex;
    bool as_ane = jsp->pr_ane && ane_s;

    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    if (! (as_hex || as_ane))
        sgj_add_nv_i(jsp, jop, name, val_i);
    else {
        char b[64];
        sgj_opaque_p jo2p =
                 sgj_new_named_object(jsp, jop, name);

        if (NULL == jo2p)
            return;
        sgj_add_nv_i(jsp, jo2p, "i", (int64_t)val_i);
        if (as_ane) {
            if (jsp->pr_hex && want_hex) {
                snprintf(b, sizeof(b), "%" PRIx64, val_i);
                sgj_add_nv_s(jsp, jo2p, "hex", b);
            }
            sgj_add_nv_s(jsp, jo2p, sc_ane_s, ane_s);
        } else if (as_hex) {
            snprintf(b, sizeof(b), "%" PRIx64, val_i);
            sgj_add_nv_s(jsp, jo2p, "hex", b);
        }
    }
}

void
sgj_add_nv_hex_bytes(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                     const uint8_t * byte_arr, int num_bytes)
{
    int blen = num_bytes * 4;
    char * bp;

    if ((NULL == jsp) || (! jsp->pr_as_json) || (! jsp->pr_hex))
        return;
    bp = (char *)calloc(blen + 4, 1);
    if (bp) {
        hex2str(byte_arr, num_bytes, NULL, 2, blen, bp);
        sgj_add_nv_s(jsp, jop, name, bp);
        free(bp);
    }
}

void
sgj_add_nv_ihexstr_ane(sgj_state * jsp, sgj_opaque_p jop, const char * name,
                       int64_t val_i, bool want_hex, const char * str_name,
                       const char * val_s, const char * ane_s)
{
    bool as_hex = jsp->pr_hex && want_hex;
    bool as_str = jsp->pr_string && val_s;
    bool as_ane = jsp->pr_ane && ane_s;
    const char * sname =  str_name ? str_name : sc_mn_s;

    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    if (! (as_hex || as_ane || as_str))
        sgj_add_nv_i(jsp, jop, name, val_i);
    else {
        char b[64];
        sgj_opaque_p jo2p =
                 sgj_new_named_object(jsp, jop, name);

        if (NULL == jo2p)
            return;
        sgj_add_nv_i(jsp, jo2p, "i", (int64_t)val_i);
        if (as_ane) {
            if (as_hex) {
                snprintf(b, sizeof(b), "%" PRIx64, val_i);
                sgj_add_nv_s(jsp, jo2p, "hex", b);
            }
            if (as_str) {
                sgj_add_nv_s(jsp, jo2p, sname, val_s);
            }
            sgj_add_nv_s(jsp, jo2p, sc_ane_s, ane_s);
        } else if (as_hex) {
            snprintf(b, sizeof(b), "%" PRIx64, val_i);
            sgj_add_nv_s(jsp, jo2p, "hex", b);
            if (as_str)
                sgj_add_nv_s(jsp, jo2p, sname, val_s);
        } else if (as_str)
            sgj_add_nv_s(jsp, jo2p, sname, val_s);
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
sgj_pr_hr_js_xx(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
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
        if ((! as_json) || (jsp && jsp->pr_output)) {
            switch (jtype) {
            case json_string:
                scnpr(b + n, blen - n, "%s", jvp->u.string.ptr);
                break;
            case json_integer:
                scnpr(b + n, blen - n, "%" PRIi64, jvp->u.integer);
                break;
            case json_boolean:
                scnpr(b + n, blen - n, "%s",
                      jvp->u.boolean ? "true" : "false");
                break;
            case json_none:
            default:
                break;
            }
            printf("%s\n", b);
        }
        if (NULL == jop) {
            if (as_json && jsp->pr_output) {
                eaten = true;
                json_array_push((json_value *)jsp->outputp,
                                jvp ? jvp : json_null_new());
            }
        } else {        /* assume jop points to named array */
            if (as_json) {
                eaten = true;
                json_array_push((json_value *)jop,
                                jvp ? jvp : json_null_new());
            }
        }
        if (jvp && (! eaten))
            json_builder_free((json_value *)jvp);
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
            json_object_push((json_value *)jop, jname,
                             jvp ? jvp : json_null_new());
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
    }
    if (as_json && jsp->pr_output)
        json_array_push((json_value *)jsp->outputp, json_string_new(b));
    else if (! as_json)
        printf("%s\n", b);
    if (jvp && (! eaten))
        json_builder_free((json_value *)jvp);
}

void
sgj_pr_hr_js_vs(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                const char * name, enum sgj_separator_t sep,
                const char * value)
{
    json_value * jvp;

    /* make json_value even if jsp->pr_as_json is false */
    jvp = value ? json_string_new(value) : NULL;
    sgj_pr_hr_js_xx(jsp, jop, leadin_sp, name, sep, jvp);
}

void
sgj_pr_hr_js_vi(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                const char * name, enum sgj_separator_t sep, int64_t value)
{
    json_value * jvp;

    jvp = json_integer_new(value);
    sgj_pr_hr_js_xx(jsp, jop, leadin_sp, name, sep, jvp);
}

void
sgj_pr_hr_js_vb(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                const char * name, enum sgj_separator_t sep, bool value)
{
    json_value * jvp;

    jvp = json_boolean_new(value);
    sgj_pr_hr_js_xx(jsp, jop, leadin_sp, name, sep, jvp);
}

#ifdef SG_PRSE_SENSE_DECODE

static const char * dtsp = "descriptor too short";
static const char * sksvp = "sense-key specific valid";
static const char * ddep = "designation_descriptor_error";
static const char * naa_exp = "Network Address Authority";
static const char * aoi_exp = "IEEE-Administered Organizational Identifier";

bool
sgj_get_designation_descriptor(sgj_state * jsp, sgj_opaque_p jop,
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
    static const int blen = sizeof(b);
    static const int elen = sizeof(e);

    if (dd_len < 4) {
        sgj_add_nv_s(jsp, jop, ddep, "too short");
        return false;
    }
    dlen = ddp[3];
    if (dlen > (dd_len - 4)) {
        snprintf(e, elen, "too long: says it is %d bytes, but given %d "
                 "bytes\n", dlen, dd_len - 4);
        sgj_add_nv_s(jsp, jop, ddep, e);
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
    sgj_add_nv_ihexstr(jsp, jop, "association", assoc, NULL, cp);
    cp = sg_get_desig_type_str(desig_type);
    if (NULL == cp)
        cp = "unknown";
    sgj_add_nv_ihexstr(jsp, jop, "designator_type", desig_type,
                       NULL, cp);
    cp = sg_get_desig_code_set_str(c_set);
    if (NULL == cp)
        cp = "unknown";
    sgj_add_nv_ihexstr(jsp, jop, "code_set", desig_type,
                       NULL, cp);
    sgj_add_nv_ihex_ane(jsp, jop, "piv", piv, false,
                        "Protocol Identifier Valid");
    sg_get_trans_proto_str(p_id, elen, e);
    sgj_add_nv_ihexstr(jsp, jop, "protocol_identifier", p_id, NULL, e);
    switch (desig_type) {
    case 0: /* vendor specific */
        sgj_add_nv_hex_bytes(jsp, jop, "vendor_specific_hex", ip, dlen);
        break;
    case 1: /* T10 vendor identification */
        n = (dlen < 8) ? dlen : 8;
        snprintf(b, blen, "%.*s", n, ip);
        sgj_add_nv_s(jsp, jop, "t10_vendor_identification", b);
        b[0] = '\0';
        if (dlen > 8)
            snprintf(b, blen, "%.*s", dlen - 8, ip + 8);
        sgj_add_nv_s(jsp, jop, "vendor_specific_identifier", b);
        break;
    case 2: /* EUI-64 based */
        sgj_add_nv_i(jsp, jop, "eui_64_based_designator_length", dlen);
        ull = sg_get_unaligned_be64(ip);
        switch (dlen) {
        case 8:
            sgj_add_nv_ihex(jsp, jop, "ieee_identifier", ull);
            break;
        case 12:
            sgj_add_nv_ihex(jsp, jop, "ieee_identifier", ull);
            sgj_add_nv_ihex(jsp, jop, "directory_id",
                            sg_get_unaligned_be32(ip + 8));
            break;
        case 16:
            sgj_add_nv_ihex(jsp, jop, "identifier_extension", ull);
            sgj_add_nv_ihex(jsp, jop, "ieee_identifier",
                            sg_get_unaligned_be64(ip + 8));
            break;
        default:
            sgj_add_nv_s(jsp, jop, "eui_64", "decoding falied");
            break;
        }
        break;
    case 3: /* NAA <n> */
        sgj_add_nv_hex_bytes(jsp, jop, "full_naa_in_hex", ip, dlen);
        naa = (ip[0] >> 4) & 0xff;
        switch (naa) {
        case 2:
            naa_sp = "IEEE Extended";
            sgj_add_nv_ihexstr_ane(jsp, jop, "naa", naa, false, NULL, naa_sp,
                                   naa_exp);
            d_id = (((ip[0] & 0xf) << 8) | ip[1]);
            sgj_add_nv_ihex(jsp, jop, "vendor_specific_identifier_a", d_id);
            aoi = sg_get_unaligned_be24(ip + 2);
            sgj_add_nv_ihex_ane(jsp, jop, "aoi", aoi, true, aoi_exp);
            vsi = sg_get_unaligned_be24(ip + 5);
            sgj_add_nv_ihex(jsp, jop, "vendor_specific_identifier_b", vsi);
            break;
        case 3:
            naa_sp = "Locally Assigned";
            sgj_add_nv_ihexstr_ane(jsp, jop, "naa", naa, false, NULL, naa_sp,
                                   naa_exp);
            ull = sg_get_unaligned_be64(ip + 0) & 0xfffffffffffffffULL;
            sgj_add_nv_ihex(jsp, jop, "locally_administered_value", ull);
            break;
        case 5:
            naa_sp = "IEEE Registered";
            sgj_add_nv_ihexstr_ane(jsp, jop, "naa", naa, false, NULL, naa_sp,
                                   naa_exp);
            aoi = (sg_get_unaligned_be32(ip + 0) >> 4) & 0xffffff;
            sgj_add_nv_ihex_ane(jsp, jop, "aoi", aoi, true, aoi_exp);
            ull = sg_get_unaligned_be48(ip + 2) & 0xfffffffffULL;
            sgj_add_nv_ihex(jsp, jop, "vendor_specific_identifier", ull);
            break;
        case 6:
            naa_sp = "IEEE Registered Extended";
            sgj_add_nv_ihexstr_ane(jsp, jop, "naa", naa, false, NULL, naa_sp,
                                   naa_exp);
            aoi = (sg_get_unaligned_be32(ip + 0) >> 4) & 0xffffff;
            sgj_add_nv_ihex_ane(jsp, jop, "aoi", aoi, true, aoi_exp);
            ull = sg_get_unaligned_be48(ip + 2) & 0xfffffffffULL;
            sgj_add_nv_ihex(jsp, jop, "vendor_specific_identifier", ull);
            ull = sg_get_unaligned_be64(ip + 8);
            sgj_add_nv_ihex(jsp, jop, "vendor_specific_identifier_extension",
                            ull);
            break;
        default:
            snprintf(b, blen, "unknown NAA value=0x%x", naa);
            sgj_add_nv_ihexstr_ane(jsp, jop, "naa", naa, true, NULL, b,
                                   naa_exp);
            break;
        }
        break;
#if 0
    case 4: /* Relative target port */
        if ((1 != c_set) || (1 != assoc) || (4 != dlen)) {
            n += sg_scnpr(b + n, blen - n, "%s      << expected binary "
                          "code_set, target port association, length 4 >>\n",
                          lip);
            n += hex2str(ip, dlen, "", 1, blen - n, b + n);
            break;
        }
        d_id = sg_get_unaligned_be16(ip + 2);
        n += sg_scnpr(b + n, blen - n, "%s      Relative target port: 0x%x\n",
                      lip, d_id);
        break;
    case 5: /* (primary) Target port group */
        if ((1 != c_set) || (1 != assoc) || (4 != dlen)) {
            n += sg_scnpr(b + n, blen - n, "%s      << expected binary "
                          "code_set, target port association, length 4 >>\n",
                          lip);
            n += hex2str(ip, dlen, lip, 1, blen - n, b + n);
            break;
        }
        d_id = sg_get_unaligned_be16(ip + 2);
        n += sg_scnpr(b + n, blen - n, "%s      Target port group: 0x%x\n",
                      lip, d_id);
        break;
    case 6: /* Logical unit group */
        if ((1 != c_set) || (0 != assoc) || (4 != dlen)) {
            n += sg_scnpr(b + n, blen - n, "%s      << expected binary "
                          "code_set, logical unit association, length 4 >>\n",
                          lip);
            n += hex2str(ip, dlen, lip, 1, blen - n, b + n);
            break;
        }
        d_id = sg_get_unaligned_be16(ip + 2);
        n += sg_scnpr(b + n, blen - n, "%s      Logical unit group: 0x%x\n",
                      lip, d_id);
        break;
    case 7: /* MD5 logical unit identifier */
        if ((1 != c_set) || (0 != assoc)) {
            n += sg_scnpr(b + n, blen - n, "%s      << expected binary "
                          "code_set, logical unit association >>\n", lip);
            n += hex2str(ip, dlen, "", 1, blen - n, b + n);
            break;
        }
        n += sg_scnpr(b + n, blen - n, "%s      MD5 logical unit "
                      "identifier:\n", lip);
        n += hex2str(ip, dlen, lip, 1, blen - n, b + n);
        break;
    case 8: /* SCSI name string */
        if (3 != c_set) {       /* accept ASCII as subset of UTF-8 */
            if (2 == c_set) {
                if (do_long)
                    n += sg_scnpr(b + n, blen - n, "%s      << expected "
                                  "UTF-8, use ASCII >>\n", lip);
            } else {
                n += sg_scnpr(b + n, blen - n, "%s      << expected UTF-8 "
                              "code_set >>\n", lip);
                n += hex2str(ip, dlen, lip, 0, blen - n, b + n);
                break;
            }
        }
        n += sg_scnpr(b + n, blen - n, "%s      SCSI name string:\n", lip);
        /* does %s print out UTF-8 ok??
         * Seems to depend on the locale. Looks ok here with my
         * locale setting: en_AU.UTF-8
         */
        n += sg_scnpr(b + n, blen - n, "%s      %.*s\n", lip, dlen,
                      (const char *)ip);
        break;
    case 9: /* Protocol specific port identifier */
        /* added in spc4r36, PIV must be set, proto_id indicates */
        /* whether UAS (USB) or SOP (PCIe) or ... */
        if (! piv)
            n += sg_scnpr(b + n, blen - n, " %s      >>>> Protocol specific "
                          "port identifier expects protocol\n%s          "
                          "identifier to be valid and it is not\n", lip, lip);
        if (TPROTO_UAS == p_id) {
            n += sg_scnpr(b + n, blen - n, "%s      USB device address: "
                          "0x%x\n", lip, 0x7f & ip[0]);
            n += sg_scnpr(b + n, blen - n, "%s      USB interface number: "
                          "0x%x\n", lip, ip[2]);
        } else if (TPROTO_SOP == p_id) {
            n += sg_scnpr(b + n, blen - n, "%s      PCIe routing ID, bus "
                          "number: 0x%x\n", lip, ip[0]);
            n += sg_scnpr(b + n, blen - n, "%s          function number: "
                          "0x%x\n", lip, ip[1]);
            n += sg_scnpr(b + n, blen - n, "%s          [or device number: "
                          "0x%x, function number: 0x%x]\n", lip,
                          (0x1f & (ip[1] >> 3)), 0x7 & ip[1]);
        } else
            n += sg_scnpr(b + n, blen - n, "%s      >>>> unexpected protocol "
                          "identifier: %s\n%s           with Protocol "
                          "specific port identifier\n", lip,
                          sg_get_trans_proto_str(p_id, elen, e), lip);
        break;
    case 0xa: /* UUID identifier */
        n += sg_t10_uuid_desig2str(ip, dlen, c_set, do_long, false, lip,
                                   blen - n, b + n);
        break;
#endif
    default: /* reserved */
        hex2str(ip, dlen, NULL, 1, blen, b);
        sgj_add_nv_s(jsp, jop, "reserved_designator_hex", b);
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
        jo2p = sgj_new_named_object(jsp, jop, "another_progress_indication");
    else
        jo2p = sgj_new_named_object(jsp, jop, "progress_indication");
    if (NULL == jo2p)
        return;
    progress = prog_indic;
    sgj_add_nv_i(jsp, jo2p, "i", progress);
    snprintf(b, sizeof(b), "%x", progress);
    sgj_add_nv_s(jsp, jo2p, "hex", b);
    progress *= 100;
    pr = progress / 65536;
    rem = (progress % 65536) / 656;
    snprintf(b, sizeof(b), "%d.02%d%%\n", pr, rem);
    sgj_add_nv_s(jsp, jo2p, "percentage", b);
}

static bool
sgj_decode_sks(sgj_state * jsp, sgj_opaque_p jop, const uint8_t * dp, int dlen,
               int sense_key)
{
    switch (sense_key) {
    case SPC_SK_ILLEGAL_REQUEST:
        if (dlen < 3) {
            sgj_add_nv_s(jsp, jop, "illegal_request_sks", dtsp);
            return false;
        }
        sgj_add_nv_ihex_ane(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                            sksvp);
        sgj_add_nv_ihex_ane(jsp, jop, "c_d", !! (dp[0] & 0x40), false,
                            "c: cdb; d: data-out");
        sgj_add_nv_ihex_ane(jsp, jop, "bpv", !! (dp[0] & 0x8), false,
                            "bit pointer (index) valid");
        sgj_add_nv_i(jsp, jop, "bit_pointer", dp[0] & 0x7);
        sgj_add_nv_ihex(jsp, jop, "field_pointer",
                        sg_get_unaligned_be16(dp + 1));
        break;
    case SPC_SK_HARDWARE_ERROR:
    case SPC_SK_MEDIUM_ERROR:
    case SPC_SK_RECOVERED_ERROR:
        if (dlen < 3) {
            sgj_add_nv_s(jsp, jop, "actual_retry_count_sks", dtsp);
            return false;
        }
        sgj_add_nv_ihex_ane(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                            sksvp);
        sgj_add_nv_ihex(jsp, jop, "actual_retry_count",
                        sg_get_unaligned_be16(dp + 1));
        break;
    case SPC_SK_NO_SENSE:
    case SPC_SK_NOT_READY:
        if (dlen < 7) {
            sgj_add_nv_s(jsp, jop, "progress_indication_sks", dtsp);
            return false;
        }
        sgj_add_nv_ihex_ane(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                            sksvp);
        sgj_progress_indication(jsp, jop, sg_get_unaligned_be16(dp + 1),
                                false);
        break;
    case SPC_SK_COPY_ABORTED:
        if (dlen < 7) {
            sgj_add_nv_s(jsp, jop, "segment_indication_sks", dtsp);
            return false;
        }
        sgj_add_nv_ihex_ane(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                            sksvp);
        sgj_add_nv_ihex_ane(jsp, jop, "sd", !! (dp[0] & 0x20), false,
                            "field pointer relative to: 1->segment "
                            "descriptor, 0->parameter list");
        sgj_add_nv_ihex_ane(jsp, jop, "bpv", !! (dp[0] & 0x8), false,
                            "bit pointer (index) valid");
        sgj_add_nv_i(jsp, jop, "bit_pointer", dp[0] & 0x7);
        sgj_add_nv_ihex(jsp, jop, "field_pointer",
                        sg_get_unaligned_be16(dp + 1));
        break;
    case SPC_SK_UNIT_ATTENTION:
        if (dlen < 7) {
            sgj_add_nv_s(jsp, jop, "segment_indication_sks", dtsp);
            return false;
        }
        sgj_add_nv_ihex_ane(jsp, jop, "sksv", !! (dp[0] & 0x80), false,
                            sksvp);
        sgj_add_nv_i(jsp, jop, "overflow", !! (dp[0] & 0x80));
        break;
    default:
        sgj_add_nv_ihex(jsp, jop, "unexpected_sense_key", sense_key);
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

    sgj_add_nv_ihex_ane(jsp, jop, "not_all_r", (dp[2] & 0x1), false,
                        "Not all referrals");
    dp += 4;
    jap = sgj_new_named_array(jsp, jop,
                              "user_data_segment_referral_descriptor");
    for (k = 0, f = 1; (k + 4) < dlen; k += g, dp += g, ++f) {
        int ntpgd = dp[3];

        jo2p = sgj_new_unattached_object(jsp);
        g = (ntpgd * 4) + 20;
        sgj_add_nv_ihex(jsp, jo2p, "number_of_target_port_group_descriptors",
                        ntpgd);
        if ((k + g) > dlen) {
            sgj_add_nv_i(jsp, jo2p, "truncated_descriptor_dlen", dlen);
            sgj_add_nv_o(jsp, jap, NULL /* name */, jo2p);
            return false;
        }
        ull = sg_get_unaligned_be64(dp + 4);
        sgj_add_nv_ihex(jsp, jo2p, "first_user_date_sgment_lba", ull);
        ull = sg_get_unaligned_be64(dp + 12);
        sgj_add_nv_ihex(jsp, jo2p, "last_user_date_sgment_lba", ull);
        ja2p = sgj_new_named_array(jsp, jo2p, "target_port_group_descriptor");
        for (j = 0; j < ntpgd; ++j) {
            jo3p = sgj_new_unattached_object(jsp);
            tp = dp + 20 + (j * 4);
            aas = tp[0] & 0xf;
            decode_tpgs_state(aas, c, sizeof(c));
            sgj_add_nv_ihexstr(jsp, jo3p, "asymmetric_access_state", aas,
                               NULL, c);
            sgj_add_nv_ihex(jsp, jo3p, "target_port_group",
                            sg_get_unaligned_be16(tp + 2));
            sgj_add_nv_o(jsp, ja2p, NULL /* name */, jo3p);
        }
        sgj_add_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    return true;
}

static bool
sgj_get_sense_descriptors(sgj_state * jsp, sgj_opaque_p jop,
                          const struct sg_scsi_sense_hdr * sshp,
                          const uint8_t * sbp, int sb_len)
{
    bool processed = true;
    int add_sb_len, desc_len, k, dt, sense_key, n, sds;
#if 0
    uint16_t sct_sc;
#endif
    uint64_t ull;
    const uint8_t * descp;
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
    jap = sgj_new_named_array(jsp, jop, "sense_data_descriptor");

    for (descp = sbp, k = 0; (k < add_sb_len);
         k += desc_len, descp += desc_len) {
        int add_d_len = (k < (add_sb_len - 1)) ? descp[1] : -1;

        jo2p = sgj_new_unattached_object(jsp);
        if ((k + add_d_len + 2) > add_sb_len)
            add_d_len = add_sb_len - k - 2;
        desc_len = add_d_len + 2;
        processed = true;
        dt = descp[0];
        switch (dt) {
        case 0:
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt,
                               NULL, "Information");
            if (add_d_len >= 10) {
                int valid = !! (0x80 & descp[2]);
                sgj_add_nv_ihexstr(jsp, jo2p, "valid", valid, NULL,
                                   valid ? "as per T10" : "Vendor specific");
                sgj_add_nv_ihex(jsp, jo2p, "information",
                                sg_get_unaligned_be64(descp + 4));
            } else {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 1:
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt,
                               NULL, "Command specific");
            if (add_d_len >= 10) {
                sgj_add_nv_ihex(jsp, jo2p, "command_specific_information",
                                sg_get_unaligned_be64(descp + 4));
            } else {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 2:         /* Sense Key Specific */
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "Sense key specific");
            processed = sgj_decode_sks(jsp, jo2p, descp + 4, desc_len - 4,
                                       sense_key);
            break;
        case 3:
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "Field replaceable unit code");
            if (add_d_len >= 2)
                sgj_add_nv_ihex(jsp, jo2p, "field_replaceable_unit_code",
                                descp[3]);
            else {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 4:
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "Stream commands");
            if (add_d_len >= 2) {
                sgj_add_nv_i(jsp, jo2p, "filemark", !! (descp[3] & 0x80));
                sgj_add_nv_ihex_ane(jsp, jo2p, "eom", !! (descp[3] & 0x40),
                                    false, "End Of Medium");
                sgj_add_nv_ihex_ane(jsp, jo2p, "ili", !! (descp[3] & 0x20),
                                    false, "Incorrect Length Indicator");
            } else {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 5:
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "Block commands");
            if (add_d_len >= 2)
                sgj_add_nv_ihex_ane(jsp, jo2p, "ili", !! (descp[3] & 0x20),
                                    false, "Incorrect Length Indicator");
            else {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 6:
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "OSD object identification");
            sgj_add_nv_s(jsp, jo2p, parsing, "Unsupported");
            processed = false;
            break;
        case 7:
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "OSD response integrity check value");
            sgj_add_nv_s(jsp, jo2p, parsing, "Unsupported");
            break;
        case 8:
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "OSD attribute identification");
            sgj_add_nv_s(jsp, jo2p, parsing, "Unsupported");
            processed = false;
            break;
        case 9:         /* this is defined in SAT (SAT-2) */
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "ATA status return");
            if (add_d_len >= 12) {
                sgj_add_nv_i(jsp, jo2p, "extend", !! (descp[2] & 1));
                sgj_add_nv_ihex(jsp, jo2p, "error", descp[3]);
                sgj_add_nv_ihex(jsp, jo2p, "count",
                                sg_get_unaligned_be16(descp + 4));
                ull = ((uint64_t)descp[10] << 40) |
                       ((uint64_t)descp[8] << 32) |
                       (descp[6] << 24) |
                       (descp[11] << 16) |
                       (descp[9] << 8) |
                       descp[7];
                sgj_add_nv_ihex(jsp, jo2p, "lba", ull);
                sgj_add_nv_ihex(jsp, jo2p, "device", descp[12]);
                sgj_add_nv_ihex(jsp, jo2p, "status", descp[13]);
            } else {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 0xa:
           /* Added in SPC-4 rev 17, became 'Another ...' in rev 34 */
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "Another progress indication");
            if (add_d_len < 6) {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
                break;
            }
            sgj_add_nv_ihex(jsp, jo2p, "another_sense_key", descp[2]);
            sgj_add_nv_ihex(jsp, jo2p, "another_additional_sense_code",
                            descp[3]);
            sgj_add_nv_ihex(jsp, jo2p,
                            "another_additional_sense_code_qualifier",
                            descp[4]);
            sgj_progress_indication(jsp, jo2p,
                                    sg_get_unaligned_be16(descp + 6), true);
            break;
        case 0xb:       /* Added in SPC-4 rev 23, defined in SBC-3 rev 22 */
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "User data segment referral");
            if (add_d_len < 2) {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
                break;
            }
            if (! sgj_uds_referral_descriptor(jsp, jo2p, descp, add_d_len)) {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
            }
            break;
        case 0xc:       /* Added in SPC-4 rev 28 */
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", dt, NULL,
                               "Forwarded sense data");
            if (add_d_len < 2) {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
                break;
            }
            sgj_add_nv_ihex_ane(jsp, jo2p, "fsdt", !! (0x80 & descp[2]),
                               NULL, "Forwarded Sense Data Truncated");
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
                    n += sg_scnpr(b + n, blen - n, " %d", sds - 1);
            }
            sgj_add_nv_ihexstr(jsp, jo2p, "sense_data_source",
                               (0x7 & descp[2]), NULL, b);
            jo3p = sgj_new_named_object(jsp, jo2p, "forwarded_sense_data");
            sgj_get_sense(jsp, jo3p, descp + 4, desc_len - 4);
            break;
        case 0xd:       /* Added in SBC-3 rev 36d */
            /* this descriptor combines descriptors 0, 1, 2 and 3 */
            sgj_add_nv_ihexstr(jsp, jo2p, "descriptor_type", 0xc, NULL,
                               "Direct-access block device");
            if (add_d_len < 28) {
                sgj_add_nv_s(jsp, jo2p, parsing, dtsp);
                processed = false;
                break;
            }
            sgj_add_nv_i(jsp, jo2p, "valid", (0x80 & descp[2]));
            sgj_add_nv_ihex_ane(jsp, jo2p, "ili", !! (0x20 & descp[2]),
                               NULL, "Incorrect Length Indicator");
            processed = sgj_decode_sks(jsp, jo2p, descp + 4, desc_len - 4,
                                       sense_key);
            sgj_add_nv_ihex(jsp, jo2p, "field_replaceable_unit_code",
                            descp[7]);
            sgj_add_nv_ihex(jsp, jo2p, "information",
                            sg_get_unaligned_be64(descp + 8));
            sgj_add_nv_ihex(jsp, jo2p, "command_specific_information",
                            sg_get_unaligned_be64(descp + 16));
            break;
#if 0
        case 0xe:       /* Added in SPC-5 rev 6 (for Bind/Unbind) */
            n += sg_scnpr(b + n, blen - n, "Device designation\n");
            j = (int)SG_ARRAY_SIZE(dd_usage_reason_str_arr);
            if (descp[3] < j)
                n += sg_scnpr(b + n, blen - n, "%s    Usage reason: %s\n",
                              lip, dd_usage_reason_str_arr[descp[3]]);
            else
                n += sg_scnpr(b + n, blen - n, "%s    Usage reason: "
                              "reserved[%d]\n", lip, descp[3]);
            n += sg_get_designation_descriptor_str(z, descp + 4, descp[1] - 2,
                                                   true, false, blen - n,
                                                   b + n);
            break;
        case 0xf:       /* Added in SPC-5 rev 10 (for Write buffer) */
            n += sg_scnpr(b + n, blen - n, "Microcode activation ");
            if (add_d_len < 6) {
                sgj_add_nv_s(jsp, jop, parsing, dtsp);
                processed = false;
                break;
            }
            progress = sg_get_unaligned_be16(descp + 6);
            n += sg_scnpr(b + n, blen - n, "time: ");
            if (0 == progress)
                n += sg_scnpr(b + n, blen - n, "unknown\n");
            else
                n += sg_scnpr(b + n, blen - n, "%d seconds\n", progress);
            break;
        case 0xde:       /* NVME Status Field; vendor (sg3_utils) specific */
            n += sg_scnpr(b + n, blen - n, "NVMe Status: ");
            if (add_d_len < 6) {
                sgj_add_nv_s(jsp, jop, parsing, dtsp);
                processed = false;
                break;
            }
            n += sg_scnpr(b + n, blen - n, "DNR=%d, M=%d, ",
                          (int)!!(0x80 & descp[5]), (int)!!(0x40 & descp[5]));
            sct_sc = sg_get_unaligned_be16(descp + 6);
            n += sg_scnpr(b + n, blen - n, "SCT_SC=0x%x\n", sct_sc);
            if (sct_sc > 0) {
                char d[80];

                n += sg_scnpr(b + n, blen - n, "    %s\n",
                        sg_get_nvme_cmd_status_str(sct_sc, sizeof(d), d));
            }
            break;
#endif
        default:
            if (dt >= 0x80)
                sgj_add_nv_ihex(jsp, jo2p, "vendor_specific_descriptor_type",
                                dt);
            else
                sgj_add_nv_ihex(jsp, jo2p, "unknown_descriptor_type", dt);
            processed = false;
            break;
        }
#if 0
        if (! processed) {
            if (add_d_len > 0) {
                n += sg_scnpr(b + n, blen - n, "%s    ", lip);
                for (j = 0; j < add_d_len; ++j) {
                    if ((j > 0) && (0 == (j % 24)))
                        n += sg_scnpr(b + n, blen - n, "\n%s    ", lip);
                    n += sg_scnpr(b + n, blen - n, "%02x ", descp[j + 2]);
                }
                n += sg_scnpr(b + n, blen - n, "\n");
            }
        }
        if (add_d_len < 0)
            n += sg_scnpr(b + n, blen - n, "%s    short descriptor\n", lip);
#endif
        sgj_add_nv_o(jsp, jap, NULL /* name */, jo2p);
    }
    return processed;
}

#define ASCQ_ATA_PT_INFO_AVAILABLE 0x1d  /* corresponding ASC is 0 */

/* Fetch sense information */
bool
sgj_get_sense(sgj_state * jsp, sgj_opaque_p jop, const uint8_t * sbp,
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
    sgj_add_nv_ihexstr(jsp, jop, "response_code", resp_code, NULL, ebp);
    sgj_add_nv_b(jsp, jop, "descriptor_format", descriptor_format);
    sgj_add_nv_ihex_ane(jsp, jop, "sdat_ovfl", sdat_ovfl, false,
                        "Sense data overflow");
    sgj_add_nv_ihexstr(jsp, jop, "sense_key", ssh.sense_key, NULL,
                       sg_lib_sense_key_desc[ssh.sense_key]);
    sgj_add_nv_ihex(jsp, jop, "additional_sense_code", ssh.asc);
    sgj_add_nv_ihex(jsp, jop, "additional_sense_code_qualifier", ssh.ascq);
    sgj_add_nv_s(jsp, jop, "additional_sense_str",
                 sg_get_additional_sense_str(ssh.asc, ssh.ascq, false,
                                             blen, b));
    if (descriptor_format) {
        if (len > 8) {
            ret = sgj_get_sense_descriptors(jsp, jop, &ssh, sbp + 8, len - 8);
            if (ret == false) {
                ebp = "unable to decode sense descriptor";
                goto fini;
            }
        }
    } else if ((len > 12) && (0 == ssh.asc) &&
               (ASCQ_ATA_PT_INFO_AVAILABLE == ssh.ascq)) {
        /* SAT ATA PASS-THROUGH fixed format */
        sgj_add_nv_ihex(jsp, jop, "error", sbp[3]);
        sgj_add_nv_ihex(jsp, jop, "status", sbp[4]);
        sgj_add_nv_ihex(jsp, jop, "device", sbp[5]);
        sgj_add_nv_i(jsp, jop, "extend", !! (0x80 & sbp[8]));
        sgj_add_nv_i(jsp, jop, "count_upper_nonzero", !! (0x40 & sbp[8]));
        sgj_add_nv_i(jsp, jop, "lba_upper_nonzero", !! (0x20 & sbp[8]));
        sgj_add_nv_i(jsp, jop, "log_index", (0x7 & sbp[8]));
        sgj_add_nv_i(jsp, jop, "lba", sg_get_unaligned_le24(sbp + 9));
    } else if (len > 2) {   /* fixed format */
        sgj_add_nv_i(jsp, jop, "valid", valid_info_fld);
        sgj_add_nv_i(jsp, jop, "filemark", !! (sbp[2] & 0x80));
        sgj_add_nv_ihex_ane(jsp, jop, "eom", !! (sbp[2] & 0x40),
                            false, "End Of Medium");
        sgj_add_nv_ihex_ane(jsp, jop, "ili", !! (sbp[2] & 0x20),
                            false, "Incorrect Length Indicator");
        info = sg_get_unaligned_be32(sbp + 3);
        sgj_add_nv_ihex(jsp, jop, "information", info);
        sgj_add_nv_ihex(jsp, jop, "additional_sense_length", sbp[7]);
        if (sb_len > 11) {
            info = sg_get_unaligned_be32(sbp + 8);
            sgj_add_nv_ihex(jsp, jop, "command_specific_information", info);
        }
        if (sb_len > 14)
            sgj_add_nv_ihex(jsp, jop, "field_replaceable_unit_code", sbp[14]);
        if (sb_len > 17)
            sgj_decode_sks(jsp, jop, sbp + 15, sb_len - 15, ssh.sense_key);
        n =  sbp[7];
        n = (sb_len > n) ? n : sb_len;
        sgj_add_nv_ihex(jsp, jop, "number_of_bytes_beyond_18",
                        (n > 18) ? n - 18 : 0);
    } else {
        snprintf(ebuff, sizeof(ebuff), "sb_len=%d too short", sb_len);
        ebp = ebuff;
        ret = false;
    }
fini:
    if ((! ret) && ebp)
        sgj_add_nv_s(jsp, jop, "sense_decode_error", ebp);
    return ret;
}

#endif

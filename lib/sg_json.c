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

#include "sg_pr2serr.h"
#include "sg_json.h"

#include "sg_json_builder.h"

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

static int sgj_name_to_snake(const char * in, char * out, int maxlen_out);


static bool
sgj_parse_opts(sgj_state * jsp, const char * j_optarg)
{
    bool bad_arg = false;
    bool prev_negate = false;
    bool negate;
    int k, c;

    for (k = 0; j_optarg[k]; ++k) {     /* step over leading whitespace */
        if (! isspace((uint8_t)j_optarg[k]))
            break;
    }
    for ( ; j_optarg[k]; ++k) {
        c = j_optarg[k];
        negate = false;
        switch (c) {
        case '=':
            if (0 == k) /* should remove this, allows '-j==h' */
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
        case 'e':
            jsp->pr_exit_status = ! prev_negate;
            break;
        case 'g':
            jsp->pr_format = 'g';
            break;
        case 'h':
            jsp->pr_hex = ! prev_negate;
            break;
        case 'k':
            jsp->pr_packed = ! prev_negate;
            break;
        case 'l':
            jsp->pr_leadin = ! prev_negate;
            break;
        case 'n':
            jsp->pr_name_ex = ! prev_negate;
            break;
        case 'o':
            jsp->pr_out_hr = ! prev_negate;
            break;
        case 'p':
            jsp->pr_pretty = ! prev_negate;
            break;
        case 'q':
            ++jsp->q_counter;
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
        case 'z':
            ++jsp->z_counter;
            break;
        case '?':
            bad_arg = true;
            jsp->first_bad_char = '\0';
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

char *
sg_json_usage(int char_if_not_j, char * b, int blen)
{
    int n = 0;
    char short_opt = char_if_not_j ? char_if_not_j : 'j';

    if ((NULL == b) || (blen < 1))
        goto fini;
    n +=  sg_scnpr(b + n, blen - n, "JSON option usage:\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "     --json[=JO] | -%c[=JO]\n\n", short_opt);
    n +=  sg_scnpr(b + n, blen - n, "  where JO is a string of one or more "
                   "of:\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      0 | 2    tab pretty output to 2 spaces\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      4    tab pretty output to 4 spaces (def)\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      8    tab pretty output to 8 spaces\n");
    if (n >= (blen - 1))
        goto fini;
    n +=  sg_scnpr(b + n, blen - n,
                   "      e    show 'exit_status' field\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      h    show 'hex' fields\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      k    packed, only non-pretty printed output\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      l    show lead-in fields (invocation "
                   "information)\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      n    show 'name_extra' information fields\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      o    non-JSON output placed in 'plain_text_output' "
                   "array in lead-in\n");
    if (n >= (blen - 1))
        goto fini;
    n +=  sg_scnpr(b + n, blen - n,
                   "      p    pretty print the JSON output\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      s    show string output (usually fields named "
                   "'meaning')\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      v    make JSON output more verbose\n");
    n +=  sg_scnpr(b + n, blen - n,
                   "      - | ~ | !    toggle next letter setting\n");

    sg_scnpr(b + n, blen - n, "\nIn the absence of the optional JO argument, "
             "the following are set\non: 'elps' while the others are set "
             "off, and tabs are set to 4.\nBefore command line JO options "
             "are applied, the environment\nvariable: %s is applied (if "
             "present). Note that\nno space is permitted between the short "
             "option ('-%c') and its\nargument ('JO'). For more information "
             "see 'man sg3_utils_json' or\n'man sdparm_json' .\n",
             sgj_opts_ev, short_opt);
fini:
    return b;
}

char *
sg_json_settings(sgj_state * jsp, char * b, int blen)
{
    snprintf(b, blen, "%d%se%sh%sk%sl%sn%so%sp%ss%sv", jsp->pr_indent_size,
             jsp->pr_exit_status ? "" : "-", jsp->pr_hex ? "" : "-",
             jsp->pr_packed ? "" : "-", jsp->pr_leadin ? "" : "-",
             jsp->pr_name_ex ? "" : "-", jsp->pr_out_hr ? "" : "-",
             jsp->pr_pretty ? "" : "-", jsp->pr_string ? "" : "-",
             jsp->verbose ? "" : "-");
    return b;
}

static void
sgj_def_opts(sgj_state * jsp)
{
    jsp->pr_as_json = true;
    jsp->pr_exit_status = true;
    jsp->pr_hex = false;
    jsp->pr_leadin = true;
    jsp->pr_out_hr = false;
    jsp->pr_name_ex = false;
    jsp->pr_packed = false;     /* 'k' control character, needs '-p' */
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
    jsp->out_hrp = NULL;
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
sgj_start_r(const char * util_name, const char * ver_str, int argc,
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
            if (argv) {
                for (k = 0; k < argc; ++k)
                    json_array_push((json_value *)jap,
                                    json_string_new(argv[k]));
            }
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
        if (jsp->verbose) {
            const char * cp = getenv(sgj_opts_ev);
            char b[32];

            json_object_push((json_value *)jv2p, "environment_variable_name",
                             json_string_new(sgj_opts_ev));
            json_object_push((json_value *)jv2p, "environment_variable_value",
                             json_string_new(cp ? cp : "no available"));
            sg_json_settings(jsp, b, sizeof(b));
            json_object_push((json_value *)jv2p, "json_options",
                             json_string_new(b));
        }
    } else {
        if (jsp->pr_out_hr && util_name)
            jv2p = json_object_push((json_value *)jvp, "utility_invoked",
                                    json_object_new(0));
    }
    if (jsp->pr_out_hr && jv2p) {
        jsp->out_hrp = json_object_push((json_value *)jv2p,
                                         "plain_text_output",
                                        json_array_new(0));
        if (jsp->pr_leadin && (jsp->verbose > 3)) {
            char * bp = (char *)calloc(4096, 1);

            if (bp) {
                sg_json_usage(0, bp, 4096);
                sgj_hr_str_out(jsp, bp, strlen(bp));
                free(bp);
            }
        }
    }
    return jvp;
}

void
sgj_js2file(sgj_state * jsp, sgj_opaque_p jop, int exit_status, FILE * fp)
{
    size_t len;
    char * b;
    json_value * jvp = (json_value *)(jop ? jop : jsp->basep);
    json_serialize_opts out_settings;

    if (NULL == jvp) {
        fprintf(fp, "%s: all NULL pointers ??\n", __func__);
        return;
    }
    if ((NULL == jop) && jsp->pr_exit_status) {
        char d[80];

#if 0
        if (sg_exit2str(exit_status, jsp->verbose, sizeof(d), d)) {
            if (0 == strlen(d))
                strncpy(d, "no errors", sizeof(d) - 1);
        } else
            strncpy(d, "not available", sizeof(d) - 1);
#else
        if (0 == exit_status)
            strncpy(d, "no errors", sizeof(d) - 1);
        else
            snprintf(d, sizeof(d), "exit_status=%d", exit_status);
#endif
        sgj_js_nv_istr(jsp, jop, "exit_status", exit_status, NULL, d);
    }
    memcpy(&out_settings, &def_out_settings, sizeof(out_settings));
    if (jsp->pr_indent_size != def_out_settings.indent_size)
        out_settings.indent_size = jsp->pr_indent_size;
    if (! jsp->pr_pretty)
        out_settings.mode = jsp->pr_packed ? json_serialize_mode_packed :
                                json_serialize_mode_single_line;

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
    free(b);
}

void
sgj_finish(sgj_state * jsp)
{
    if (jsp && jsp->basep) {
        json_builder_free((json_value *)jsp->basep);
        jsp->basep = NULL;
        jsp->out_hrp = NULL;
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

    if ((NULL == jsp) || (! jsp->pr_as_json)) {
        va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
    } else if (jsp->pr_out_hr) {
        bool step = false;
        size_t ln;
        char b[256];
        static const int blen = sizeof(b);

        va_start(args, fmt);
        ln = vsnprintf(b, blen, fmt, args);
        if ((ln > 0) && (ln < (size_t)blen)) {
            char * cp;

             /* deal with leading, trailing and embedded newlines */
             while ( true ) {
                cp = strrchr(b, '\n');
                if (NULL == cp)
                    break;
                else if (cp == b) {
                    if ('\0' == *(cp + 1))
                        *cp = '\0';
                    else
                        step = true;
                    break;
                } else if ('\0' == *(cp + 1))
                    *cp = '\0';
                else
                    *cp = ';';
             }
             /* replace any tabs with semicolons or spaces */
             while ( true ) {
                cp = strchr(b, '\t');
                if (NULL == cp)
                    break;
                else if (cp == b) {
                    if ('\0' == *(cp + 1))
                        *cp = '\0';
                    else {
                        *cp = ' ';      /* so don't find \t again and again */
                        step = true;
                    }
                } else {
                    if (';' == *(cp - 1))
                        *cp = ' ';
                    else
                        *cp = ';';
                }
            }
        }
        json_array_push((json_value *)jsp->out_hrp,
                        json_string_new(step ? b + 1 : b));
        va_end(args);
    } else {    /* do nothing, just consume arguments */
        va_start(args, fmt);
        va_end(args);
    }
}

/* jop will 'own' returned value (if non-NULL) */
sgj_opaque_p
sgj_named_subobject_r(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name)
{
    sgj_opaque_p resp = NULL;

    if (jsp && jsp->pr_as_json && sn_name)
        resp = json_object_push((json_value *)(jop ? jop : jsp->basep),
                                 sn_name, json_object_new(0));
    return resp;
}

sgj_opaque_p
sgj_snake_named_subobject_r(sgj_state * jsp, sgj_opaque_p jop,
                            const char * conv2sname)
{
    if (jsp && jsp->pr_as_json && conv2sname) {
        int olen = strlen(conv2sname);
        char * sname = (char *)malloc(olen + 8);
        int nlen = sgj_name_to_snake(conv2sname, sname, olen + 8);

        if (nlen > 0)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    sname, json_object_new(0));
    }
    return NULL;
}

/* jop will 'own' returned value (if non-NULL) */
sgj_opaque_p
sgj_named_subarray_r(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name)
{
    sgj_opaque_p resp = NULL;

    if (jsp && jsp->pr_as_json && sn_name)
        resp = json_object_push((json_value *)(jop ? jop : jsp->basep),
                                sn_name, json_array_new(0));
    return resp;
}

sgj_opaque_p
sgj_snake_named_subarray_r(sgj_state * jsp, sgj_opaque_p jop,
                           const char * conv2sname)
{
    if (jsp && jsp->pr_as_json && conv2sname) {
        int olen = strlen(conv2sname);
        char * sname = (char *)malloc(olen + 8);
        int nlen = sgj_name_to_snake(conv2sname, sname, olen + 8);

        if (nlen > 0)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    sname, json_array_new(0));
    }
    return NULL;
}

/* Newly created object is un-attached to jsp->basep tree */
sgj_opaque_p
sgj_new_unattached_object_r(sgj_state * jsp)
{
    return (jsp && jsp->pr_as_json) ? json_object_new(0) : NULL;
}

/* Newly created array is un-attached to jsp->basep tree */
sgj_opaque_p
sgj_new_unattached_array_r(sgj_state * jsp)
{
    return (jsp && jsp->pr_as_json) ? json_array_new(0) : NULL;
}

/* Newly created string is un-attached to jsp->basep tree */
sgj_opaque_p
sgj_new_unattached_string_r(sgj_state * jsp, const char * value)
{
    return (jsp && jsp->pr_as_json) ? json_string_new(value) : NULL;
}

/* Newly created string with length object is un-attached to jsp->basep
 * tree */
sgj_opaque_p
sgj_new_unattached_str_len_r(sgj_state * jsp, const char * value, int vlen)
{
    return (jsp && jsp->pr_as_json) ? json_string_new_length(vlen, value) :
                                      NULL;
}

/* Newly created integer object is un-attached to jsp->basep tree */
sgj_opaque_p
sgj_new_unattached_integer_r(sgj_state * jsp, uint64_t value)
{
    return (jsp && jsp->pr_as_json) ? json_integer_new(value) : NULL;
}

/* Newly created boolean object is un-attached to jsp->basep tree */
sgj_opaque_p
sgj_new_unattached_bool_r(sgj_state * jsp, bool value)
{
    return (jsp && jsp->pr_as_json) ? json_boolean_new(value) : NULL;
}

/* Newly created null object is un-attached to jsp->basep tree */
sgj_opaque_p
sgj_new_unattached_null_r(sgj_state * jsp)
{
    return (jsp && jsp->pr_as_json) ? json_null_new() : NULL;
}

sgj_opaque_p
sgj_js_nv_s(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
            const char * value)
{
    if (jsp && jsp->pr_as_json && value) {
        if (sn_name)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    sn_name, json_string_new(value));
        else
            return json_array_push((json_value *)(jop ? jop : jsp->basep),
                                   json_string_new(value));
    } else
        return NULL;
}

sgj_opaque_p
sgj_js_nv_s_len(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
                const char * value, int vlen)
{
    int k;

    if (jsp && jsp->pr_as_json && value && (vlen >= 0)) {
        for (k = 0; k < vlen; ++k) {    /* don't want '\0' in value string */
            if (0 == value[k])
                break;
        }
        if (sn_name)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    sn_name, json_string_new_length(k, value));
        else
            return json_array_push((json_value *)(jop ? jop : jsp->basep),
                                   json_string_new_length(k, value));
    } else
        return NULL;
}

#if 1
static bool
has_control_char(const uint8_t * up, int len)
{
    int k;
    uint8_t u;

    for (k = 0; k < len; ++k) {
        u = up[k];
        if ((u < 0x20) || (0x7f == u))
            return true;
    }
    return false;
}
#endif

sgj_opaque_p
sgj_js_nv_s_len_chk(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
                    const uint8_t * value, int vlen)
{
    sgj_opaque_p res = NULL;

#if 0
    if (value && (vlen > 0) &&
        sg_has_control_char(value, vlen))
#else
    if (value && (vlen > 0) &&
        has_control_char(value, vlen))
#endif
    {
        const int n = vlen * 4 + 4;
        char * p = (char *)malloc(n);

        if (p) {
            int k;

            k = sgj_conv2json_string(value, vlen, p, n);
            if (k > 0)
                res = sgj_js_nv_s_len(jsp, jop, sn_name, p, k);
            free(p);
        }
        return res;
    } else
        return sgj_js_nv_s_len(jsp, jop, sn_name, (const char *)value, vlen);
}

sgj_opaque_p
sgj_js_nv_i(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
            int64_t value)
{
    if (jsp && jsp->pr_as_json) {
        if (sn_name)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    sn_name, json_integer_new(value));
        else
            return json_array_push((json_value *)(jop ? jop : jsp->basep),
                                   json_integer_new(value));
    }
    else
        return NULL;
}

sgj_opaque_p
sgj_js_nv_b(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
            bool value)
{
    if (jsp && jsp->pr_as_json) {
        if (sn_name)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    sn_name, json_boolean_new(value));
        else
            return json_array_push((json_value *)(jop ? jop : jsp->basep),
                                   json_boolean_new(value));
    } else
        return NULL;
}

/* jop will 'own' ua_jop (if returned value is non-NULL) */
sgj_opaque_p
sgj_js_nv_o(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
            sgj_opaque_p ua_jop)
{
    if (jsp && jsp->pr_as_json && ua_jop) {
        if (sn_name)
            return json_object_push((json_value *)(jop ? jop : jsp->basep),
                                    sn_name, (json_value *)ua_jop);
        else
            return json_array_push((json_value *)(jop ? jop : jsp->basep),
                                   (json_value *)ua_jop);
    } else
        return NULL;
}

void
sgj_js_nv_ihex(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
               uint64_t value)
{
    if ((NULL == jsp) || (NULL == sn_name) || (! jsp->pr_as_json))
        return;
    else if (jsp->pr_hex)  {
        sgj_opaque_p jo2p = sgj_named_subobject_r(jsp, jop, sn_name);
        char b[64];

        if (NULL == jo2p)
            return;
        sgj_js_nv_i(jsp, jo2p, "i", (int64_t)value);
        snprintf(b, sizeof(b), "%" PRIx64, value);
        sgj_js_nv_s(jsp, jo2p, "hex", b);
    } else
        sgj_js_nv_i(jsp, jop, sn_name, (int64_t)value);
}

static const char * sc_mn_s = "meaning";

void
sgj_js_nv_istr(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
               int64_t val_i, const char * str_name, const char * val_s)
{
    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    else if (val_s && jsp->pr_string) {
        sgj_opaque_p jo2p = sgj_named_subobject_r(jsp, jop, sn_name);

        if (NULL == jo2p)
            return;
        sgj_js_nv_i(jsp, jo2p, "i", (int64_t)val_i);
        sgj_js_nv_s(jsp, jo2p, str_name ? str_name : sc_mn_s, val_s);
    } else
        sgj_js_nv_i(jsp, jop, sn_name, val_i);
}

void
sgj_js_nv_ihexstr(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
                  int64_t val_i, const char * str_name, const char * val_s)
{
    bool as_str;

    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    as_str = jsp->pr_string && val_s;
    if ((! jsp->pr_hex) && (! as_str))
        sgj_js_nv_i(jsp, jop, sn_name, val_i);
    else {
        char b[64];
        sgj_opaque_p jo2p = sgj_named_subobject_r(jsp, jop, sn_name);

        if (NULL == jo2p)
            return;
        sgj_js_nv_i(jsp, jo2p, "i", (int64_t)val_i);
        if (jsp->pr_hex) {
            snprintf(b, sizeof(b), "%" PRIx64, val_i);
            sgj_js_nv_s(jsp, jo2p, "hex", b);
        }
        if (as_str)
            sgj_js_nv_s(jsp, jo2p, str_name ? str_name : sc_mn_s, val_s);
    }
}

static const char * sc_nex_s = "name_extra";

void
sgj_js_nv_ihex_nex(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
                   int64_t val_i, bool hex_as_well, const char * nex_s)
{
    bool as_hex, as_nex;

    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    as_hex = jsp->pr_hex && hex_as_well;
    as_nex = jsp->pr_name_ex && nex_s;
    if (! (as_hex || as_nex))
        sgj_js_nv_i(jsp, jop, sn_name, val_i);
    else {
        char b[64];
        sgj_opaque_p jo2p =
                 sgj_named_subobject_r(jsp, jop, sn_name);

        if (NULL == jo2p)
            return;
        sgj_js_nv_i(jsp, jo2p, "i", (int64_t)val_i);
        if (as_hex) {
            snprintf(b, sizeof(b), "%" PRIx64, val_i);
            sgj_js_nv_s(jsp, jo2p, "hex", b);
        }
        if (as_nex)
            sgj_js_nv_s(jsp, jo2p, sc_nex_s, nex_s);
    }
}

void
sgj_js_nv_s_nex(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
                const char * val_s, const char * nex_s)
{
    bool as_nex;

    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    as_nex = jsp->pr_name_ex && nex_s;
    if ((NULL == val_s) && (! as_nex))
        /* corner case: assume jop is an array */
        json_array_push((json_value *)(jop ? jop : jsp->basep),
                         json_string_new(sn_name));
    else if (NULL == val_s)
        sgj_js_nv_s(jsp, jop, sn_name, nex_s);
    else if (! as_nex)
        sgj_js_nv_s(jsp, jop, sn_name, val_s);
    else {
        sgj_opaque_p jo2p =
                 sgj_named_subobject_r(jsp, jop, sn_name);

        if (NULL == jo2p)
            return;
        sgj_js_nv_s(jsp, jo2p, "s", val_s);
        sgj_js_nv_s(jsp, jo2p, sc_nex_s, nex_s);
    }
}

#if 1
static void
h2str(const uint8_t * byte_arr, int num_bytes, char * bp, int blen)
{
    int j, k, n;

    for (k = 0, n = 0; (k < num_bytes) && (n < blen); ) {
        j = sg_scnpr(bp + n, blen - n, "%02x ", byte_arr[k]);
        if (j < 2)
            break;
        n += j;
        ++k;
        if ((0 == (k % 8)) && (k < num_bytes) && (n < blen)) {
            bp[n++] = ' ';
        }
    }
    j = strlen(bp);
    if ((j > 0) && (' ' == bp[j - 1]))
        bp[j - 1] = '\0';    /* chop off trailing space */
}
#endif

/* Add hex byte strings irrespective of jsp->pr_hex setting. */
void
sgj_js_nv_hex_bytes(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
                    const uint8_t * byte_arr, int num_bytes)
{
    int blen = num_bytes * 4;
    char * bp;

    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    bp = (char *)calloc(blen + 4, 1);
    if (bp) {
#if 0
        hex2str(byte_arr, num_bytes, NULL, 2, blen, bp);
#else
        h2str(byte_arr, num_bytes, bp, blen);
#endif
        sgj_js_nv_s(jsp, jop, sn_name, bp);
        free(bp);
    }
}

void
sgj_js_nv_ihexstr_nex(sgj_state * jsp, sgj_opaque_p jop, const char * sn_name,
                      int64_t val_i, bool hex_as_well, const char * str_name,
                      const char * val_s, const char * nex_s)
{
    bool as_hex = jsp->pr_hex && hex_as_well;
    bool as_str = jsp->pr_string && val_s;
    bool as_nex = jsp->pr_name_ex && nex_s;
    const char * sname =  str_name ? str_name : sc_mn_s;

    if ((NULL == jsp) || (! jsp->pr_as_json))
        return;
    if (! (as_hex || as_nex || as_str))
        sgj_js_nv_i(jsp, jop, sn_name, val_i);
    else {
        char b[64];
        sgj_opaque_p jo2p =
                 sgj_named_subobject_r(jsp, jop, sn_name);

        if (NULL == jo2p)
            return;
        sgj_js_nv_i(jsp, jo2p, "i", (int64_t)val_i);
        if (as_nex) {
            if (as_hex) {
                snprintf(b, sizeof(b), "%" PRIx64, val_i);
                sgj_js_nv_s(jsp, jo2p, "hex", b);
            }
            if (as_str) {
                sgj_js_nv_s(jsp, jo2p, sname, val_s);
            }
            sgj_js_nv_s(jsp, jo2p, sc_nex_s, nex_s);
        } else if (as_hex) {
            snprintf(b, sizeof(b), "%" PRIx64, val_i);
            sgj_js_nv_s(jsp, jo2p, "hex", b);
            if (as_str)
                sgj_js_nv_s(jsp, jo2p, sname, val_s);
        } else if (as_str)
            sgj_js_nv_s(jsp, jo2p, sname, val_s);
    }
}

/* Treat '\n' in sp as line breaks. Consumes characters from sp until either
 * a '\0' is found or slen is exhausted. Add each line to jsp->out_hrp JSON
 * array (if conditions met). Outputs to stdout. */
void
sgj_hr_str_out(sgj_state * jsp, const char * sp, int slen)
{
    char c;
    int k, n;
    const char * prev_sp = sp;
    const char * cur_sp = sp;

    if ((NULL == jsp) || (NULL == jsp->out_hrp) || (! jsp->pr_as_json) ||
        (! jsp->pr_out_hr))
        return;
    for (k = 0; k < slen; ++k, ++cur_sp) {
        c = *cur_sp;
        if ('\0' == c)
            break;
        else if ('\n' == c) {
            n = cur_sp - prev_sp;
            /* when name is NULL, add to array (jsp->out_hrp) */
            sgj_js_nv_s_len(jsp, jsp->out_hrp, NULL, prev_sp, n);
            prev_sp = cur_sp + 1;
        }
    }
    if (prev_sp < cur_sp) {
        n = cur_sp - prev_sp;
        sgj_js_nv_s_len(jsp, jsp->out_hrp, NULL, prev_sp, n);
    }
}

char *
sgj_convert2snake(const char * in_name, char * sn_name, int max_sname_len)
{
    sgj_name_to_snake(in_name, sn_name, max_sname_len);
    return sn_name;
}

bool
sgj_is_snake_name(const char * in_name)
{
    size_t k;
    size_t ln = strlen(in_name);
    char c;

    for (k = 0; k < ln; ++k) {
        c = in_name[k];
        if (((c >= '0') && (c <= '9')) ||
            ((c >= 'a') && (c <= 'z')) ||
            (c == '_'))
            continue;
        else
            return false;
    }
    return true;
}

/* This function tries to convert the 'in' C string to "snake_case"
 * convention so the output 'out' only contains lower case ASCII letters,
 * numerals and "_" as a separator. Any leading or trailing underscores
 * are removed as are repeated underscores (e.g. "_Snake __ case" becomes
 * "snake_case"). Parentheses and the characters between them are removed.
 * Returns number of characters placed in 'out' excluding the trailing
 * NULL */
char *
sgj_convert2snake_rm_parens(const char * in, char * out, int maxlen_out)
{
    bool prev_underscore = false;
    bool within_paren = false;
    int c, k, j, inlen;

    if (maxlen_out < 2) {
        if (maxlen_out == 1)
            out[0] = '\0';
        return out;
    }
    inlen = strlen(in);
    for (k = 0, j = 0; (k < inlen) && (j < maxlen_out); ++k) {
        c = in[k];
        if (within_paren) {
            if (')' == c)
                within_paren = false;
            continue;
        }
        if (isalnum(c)) {
            out[j++] = isupper(c) ? tolower(c) : c;
            prev_underscore = false;
        } else if ('(' == c)
            within_paren = true;
        else if ((j > 0) && (! prev_underscore)) {
            out[j++] = '_';
            prev_underscore = true;
        }
        /* else we are skipping character 'c' */
    }
    if (j == maxlen_out)
        out[--j] = '\0';
    else if (0 == j) {
        out[0] = '_';
        out[1] = '\0';
        return out;
    }
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
    return out;
}

static int
sgj_name_to_snake(const char * in, char * out, int maxlen_out)
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
    /* trim of trailing underscore (can only be one) */
    if (0 == j) {
        out[j++] = '_';         /* degenerate case: name set to '_' */
        out[j] = '\0';
    } else if ('_' == out[j - 1])
        out[--j] = '\0';
    else
        out[j] = '\0';
    return j;
}

static int
sgj_jtype_to_s(char * b, int blen_max, json_value * jvp, bool as_hex)
{
    json_type jtype = jvp ? jvp->type : json_none;

    switch (jtype) {
    case json_string:
        return sg_scnpr(b, blen_max, "%s", jvp->u.string.ptr);
    case json_integer:
        if (as_hex)
            return sg_scnpr(b, blen_max, "0x%" PRIx64, jvp->u.integer);
        else
            return sg_scnpr(b, blen_max, "%" PRIi64, jvp->u.integer);
    case json_boolean:
        return sg_scnpr(b, blen_max, "%s", jvp->u.boolean ? "true" : "false");
    case json_none:
    default:
        if ((blen_max > 0) && ('\0' != b[0]))
            b[0] = '\0';
        break;
    }
    return 0;
}

static int
sgj_haj_helper(char * b, int blen_max, const char * name,
               enum sgj_separator_t sep, bool use_jvp, json_value * jvp,
               int64_t val_instead, bool as_hex)
{
    int n = 0;

    if (name) {
        n += sg_scnpr(b + n, blen_max - n, "%s", name);
        switch (sep) {
        case SGJ_SEP_NONE:
            break;
        case SGJ_SEP_SPACE_1:
            n += sg_scnpr(b + n, blen_max - n, " ");
            break;
        case SGJ_SEP_SPACE_2:
            n += sg_scnpr(b + n, blen_max - n, "  ");
            break;
        case SGJ_SEP_SPACE_3:
            n += sg_scnpr(b + n, blen_max - n, "   ");
            break;
        case SGJ_SEP_SPACE_4:
            n += sg_scnpr(b + n, blen_max - n, "    ");
            break;
        case SGJ_SEP_EQUAL_NO_SPACE:
            n += sg_scnpr(b + n, blen_max - n, "=");
            break;
        case SGJ_SEP_EQUAL_1_SPACE:
            n += sg_scnpr(b + n, blen_max - n, "= ");
            break;
        case SGJ_SEP_SPACE_EQUAL_SPACE:
            n += sg_scnpr(b + n, blen_max - n, " = ");
            break;
        case SGJ_SEP_COLON_NO_SPACE:
            n += sg_scnpr(b + n, blen_max - n, ":");
            break;
        case SGJ_SEP_COLON_1_SPACE:
            n += sg_scnpr(b + n, blen_max - n, ": ");
            break;
        default:
            break;
        }
    }
    if (use_jvp)
        n += sgj_jtype_to_s(b + n, blen_max - n, jvp, as_hex);
    else if (as_hex)
        n += sg_scnpr(b + n, blen_max - n, "0x%" PRIx64, val_instead);
    else
        n += sg_scnpr(b + n, blen_max - n, "%" PRIi64, val_instead);
    return n;
}

/* aname will be converted to a snake name, if required */
static void
sgj_haj_xx(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
           const char * aname, enum sgj_separator_t sep, json_value * jvp,
           bool hex_haj, const char * val_s, const char * nex_s)
{
    bool eaten = false;
    bool as_json = (jsp && jsp->pr_as_json);
    bool done;
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
    if (NULL == aname) {
        if ((! as_json) || (jsp && jsp->pr_out_hr)) {
            sgj_jtype_to_s(b + n, blen - n, jvp, hex_haj);
            printf("%s\n", b);
        }
        if (NULL == jop) {
            if (as_json && jsp->pr_out_hr) {
                eaten = true;
                json_array_push((json_value *)jsp->out_hrp,
                                jvp ? jvp : json_null_new());
            }
        } else {        /* assume jop points to named array */
            if (as_json) {
                eaten = true;
                json_array_push((json_value *)jop,
                                jvp ? jvp : json_null_new());
            }
        }
        goto fini;
    }
    if (as_json) {
        int k;

        if (NULL == jop)
            jop = jsp->basep;
        k = sgj_name_to_snake(aname, jname, sizeof(jname));
        if (k > 0) {
            done = false;
            if (nex_s && (strlen(nex_s) > 0)) {
                switch (jtype) {
                case json_string:
                    break;
                case json_integer:
                    sgj_js_nv_ihexstr_nex(jsp, jop, jname, jvp->u.integer,
                                          hex_haj, sc_mn_s, val_s, nex_s);
                    done = true;
                    break;
                case json_boolean:
                    sgj_js_nv_ihexstr_nex(jsp, jop, jname, jvp->u.boolean,
                                          false, sc_mn_s, val_s, nex_s);
                    done = true;
                    break;
                case json_none:
                default:
                    break;
                }
            } else {
                switch (jtype) {
                case json_string:
                    break;
                case json_integer:
                    if (hex_haj) {
                        sgj_js_nv_ihexstr(jsp, jop, jname, jvp->u.integer,
                                          sc_mn_s, val_s);
                        done = true;
                    }
                    break;
                case json_none:
                default:
                    break;
                }
            }
            if (! done) {
                eaten = true;
                json_object_push((json_value *)jop, jname,
                                 jvp ? jvp : json_null_new());
            }
        }
    }
    if (jvp && ((as_json && jsp->pr_out_hr) || (! as_json)))
        sgj_haj_helper(b + n, blen - n, aname, sep, true, jvp, 0, hex_haj);

    if (as_json && jsp->pr_out_hr)
        json_array_push((json_value *)jsp->out_hrp, json_string_new(b));
    if (! as_json)
        printf("%s\n", b);
fini:
    if (jvp && (! eaten))
        json_builder_free((json_value *)jvp);
}

void
sgj_haj_vs(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
           const char * aname, enum sgj_separator_t sep, const char * value)
{
    json_value * jvp;

    /* make json_value even if jsp->pr_as_json is false */
    jvp = value ? json_string_new(value) : NULL;
    sgj_haj_xx(jsp, jop, leadin_sp, aname, sep, jvp, false, NULL, NULL);
}

void
sgj_haj_vi(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
          const char * aname, enum sgj_separator_t sep, int64_t value,
           bool hex_haj)
{
    json_value * jvp;

    jvp = json_integer_new(value);
    sgj_haj_xx(jsp, jop, leadin_sp, aname, sep, jvp, hex_haj, NULL, NULL);
}

void
sgj_haj_vistr(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
              const char * aname, enum sgj_separator_t sep, int64_t value,
              bool hex_haj, const char * val_s)
{
    json_value * jvp;

    jvp = json_integer_new(value);
    sgj_haj_xx(jsp, jop, leadin_sp, aname, sep, jvp, hex_haj, val_s,
                 NULL);
}

void
sgj_haj_vi_nex(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
               const char * aname, enum sgj_separator_t sep,
               int64_t value, bool hex_haj, const char * nex_s)
{
    json_value * jvp;

    jvp = json_integer_new(value);
    sgj_haj_xx(jsp, jop, leadin_sp, aname, sep, jvp, hex_haj, NULL, nex_s);
}

void
sgj_haj_vistr_nex(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
                  const char * aname, enum sgj_separator_t sep,
                  int64_t value, bool hex_haj,
                  const char * val_s, const char * nex_s)
{
    json_value * jvp;

    jvp = json_integer_new(value);
    sgj_haj_xx(jsp, jop, leadin_sp, aname, sep, jvp, hex_haj, val_s,
               nex_s);
}

void
sgj_haj_vb(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
           const char * aname, enum sgj_separator_t sep, bool value)
{
    json_value * jvp;

    jvp = json_boolean_new(value);
    sgj_haj_xx(jsp, jop, leadin_sp, aname, sep, jvp, false, NULL, NULL);
}

sgj_opaque_p
sgj_haj_subo_r(sgj_state * jsp, sgj_opaque_p jop, int leadin_sp,
               const char * aname, enum sgj_separator_t sep, int64_t value,
               bool hex_haj)
{
    bool as_json = (jsp && jsp->pr_as_json);
    int n = 0;
    sgj_opaque_p jo2p;
    char b[256];
    static const int blen = sizeof(b);

    if (NULL == aname)
        return NULL;
    for (n = 0; n < leadin_sp; ++n)
        b[n] = ' ';
    b[n] = '\0';
    if ((! as_json) || (jsp && jsp->pr_out_hr))
        sgj_haj_helper(b + n, blen - n, aname, sep, false, NULL, value,
                       hex_haj);

    if (as_json && jsp->pr_out_hr)
        json_array_push((json_value *)jsp->out_hrp, json_string_new(b));
    if (! as_json)
        printf("%s\n", b);

    if (as_json) {
        sgj_name_to_snake(aname, b, blen);
        jo2p = sgj_named_subobject_r(jsp, jop, b);
        if (jo2p) {
            sgj_js_nv_i(jsp, jo2p, "i", value);
            if (hex_haj && jsp->pr_hex) {
                snprintf(b, blen, "%" PRIx64, value);
                sgj_js_nv_s(jsp, jo2p, "hex", b);
            }
        }
        return jo2p;
    }
    return NULL;
}

/* Convert a byte stream that is meant to be printable ASCII or UTF-8 to
 * something that is allowable in a JSON string. This means treating the
 * ASCII control characters (i.e. < 0x20) and DEL as specials. Also '\' and
 * '"' need to be escaped with a preceding '\'. These C escape codes are used
 * in JSON: '\b', '\f', '\n', '\r' and '\t'. Other control characters, and DEL
 * are encoded as '\x<hh>' where <hh> is two hex digits. So the DEL and
 * null ACSII characters in the input will appear as '\x7f' and '\x00'
 * respectively in the output. The output serializer will expand those
 * two to '\\x7f' and '\\x00'. Note that the JSON form of '\u<hhhh>' is
 * _not_ used. The input is pointed to by 'cup' which is 'ulen' bytes long.
 * The output is written to 'op' and will not exceed 'olen_max' bytes. If
 * 'olen_max' is breached, this function returns -1 else it returns the
 * number of bytes written to 'op'. */
int
sgj_conv2json_string(const uint8_t * cup, int ulen, char * op, int olen_max)
{
    int k, j;

    for (k = 0, j = 0; k < ulen; k++) {
        uint8_t u = cup[k];

        /* Treat DEL [0x7f] as non-printable, output: "\\x7f" */
        if ((u >= 0x20) && (u != 0x7f)) {
            if (j + 1 >= olen_max)
                return -1;
            op[j++] = u;
        } else {
            uint8_t u2 = 0;

            switch (u) {
            case '"': case '\\': u2 = u; break;
            case '\b': u2 = 'b'; break;
            case '\f': u2 = 'f'; break;
            case '\n': u2 = 'n'; break;
            case '\r': u2 = 'r'; break;
            case '\t': u2 = 't'; break;
            }
            if (u2) {
                /* the escaping of these is handled by the json_builder's
                 * output serializer. */
                if (j + 1 >= olen_max)
                    return -1;
                op[j++] = u;    /* not using u2, only that it is != 0 */
            } else {
                char b[8];

                if (snprintf(b, sizeof(b), "\\x%02x", u) != 4 ||
                    j + 4 >= olen_max)
                    return -1;
                memcpy(op + j, b, 4);
                j += 4;
            }
        }
    }
    return j;
}


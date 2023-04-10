// SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause)
/*
 * Simple streaming JSON writer
 *
 * This takes care of the annoying bits of JSON syntax like the commas
 * after elements
 *
 * Authors:     Stephen Hemminger <stephen@networkplumber.org>
 *
 * Borrowed from Linux kernel [5.17.0]: tools/bpf/bpftool/json_writer.[hc]
 */

#include <stdio.h>
#include <stdbool.h>
#include <stdarg.h>
#include <assert.h>
#include <malloc.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <getopt.h>
#include <errno.h>

#include "../lib/sg_json_builder.h"
#include "sg_lib.h"
#include "sg_pr2serr.h"

#define MY_NAME "sg_tst_json_builder"

static const char * version_str = "1.02 20230408";


static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"json", optional_argument, 0, 'j'},
        {"js-file", required_argument, 0, 'J'},
        {"js_file", required_argument, 0, 'J'},
        {"verbose", no_argument, 0, 'v'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
};

static  json_serialize_opts out_settings = {
    json_serialize_mode_multiline,
    0,
    4
};


static void
usage()
{
    pr2serr("Usage: sg_tst_json_builder  [--help] [--json[=JO]] "
            "[--js-file=JFN]\n"
            "                            [--verbose] [--version] [DEVICE]\n"
            "  where:\n"
            "    --help|-h         print out usage message\n"
            "    --json[=JO]|-j[JO]     output in JSON instead of human "
            "readable text\n"
            "                           use --json=? for JSON help\n"
            "    --js-file=JFN|-J JFN    JFN is a filename to which JSON "
            "output is\n"
            "                            written (def: stdout); truncates "
            "then writes\n"
            "    --verbose|-v      increase verbosity\n"
            "    --version|-V      print version string and exit\n\n"
            "Test json functions declared in include/sg_pr2serr.h .\n"
            );
}


int
main(int argc, char * argv[])
{
    bool do_json = false;
    bool verbose_given = false;
    bool version_given = false;
    int c;
    int verbose = 0;
    int ret = 0;
    size_t len;
    sgj_state jstate;
    sgj_state * jstp = &jstate;
    json_value * jv1p;
    json_value * jv2p;
    json_value * jv3p = json_object_new(0);
    json_value * jvp = NULL;
    json_value * jv4p;
    json_value * jv5p;
    json_value * ja1p = json_array_new(0);
    json_value * ja2p;
    json_value * jsp = json_string_new("hello world 1");
    json_value * js2p = json_string_new("hello world 2");
    json_value * js3p = json_string_new("hello world 3");
    json_value * js10 = json_string_new("good-bye world");
    json_value * js11 = json_string_new("good-bye world 2");
    json_value * js12 = json_string_new("duplicate name 1");
    const char * device_name = NULL;
    const char * json_arg = NULL;
    const char * js_file = NULL;
    char b[8192];

// xxxxx
    sgj_init_state(jstp, NULL);
    if (getenv("SG3_UTILS_INVOCATION"))
        sg_rep_invocation(MY_NAME, version_str, argc, argv, stderr);
    while (1) {
        int option_index = 0;

        c = getopt_long(argc, argv, "hj::J:vV", long_options, &option_index);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
        case '?':
            usage();
            return 0;
        case 'j':
            do_json = true;
            json_arg = optarg;
            break;
        case 'J':
            do_json = true;
            js_file = optarg;
            break;
                case 'v':
            verbose_given = true;
            ++verbose;
            break;
        case 'V':
            version_given = true;
            break;
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

    if (device_name)
        pr2serr("argument %s (a device node?) ignored\n\n", device_name);
    if (version_given) {
        pr2serr("version: %s\n", version_str);
        return 0;
    }
    jvp = sgj_start_r(MY_NAME, version_str, argc, argv, jstp);
    jv1p = json_object_push(jvp, "contents", jsp);

    if (jvp == jv1p)
        printf("jvp == jv1p\n");
    else
        printf("jvp != jv1p\n");

#if 1
    json_array_push(ja1p, js2p);
    jv2p = json_object_push(jvp, "extra", js3p);
    if (jv2p)
        printf("jv2p->type=%d\n", jv2p->type);
    else
        printf("jv2p is NULL\n");
    ja2p = json_array_push(ja1p, json_string_new(
                "test double quote, etc: \" world \\ 99\t\ttwo tabs"));
    if (ja2p)
        printf("ja2p->type=%d\n", ja2p->type);
    else
        printf("ja2p is NULL\n");
    // json_object_push(ja2p, "boo", json_string_new("hello world 88"));
    json_object_push(jvp, "a_array", ja1p);
    jv4p = json_object_push(jvp, "a_object", jv3p);
    if (jv4p)
        printf("jv4p->type=%d\n", jv4p->type);
    else
        printf("jv4p is NULL\n");
    json_object_push(jv4p, "test", js10);
    json_object_push(jv4p, "test2", js11);
    json_object_push(jv4p, "test", js12);
    // ja3p = json_array_push(ja2p, json_string_new("good-bye"));
    // jv4p = json_object_push(jvp, "a_array", ja2p);
    // jv5p = json_object_merge(jvp, ja1p);
#endif
    jv5p = jvp;

    len = json_measure_ex(jv5p, out_settings);
    printf("jvp length: %zu bytes\n", len);
    if (len < sizeof(b)) {
        json_serialize_ex(b, jv5p, out_settings);
        printf("json serialized:\n");
        printf("%s\n", b);
    } else
        printf("since json output length [%zu] > 8192, skip outputting\n",
               len);

    json_builder_free(jvp);
    printf("\nNow test using sgj_* interface in sg_pr2serr.h\n");
    {
        sgj_state a_js;
        sgj_state * jsp = &a_js;
        sgj_opaque_p jop = NULL;
        sgj_opaque_p jo2p = NULL;
        sgj_opaque_p jap = NULL;
        FILE * fp = stdout;

        if (verbose_given)
            pr2serr("do_json=%d\n", do_json);
        if (! sgj_init_state(jsp, json_arg)) {
            int bad_char = jsp->first_bad_char;
            char e[1500];

            pr2serr("sgj_init_state() returned false\n");

            if (bad_char) {
                pr2serr("bad argument to --json= option, unrecognized "
                        "character '%c'\n\n", bad_char);
            }
            sg_json_usage(0, e, sizeof(e));
            pr2serr("%s", e);
            return 1;
        }
        jop = sgj_start_r(MY_NAME, version_str, argc, argv, jsp);

        jap = sgj_named_subarray_r(jsp, jop, "mixed_array");
        sgj_js_nv_o(jsp, jap, NULL /* no name so adding to array */,
                    sgj_new_unattached_string_r(jsp, "a string"));
        sgj_js_nv_o(jsp, jap, NULL,
                    sgj_new_unattached_str_len_r(jsp,
                        "a 13 byte string", 13));
        sgj_js_nv_o(jsp, jap, NULL, sgj_new_unattached_null_r(jsp));
        sgj_js_nv_o(jsp, jap, NULL,
                    sgj_new_unattached_integer_r(jsp, 9876));
        sgj_js_nv_o(jsp, jap, NULL,
                    sgj_new_unattached_bool_r(jsp, true));

        jo2p = sgj_named_subobject_r(jsp, jop, "named_subobject");
        sgj_js_nv_i(jsp, jo2p, "a_numeric_value", 1234);
        sgj_js_nv_s(jsp, jo2p,
                    "next_explained", "hex shown if '--json=h' given "
                    "command line");
        sgj_js_nv_ihex(jsp, jo2p, "a_numeric_value_optionally_with_hex",
                       2468);
        sgj_js_nv_s_nex(jsp, jo2p, "kernel_node_name", "/dev/sda",
                        "kernel name before udev or user changed it");
        /* add more tests here <<<<<<<<<             xxxxxxxxxxxxxxxxx */

        if (js_file) {
            if ((1 != strlen(js_file)) || ('-' != js_file[0])) {
                fp = fopen(js_file, "w");   /* truncate if exists */
                if (NULL == fp) {
                    int e = errno;

                    pr2serr("unable to open file: %s [%s]\n", js_file,
                            safe_strerror(e));
                    ret = sg_convert_errno(e);
                }
            }
            /* '--js-file=-' will send JSON output to stdout */
        }
        if (fp)
            sgj_js2file(jsp, NULL, ret, fp);
        if (js_file && fp && (stdout != fp))
            fclose(fp);
        sgj_finish(jsp);
    }


    return ret;
}


#if 0
int main(int argc, char **argv)
{
        json_writer_t *wr = jsonw_new(stdout);

        jsonw_start_object(wr);
        jsonw_pretty(wr, true);
        jsonw_name(wr, "Vyatta");
        jsonw_start_object(wr);
        jsonw_string_field(wr, "url", "http://vyatta.com");
        jsonw_uint_field(wr, "downloads", 2000000ul);
        jsonw_float_field(wr, "stock", 8.16);

        jsonw_name(wr, "ARGV");
        jsonw_start_array(wr);
        while (--argc)
                jsonw_string(wr, *++argv);
        jsonw_end_array(wr);

        jsonw_name(wr, "empty");
        jsonw_start_array(wr);
        jsonw_end_array(wr);

        jsonw_name(wr, "NIL");
        jsonw_start_object(wr);
        jsonw_end_object(wr);

        jsonw_null_field(wr, "my_null");

        jsonw_name(wr, "special chars");
        jsonw_start_array(wr);
        jsonw_string_field(wr, "slash", "/");
        jsonw_string_field(wr, "newline", "\n");
        jsonw_string_field(wr, "tab", "\t");
        jsonw_string_field(wr, "ff", "\f");
        jsonw_string_field(wr, "quote", "\"");
        jsonw_string_field(wr, "tick", "\'");
        jsonw_string_field(wr, "backslash", "\\");
        jsonw_end_array(wr);

jsonw_name(wr, "ARGV");
jsonw_start_array(wr);
jsonw_string(wr, "boo: appended or new entry?");
jsonw_end_array(wr);

        jsonw_end_object(wr);

        jsonw_end_object(wr);
        jsonw_destroy(&wr);
        return 0;
}

#endif

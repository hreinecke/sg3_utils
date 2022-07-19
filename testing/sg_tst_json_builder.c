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
#include <stdint.h>

#include "../lib/sg_json_builder.h"
#include "sg_pr2serr.h"

#define MY_NAME "sg_tst_json_builder"


static  json_serialize_opts out_settings = {
    json_serialize_mode_multiline,
    0,
    4
};

int
main(int argc, char * argv[])
{
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
    char b[8192];

    sgj_init_state(jstp, NULL);
    jvp = sgj_start_r(MY_NAME, "0.02 20220503", argc, argv, jstp);
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
    return 0;
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

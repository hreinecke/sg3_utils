// SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause)
/*
 * Simple streaming JSON writer
 *
 * This takes care of the annoying bits of JSON syntax like the commas
 * after elements
 *
 * Authors:	Stephen Hemminger <stephen@networkplumber.org>
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


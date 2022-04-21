
/* vim: set et ts=3 sw=3 sts=3 ft=c:
 *
 * Copyright (C) 2014 James McLaughlin.  All rights reserved.
 * https://github.com/udp/json-builder
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in the
 *   documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef SG_JSON_BUILDER_H
#define SG_JSON_BUILDER_H

/* This code was fetched from https://github.com/json-parser/json-builder
 * and comes with the 2 clause BSD license (shown above) which is the same
 * license that most of the rest of this package uses.
 *
 * This header file is in this 'lib' directory so its interface is _not_
 * published with sg3_utils other header files found in the 'include'
 * directory. Currently only this header's implementation (i.e.
 * sg_json_builder.c) and sg_pr2serr.c are the only users of this header. */

/*
 * Used to require json.h from json-parser but what was needed as been
 * included in this header.
 * https://github.com/udp/json-parser
 */
/* #include "json.h" */

#ifndef json_char
   #define json_char char
#endif

#ifndef json_int_t
   #undef JSON_INT_T_OVERRIDDEN
   #if defined(_MSC_VER)
      #define json_int_t __int64
   #elif (defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L) || (defined(__cplusplus) && __cplusplus >= 201103L)
      /* C99 and C++11 */
      #include <stdint.h>
      #define json_int_t int_fast64_t
   #else
      /* C89 */
      #define json_int_t long
   #endif
#else
   #define JSON_INT_T_OVERRIDDEN 1
#endif

#include <stddef.h>

#ifdef __cplusplus

   #include <string.h>

   extern "C"
   {

#endif

typedef struct
{
   unsigned long max_memory;  /* should be size_t, but would modify the API */
   int settings;

   /* Custom allocator support (leave null to use malloc/free)
    */

   void * (* mem_alloc) (size_t, int zero, void * user_data);
   void (* mem_free) (void *, void * user_data);

   void * user_data;  /* will be passed to mem_alloc and mem_free */

   size_t value_extra;  /* how much extra space to allocate for values? */

} json_settings;

#define json_enable_comments  0x01

typedef enum
{
   json_none,
   json_object,
   json_array,
   json_integer,
   json_double,
   json_string,
   json_boolean,
   json_null

} json_type;

extern const struct _json_value json_value_none;

typedef struct _json_object_entry
{
    json_char * name;
    unsigned int name_length;

    struct _json_value * value;

} json_object_entry;

typedef struct _json_value
{
   struct _json_value * parent;

   json_type type;

   union
   {
      int boolean;
      json_int_t integer;
      double dbl;

      struct
      {
         unsigned int length;
         json_char * ptr; /* null terminated */

      } string;

      struct
      {
         unsigned int length;

         json_object_entry * values;

         #if defined(__cplusplus)
         json_object_entry * begin () const
         {  return values;
         }
         json_object_entry * end () const
         {  return values + length;
         }
         #endif

      } object;

      struct
      {
         unsigned int length;
         struct _json_value ** values;

         #if defined(__cplusplus)
         _json_value ** begin () const
         {  return values;
         }
         _json_value ** end () const
         {  return values + length;
         }
         #endif

      } array;

   } u;

   union
   {
      struct _json_value * next_alloc;
      void * object_mem;

   } _reserved;

   #ifdef JSON_TRACK_SOURCE

      /* Location of the value in the source JSON
       */
      unsigned int line, col;

   #endif


   /* C++ operator sugar removed */

} json_value;

#if 0
#define json_error_max 128
json_value * json_parse_ex (json_settings * settings,
                            const json_char * json,
                            size_t length,
                            char * error);

void json_value_free (json_value *);


/* Not usually necessary, unless you used a custom mem_alloc and now want to
 * use a custom mem_free.
 */
void json_value_free_ex (json_settings * settings,
                         json_value *);
#endif

/* <<< end of code from json-parser's json.h >>> */


/* IMPORTANT NOTE:  If you want to use json-builder functions with values
 * allocated by json-parser as part of the parsing process, you must pass
 * json_builder_extra as the value_extra setting in json_settings when
 * parsing.  Otherwise there will not be room for the extra state and
 * json-builder WILL invoke undefined behaviour.
 *
 * Also note that unlike json-parser, json-builder does not currently support
 * custom allocators (for no particular reason other than that it doesn't have
 * any settings or global state.)
 */
extern const size_t json_builder_extra;


/*** Arrays
 ***
 * Note that all of these length arguments are just a hint to allow for
 * pre-allocation - passing 0 is fine.
 */
json_value * json_array_new (size_t length);
json_value * json_array_push (json_value * array, json_value *);


/*** Objects
 ***/
json_value * json_object_new (size_t length);

json_value * json_object_push (json_value * object,
                               const json_char * name,
                               json_value *);

/* Same as json_object_push, but doesn't call strlen() for you.
 */
json_value * json_object_push_length (json_value * object,
                                      unsigned int name_length, const json_char * name,
                                      json_value *);

/* Same as json_object_push_length, but doesn't copy the name buffer before
 * storing it in the value.  Use this micro-optimisation at your own risk.
 */
json_value * json_object_push_nocopy (json_value * object,
                                      unsigned int name_length, json_char * name,
                                      json_value *);

/* Merges all entries from objectB into objectA and destroys objectB.
 */
json_value * json_object_merge (json_value * objectA, json_value * objectB);

/* Sort the entries of an object based on the order in a prototype object.
 * Helpful when reading JSON and writing it again to preserve user order.
 */
void json_object_sort (json_value * object, json_value * proto);



/*** Strings
 ***/
json_value * json_string_new (const json_char *);
json_value * json_string_new_length (unsigned int length, const json_char *);
json_value * json_string_new_nocopy (unsigned int length, json_char *);


/*** Everything else
 ***/
json_value * json_integer_new (json_int_t);
json_value * json_double_new (double);
json_value * json_boolean_new (int);
json_value * json_null_new (void);


/*** Serializing
 ***/
#define json_serialize_mode_multiline     0
#define json_serialize_mode_single_line   1
#define json_serialize_mode_packed        2

#define json_serialize_opt_CRLF                    (1 << 1)
#define json_serialize_opt_pack_brackets           (1 << 2)
#define json_serialize_opt_no_space_after_comma    (1 << 3)
#define json_serialize_opt_no_space_after_colon    (1 << 4)
#define json_serialize_opt_use_tabs                (1 << 5)

typedef struct json_serialize_opts
{
   int mode;
   int opts;
   int indent_size;

} json_serialize_opts;


/* Returns a length in characters that is at least large enough to hold the
 * value in its serialized form, including a null terminator.
 */
size_t json_measure (json_value *);
size_t json_measure_ex (json_value *, json_serialize_opts);


/* Serializes a JSON value into the buffer given (which must already be
 * allocated with a length of at least json_measure(value, opts))
 */
void json_serialize (json_char * buf, json_value *);
void json_serialize_ex (json_char * buf, json_value *, json_serialize_opts);


/*** Cleaning up
 ***/
void json_builder_free (json_value *);

#ifdef __cplusplus
}
#endif

#endif		/* SG_JSON_BUILDER_H */




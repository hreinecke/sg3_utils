#ifndef SG_LIB_H
#define SG_LIB_H

/*
 * Copyright (c) 2004-2005 Douglas Gilbert.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
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
 *
 */

/* Version 1.09 [20050504]
 *
 * On 5th October 2004 a FreeBSD license was added to this file.
 * The intention is to keep this file and the related sg_lib.c file
 * as open source and encourage their unencumbered use.
 */


/* This header file contains defines and function declarations that may
 * be useful to Linux applications that communicate with devices that
 * use a SCSI command set. These command sets have names like SPC-3, SBC-2,
 * SSC-2, SES-2 and draft standards defining them can be found at
 * http://www.t10.org . Virtually all devices in the Linux SCSI subsystem
 * utilize SCSI command sets. Many devices in other Linux device subsystems
 * utilize SCSI command sets either natively or via emulation (e.g. a
 * parallel ATA disk in a USB enclosure). Some defines found in the Linux
 * kernel source directory include/scsi (mainly in the scsi.h header)
 * are replicated here.
 * This header is organised into two parts: part 1 is operating system
 * independent (i.e. may be useful to other OSes) and part 2 is Linux
 * specific (or at least closely related).
 */


/*
 * PART 1: OPERATING SYSTEM INDEPENDENT SECTION
 *         ------------------------------------
 */

#ifndef SCSI_CHECK_CONDITION
/* Following are the SCSI status codes as found in SAM-3 at www.t10.org . */
#define SCSI_CHECK_CONDITION 0x2
#define SCSI_CONDITION_MET 0x4
#define SCSI_BUSY 0x8
#define SCSI_IMMEDIATE 0x10
#define SCSI_IMMEDIATE_CONDITION_MET 0x14
#define SCSI_RESERVATION_CONFLICT 0x18
#define SCSI_COMMAND_TERMINATED 0x22    /* obsolete since SAM-2 */
#define SCSI_TASK_SET_FULL 0x28
#define SCSI_ACA_ACTIVE 0x30
#define SCSI_TASK_ABORTED 0x40
#endif


/* Returns length of SCSI command given the opcode (first byte). 
   Yields the wrong answer for variable length commands (opcode=0x7f)
   and potentially some vendor specific commands. */
extern int sg_get_command_size(unsigned char cdb_byte0);

/* Command name given pointer to the cdb. Certain command names
   depend on peripheral type (give 0 if unknown). Places command
   name into buff and will write no more than buff_len bytes. */
extern void sg_get_command_name(const unsigned char * cdbp, int peri_type,
                                int buff_len, char * buff);

/* Command name given only the first byte (byte 0) of a cdb and
 * peripheral type. */
extern void sg_get_opcode_name(unsigned char cdb_byte0, int peri_type,
                               int buff_len, char * buff);

/* Command name given opcode (byte 0), service action and peripheral type.
   If no service action give 0, if unknown peripheral type give 0. */
extern void sg_get_opcode_sa_name(unsigned char cdb_byte0, int service_action,
                                  int peri_type, int buff_len, char * buff);

/* This is a slightly stretched SCSI sense "descriptor" format header.
   The addition is to allow the 0x70 and 0x71 response codes. The idea
   is to place the salient data of both "fixed" and "descriptor" sense
   format into one structure to ease application processing.
   The original sense buffer should be kept around for those cases
   in which more information is required (e.g. the LBA of a MEDIUM ERROR). */
struct sg_scsi_sense_hdr {
    unsigned char response_code; /* permit: 0x0, 0x70, 0x71, 0x72, 0x73 */
    unsigned char sense_key;
    unsigned char asc;
    unsigned char ascq;
    unsigned char byte4;
    unsigned char byte5;
    unsigned char byte6;
    unsigned char additional_length;
};

/* Maps the salient data from a sense buffer which is in either fixed or
   descriptor format into a structure mimicking a descriptor format
   header (i.e. the first 8 bytes of sense descriptor format).
   If zero response code returns 0. Otherwise returns 1 and if 'sshp' is
   non-NULL then zero all fields and then set the appropriate fields in
   that structure. sshp::additional_length is always 0 for response
   codes 0x70 and 0x71 (fixed format). */
extern int sg_scsi_normalize_sense(const unsigned char * sensep, 
                                   int sense_len,
                                   struct sg_scsi_sense_hdr * sshp);

/* Attempt to find the first SCSI sense data descriptor that matches the
   given 'desc_type'. If found return pointer to start of sense data
   descriptor; otherwise (including fixed format sense data) returns NULL. */
extern const unsigned char * sg_scsi_sense_desc_find(
                const unsigned char * sensep, int sense_len, int desc_type);

/* Yield string associated with sense_key value. Returns 'buff'. */
extern char * sg_get_sense_key_str(int sense_key,int buff_len, char * buff);

/* Yield string associated with ASC/ASCQ values. Returns 'buff'. */
extern char * sg_get_asc_ascq_str(int asc, int ascq, int buff_len,
                                  char * buff);

/* Returns 1 if valid bit set, 0 if valid bit clear. Irrespective the
   information field is written out via 'info_outp' (except when it is
   NULL). Handles both fixed and descriptor sense formats. */
extern int sg_get_sense_info_fld(const unsigned char * sensep, int sb_len,
                                 unsigned long long * info_outp);

/* Returns 1 if sense key is NO_SENSE or NOT_READY and SKSV is set. Places
   progress field from sense data where progress_outp points. If progress
   field is not available returns 0. Handles both fixed and descriptor
   sense formats. N.B. App should multiply by 100 and divide by 65536
   to get percentage completion from given value. */
extern int sg_get_sense_progress_fld(const unsigned char * sensep,
                                     int sb_len, int * progress_outp);


/* <<< General purpose (i.e. not SCSI specific) utility functions >>> */

/* Always returns valid string even if errnum is wild (or library problem) */
extern char * safe_strerror(int errnum);


/* Print (to stdout) 'str' of bytes in hex, 16 bytes per line optionally
   followed at the right hand side of the line with an ASCII interpretation.
   Each line is prefixed with an address, starting at 0 for str[0]..str[15].
   All output numbers are in hex. 'no_ascii' allows for 3 output types:
       > 0     each line has address then up to 16 ASCII-hex bytes
       = 0     in addition, the bytes are listed in ASCII to the right
       < 0     only the ASCII-hex bytes are listed (i.e. without address)
*/
extern void dStrHex(const char* str, int len, int no_ascii);

/* If the number in 'buf' can not be decoded or the multiplier is unknown
   then -1 is returned. Accepts a hex prefix (0x or 0X) or a decimal
   multiplier suffix (not both). Recognised multipliers: c C  *1;  w W  *2;
   b  B *512;  k K KiB  *1,024;  KB  *1,000;  m M MiB  *1,048,576;
   MB *1,000,000; g G GiB *1,073,741,824;  GB *1,000,000,000 and x<m>
   which multiplies the leading number by <n> . */
extern int sg_get_num(const char * buf);

/* If the number in 'buf' can not be decoded or the multiplier is unknown
   then -1LL is returned. Accepts a hex prefix (0x or 0X) or a decimal
   multiplier suffix (not both). In addition to supporting the multipliers
   of sg_get_num(), this function supports: t T TiB  *(2**40); TB *(10**12);
   p P PiB  *(2**50); PB  *(10**15) . */
extern long long sg_get_llnum(const char * buf);

extern const char * sg_lib_version();



/*
 * PART 2: LINUX SPECIFIC SECTION
 *         ----------------------
 */

/* The following are 'host_status' codes */
#ifndef DID_OK
#define DID_OK 0x00
#endif
#ifndef DID_NO_CONNECT
#define DID_NO_CONNECT 0x01     /* Unable to connect before timeout */
#define DID_BUS_BUSY 0x02       /* Bus remain busy until timeout */
#define DID_TIME_OUT 0x03       /* Timed out for some other reason */
#define DID_BAD_TARGET 0x04     /* Bad target (id?) */
#define DID_ABORT 0x05          /* Told to abort for some other reason */
#define DID_PARITY 0x06         /* Parity error (on SCSI bus) */
#define DID_ERROR 0x07          /* Internal error */
#define DID_RESET 0x08          /* Reset by somebody */
#define DID_BAD_INTR 0x09       /* Received an unexpected interrupt */
#define DID_PASSTHROUGH 0x0a    /* Force command past mid-level */
#define DID_SOFT_ERROR 0x0b     /* The low-level driver wants a retry */
#endif
#ifndef DID_IMM_RETRY
#define DID_IMM_RETRY 0x0c      /* Retry without decrementing retry count  */
#endif
#ifndef DID_REQUEUE
#define DID_REQUEUE 0x0d        /* Requeue command (no immediate retry) also
                                 * without decrementing the retry count    */
#endif

/* These defines are to isolate applictaions from kernel define changes */
#define SG_LIB_DID_OK           DID_OK
#define SG_LIB_DID_NO_CONNECT   DID_NO_CONNECT
#define SG_LIB_DID_BUS_BUSY     DID_BUS_BUSY
#define SG_LIB_DID_TIME_OUT     DID_TIME_OUT
#define SG_LIB_DID_BAD_TARGET   DID_BAD_TARGET
#define SG_LIB_DID_ABORT        DID_ABORT
#define SG_LIB_DID_PARITY       DID_PARITY
#define SG_LIB_DID_ERROR        DID_ERROR
#define SG_LIB_DID_RESET        DID_RESET
#define SG_LIB_DID_BAD_INTR     DID_BAD_INTR
#define SG_LIB_DID_PASSTHROUGH  DID_PASSTHROUGH
#define SG_LIB_DID_SOFT_ERROR   DID_SOFT_ERROR
#define SG_LIB_DID_IMM_RETRY    DID_IMM_RETRY
#define SG_LIB_DID_REQUEUE      DID_REQUEUE

/* The following are 'driver_status' codes */
#ifndef DRIVER_OK
#define DRIVER_OK 0x00
#endif
#ifndef DRIVER_BUSY
#define DRIVER_BUSY 0x01
#define DRIVER_SOFT 0x02
#define DRIVER_MEDIA 0x03
#define DRIVER_ERROR 0x04
#define DRIVER_INVALID 0x05
#define DRIVER_TIMEOUT 0x06
#define DRIVER_HARD 0x07
#define DRIVER_SENSE 0x08       /* Sense_buffer has been set */

/* Following "suggests" are "or-ed" with one of previous 8 entries */
#define SUGGEST_RETRY 0x10
#define SUGGEST_ABORT 0x20
#define SUGGEST_REMAP 0x30
#define SUGGEST_DIE 0x40
#define SUGGEST_SENSE 0x80
#define SUGGEST_IS_OK 0xff
#endif
#ifndef DRIVER_MASK
#define DRIVER_MASK 0x0f
#endif
#ifndef SUGGEST_MASK
#define SUGGEST_MASK 0xf0
#endif

/* These defines are to isolate applictaions from kernel define changes */
#define SG_LIB_DRIVER_OK        DRIVER_OK
#define SG_LIB_DRIVER_BUSY      DRIVER_BUSY
#define SG_LIB_DRIVER_SOFT      DRIVER_SOFT
#define SG_LIB_DRIVER_MEDIA     DRIVER_MEDIA
#define SG_LIB_DRIVER_ERROR     DRIVER_ERROR
#define SG_LIB_DRIVER_INVALID   DRIVER_INVALID
#define SG_LIB_DRIVER_TIMEOUT   DRIVER_TIMEOUT
#define SG_LIB_DRIVER_HARD      DRIVER_HARD
#define SG_LIB_DRIVER_SENSE     DRIVER_SENSE
#define SG_LIB_SUGGEST_RETRY    SUGGEST_RETRY
#define SG_LIB_SUGGEST_ABORT    SUGGEST_ABORT
#define SG_LIB_SUGGEST_REMAP    SUGGEST_REMAP
#define SG_LIB_SUGGEST_DIE      SUGGEST_DIE
#define SG_LIB_SUGGEST_SENSE    SUGGEST_SENSE
#define SG_LIB_SUGGEST_IS_OK    SUGGEST_IS_OK
#define SG_LIB_DRIVER_MASK      DRIVER_MASK
#define SG_LIB_SUGGEST_MASK     SUGGEST_MASK


extern FILE * sg_warnings_str;

extern void sg_set_warnings_str(FILE * warnings_str);

/* The following "print" functions send ACSII to 'sg_warnings_fd' file
   descriptor (default value is stderr) */
extern void sg_print_command(const unsigned char * command);
extern void sg_print_sense(const char * leadin,
                           const unsigned char * sense_buffer, int sb_len);
extern void sg_print_status(int masked_status);
extern void sg_print_scsi_status(int scsi_status);
extern void sg_print_host_status(int host_status);
extern void sg_print_driver_status(int driver_status);

/* sg_chk_n_print() returns 1 quietly if there are no errors/warnings
   else it prints errors/warnings (prefixed by 'leadin') to
   'sg_warnings_fd' and returns 0. */
extern int sg_chk_n_print(const char * leadin, int masked_status,
                          int host_status, int driver_status,
                          const unsigned char * sense_buffer, int sb_len);

/* The following function declaration is for the sg version 3 driver. */
struct sg_io_hdr;
/* sg_chk_n_print3() returns 1 quietly if there are no errors/warnings;
   else it prints errors/warnings (prefixed by 'leadin') to
   'sg_warnings_fd' and returns 0. */
extern int sg_chk_n_print3(const char * leadin, struct sg_io_hdr * hp);

/* Calls sg_scsi_normalize_sense() after obtaining the sense buffer and
   its length from the struct sg_io_hdr pointer. If these cannot be
   obtained, 0 is returned. */
extern int sg_normalize_sense(const struct sg_io_hdr * hp, 
                              struct sg_scsi_sense_hdr * sshp);


/* The following "category" function returns one of the following */
#define SG_LIB_CAT_CLEAN 0      /* No errors or other information */
#define SG_LIB_CAT_MEDIA_CHANGED 1 /* interpreted from sense buffer */
                                /*       [sk,asc,ascq: 0x6,0x28,*] */
#define SG_LIB_CAT_RESET 2      /* interpreted from sense buffer */
                                /*       [sk,asc,ascq: 0x6,0x29,*] */
#define SG_LIB_CAT_TIMEOUT 3
#define SG_LIB_CAT_RECOVERED 4  /* Successful command after recovered err */
                                /*       [sk,asc,ascq: 0x1,*,*] */
#define SG_LIB_CAT_INVALID_OP 5 /* Invalid operation code: */
                                /*       [sk,asc,ascq: 0x5,0x20,0x0] */
#define SG_LIB_CAT_MEDIUM_HARD 6 /* medium or hardware error sense key */
                                /*       [sk,asc,ascq: 0x3/0x4,*,*] */
#define SG_LIB_CAT_ILLEGAL_REQ 7 /* Illegal request (other than invalid */
                                 /* opcode):   [sk,asc,ascq: 0x5,*,*] */
#define SG_LIB_CAT_SENSE 98     /* Something else is in the sense buffer */
#define SG_LIB_CAT_OTHER 99     /* Some other error/warning has occurred */

extern int sg_err_category(int masked_status, int host_status,
               int driver_status, const unsigned char * sense_buffer,
               int sb_len);

extern int sg_err_category_new(int scsi_status, int host_status,
               int driver_status, const unsigned char * sense_buffer,
               int sb_len);

/* The following function declaration is for the sg version 3 driver. */
extern int sg_err_category3(struct sg_io_hdr * hp);


/* Note about SCSI status codes found in older versions of Linux.
   Linux has traditionally used a 1 bit right shifted and masked 
   version of SCSI standard status codes. Now CHECK_CONDITION
   and friends (in <scsi/scsi.h>) are deprecated. */

#endif

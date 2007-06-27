#ifndef SG_ERR_H
#define SG_ERR_H

/* Feel free to copy and modify this GPL-ed code into your applications. */

/* Version 0.97 (20040830) 
*/


/* Some of the following error/status codes are exchanged between the
   various layers of the SCSI sub-system in Linux and should never
   reach the user. They are placed here for completeness. What appears
   here is copied from drivers/scsi/scsi.h which is not visible in
   the user space. */

#ifndef SCSI_CHECK_CONDITION
/* Following are the "true" SCSI status codes. Linux has traditionally
   used a 1 bit right and masked version of these. So now CHECK_CONDITION
   and friends (in <scsi/scsi.h>) are deprecated. */
#define SCSI_CHECK_CONDITION 0x2
#define SCSI_CONDITION_MET 0x4
#define SCSI_BUSY 0x8
#define SCSI_IMMEDIATE 0x10
#define SCSI_IMMEDIATE_CONDITION_MET 0x14
#define SCSI_RESERVATION_CONFLICT 0x18
#define SCSI_COMMAND_TERMINATED 0x22
#define SCSI_TASK_SET_FULL 0x28
#define SCSI_ACA_ACTIVE 0x30
#define SCSI_TASK_ABORTED 0x40
#endif

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

/* These defines are to isolate applictaions from kernel define changes */
#define SG_ERR_DID_OK           DID_OK
#define SG_ERR_DID_NO_CONNECT   DID_NO_CONNECT
#define SG_ERR_DID_BUS_BUSY     DID_BUS_BUSY
#define SG_ERR_DID_TIME_OUT     DID_TIME_OUT
#define SG_ERR_DID_BAD_TARGET   DID_BAD_TARGET
#define SG_ERR_DID_ABORT        DID_ABORT
#define SG_ERR_DID_PARITY       DID_PARITY
#define SG_ERR_DID_ERROR        DID_ERROR
#define SG_ERR_DID_RESET        DID_RESET
#define SG_ERR_DID_BAD_INTR     DID_BAD_INTR
#define SG_ERR_DID_PASSTHROUGH  DID_PASSTHROUGH
#define SG_ERR_DID_SOFT_ERROR   DID_SOFT_ERROR

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
#define SG_ERR_DRIVER_OK        DRIVER_OK
#define SG_ERR_DRIVER_BUSY      DRIVER_BUSY
#define SG_ERR_DRIVER_SOFT      DRIVER_SOFT
#define SG_ERR_DRIVER_MEDIA     DRIVER_MEDIA
#define SG_ERR_DRIVER_ERROR     DRIVER_ERROR
#define SG_ERR_DRIVER_INVALID   DRIVER_INVALID
#define SG_ERR_DRIVER_TIMEOUT   DRIVER_TIMEOUT
#define SG_ERR_DRIVER_HARD      DRIVER_HARD
#define SG_ERR_DRIVER_SENSE     DRIVER_SENSE
#define SG_ERR_SUGGEST_RETRY    SUGGEST_RETRY
#define SG_ERR_SUGGEST_ABORT    SUGGEST_ABORT
#define SG_ERR_SUGGEST_REMAP    SUGGEST_REMAP
#define SG_ERR_SUGGEST_DIE      SUGGEST_DIE
#define SG_ERR_SUGGEST_SENSE    SUGGEST_SENSE
#define SG_ERR_SUGGEST_IS_OK    SUGGEST_IS_OK
#define SG_ERR_DRIVER_MASK      DRIVER_MASK
#define SG_ERR_SUGGEST_MASK     SUGGEST_MASK



/* The following "print" functions send ACSII to stdout */
extern void sg_print_command(const unsigned char * command);
extern void sg_print_sense(const char * leadin,
                           const unsigned char * sense_buffer, int sb_len);
extern void sg_print_status(int masked_status);
extern void sg_print_scsi_status(int scsi_status);
extern void sg_print_host_status(int host_status);
extern void sg_print_driver_status(int driver_status);

/* sg_chk_n_print() returns 1 quietly if there are no errors/warnings
   else it prints to standard output and returns 0. */
extern int sg_chk_n_print(const char * leadin, int masked_status,
                          int host_status, int driver_status,
                          const unsigned char * sense_buffer, int sb_len);

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
   header (i.e. the first 8 bytes).
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

/* The following function declaration is for the sg version 3 driver. 
   Only version 3 sg_err.c defines it. */
struct sg_io_hdr;
extern int sg_chk_n_print3(const char * leadin, struct sg_io_hdr * hp);

/* Calls sg_scsi_normalize_sense() after obtaining the sense buffer and
   its length from the struct sg_io_hdr pointer. If these cannot be
   obtained, 0 is returned. */
extern int sg_normalize_sense(const struct sg_io_hdr * hp, 
                              struct sg_scsi_sense_hdr * sshp);


/* The following "category" function returns one of the following */
#define SG_ERR_CAT_CLEAN 0      /* No errors or other information */
#define SG_ERR_CAT_MEDIA_CHANGED 1 /* interpreted from sense buffer */
#define SG_ERR_CAT_RESET 2      /* interpreted from sense buffer */
#define SG_ERR_CAT_TIMEOUT 3
#define SG_ERR_CAT_RECOVERED 4  /* Successful command after recovered err */
#define SG_ERR_CAT_SENSE 98     /* Something else is in the sense buffer */
#define SG_ERR_CAT_OTHER 99     /* Some other error/warning has occurred */

extern int sg_err_category(int masked_status, int host_status,
               int driver_status, const unsigned char * sense_buffer,
               int sb_len);

extern int sg_err_category_new(int scsi_status, int host_status,
               int driver_status, const unsigned char * sense_buffer,
               int sb_len);

/* The following function declaration is for the sg version 3 driver. 
   Only version 3 sg_err.c defines it. */
extern int sg_err_category3(struct sg_io_hdr * hp);

/* Returns length of SCSI command given the opcode (first byte). 
   Yields the wrong answer for variable length commands (opcode=0x7f)
   and potentially some vendor specific commands. */
extern int sg_get_command_size(unsigned char opcode);

/* Command name given pointer to command bytes. Certain command names
   depend on the service action within the command as well. */
extern void sg_get_command_name(const unsigned char * cmdp, int peri_type,
                                int buff_len, char * buff);

/* Opcode name given only the first byte (byte 0) of a command */
extern void sg_get_opcode_name(unsigned char cmd_byte0, int peri_type,
                               int buff_len, char * buff);

/* Command name given opcode (byte 0) and service action of a command */
extern void sg_get_opcode_sa_name(unsigned char cmd_byte0, int service_action,
                                  int peri_type, int buff_len, char * buff);


/* <<< General purpose (i.e. not SCSI specific) utility functions >>> */

/* Always returns valid string even if errnum is wild (or library problem) */
extern char * safe_strerror(int errnum);


/* Print (to stdout) 'str' of bytes in hex, 16 bytes per line optionally
   followed at the right hand side of the line with an ASCII interpretation.
   Each line is prefixed with an address, starting at 0 for str[0]..str[15].
   All output numbers are in hex. */
extern void dStrHex(const char* str, int len, int no_ascii);

#endif

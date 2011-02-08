#ifndef SG_PT_H
#define SG_PT_H

/*
 * Copyright (c) 2005-2011 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* This declaration hides the fact that each implementation has its own
 * structure "derived" (using a C++ term) from this one. It compiles
 * because 'struct sg_pt_base' is only referenced (by pointer: 'objp')
 * in this interface. An instance of this structure represents the
 * context of one SCSI command. */
struct sg_pt_base;


/* The format of the version string is like this: "2.01 20090201".
 * The leading digit will be incremented if this interface changes
 * in a way that may impact backward compatibility. */
extern const char * scsi_pt_version();


/* Returns >= 0 if successful. If error in Unix returns negated errno. */
extern int scsi_pt_open_device(const char * device_name, int read_only,
                               int verbose);

/* Similar to scsi_pt_open_device() but takes Unix style open flags OR-ed
 * together. Returns valid file descriptor( >= 0 ) if successful, otherwise
 * returns -1 or a negated errno. */
extern int scsi_pt_open_flags(const char * device_name, int flags,
                                     int verbose);

/* Returns 0 if successful. If error in Unix returns negated errno. */
extern int scsi_pt_close_device(int device_fd);


/* Creates an object that can be used to issue one or more SCSI commands
 * (or task management functions). Returns NULL if problem.
 * Once this object has been created it should be destroyed with
 * destruct_scsi_pt_obj() when it is no longer needed. */
extern struct sg_pt_base * construct_scsi_pt_obj(void);

/* Clear state information held in *objp . This allows this object to be
 * used to issue more than one SCSI command. */
extern void clear_scsi_pt_obj(struct sg_pt_base * objp);

/* Set the CDB (command descriptor block) */
extern void set_scsi_pt_cdb(struct sg_pt_base * objp,
                            const unsigned char * cdb, int cdb_len);
/* Set the sense buffer and the maximum length that it can handle */
extern void set_scsi_pt_sense(struct sg_pt_base * objp, unsigned char * sense,
                              int max_sense_len);
/* Set a pointer and length to be used for data transferred from device */
extern void set_scsi_pt_data_in(struct sg_pt_base * objp,   /* from device */
                                unsigned char * dxferp, int dxfer_len);
/* Set a pointer and length to be used for data transferred to device */
extern void set_scsi_pt_data_out(struct sg_pt_base * objp,    /* to device */
                                 const unsigned char * dxferp, int dxfer_len);
/* The following "set_"s implementations may be dummies */
extern void set_scsi_pt_packet_id(struct sg_pt_base * objp, int pack_id);
extern void set_scsi_pt_tag(struct sg_pt_base * objp, uint64_t tag);
extern void set_scsi_pt_task_management(struct sg_pt_base * objp,
                                        int tmf_code);
extern void set_scsi_pt_task_attr(struct sg_pt_base * objp, int attribute,
                                  int priority);

/* Following is a guard which is defined when set_scsi_pt_flags() is
 * present. Older versions of this library may not have this function. */
#define SCSI_PT_FLAGS_FUNCTION 1
/* If neither QUEUE_AT_HEAD nor QUEUE_AT_TAIL are given, or both
 * are given, use the pass-through default. */
#define SCSI_PT_FLAGS_QUEUE_AT_TAIL 0x10
#define SCSI_PT_FLAGS_QUEUE_AT_HEAD 0x20
/* Set (potentially OS dependant) flags for pass-through mechanism.
 * Apart from contradictions, flags can be OR-ed together. */
extern void set_scsi_pt_flags(struct sg_pt_base * objp, int flags);

#define SCSI_PT_DO_START_OK 0
#define SCSI_PT_DO_BAD_PARAMS 1
#define SCSI_PT_DO_TIMEOUT 2
/* If OS error prior to or during command submission then returns negated
 * error value (e.g. Unix '-errno'). This includes interrupted system calls
 * (e.g. by a signal) in which case -EINTR would be returned. Note that
 * system call errors also can be fetched with get_scsi_pt_os_err().
 * Return 0 if okay (i.e. at the very least: command sent). Positive
 * return values are errors (see SCSI_PT_DO_* defines). */
extern int do_scsi_pt(struct sg_pt_base * objp, int fd, int timeout_secs,
                      int verbose);

#define SCSI_PT_RESULT_GOOD 0
#define SCSI_PT_RESULT_STATUS 1 /* other than GOOD and CHECK CONDITION */
#define SCSI_PT_RESULT_SENSE 2
#define SCSI_PT_RESULT_TRANSPORT_ERR 3
#define SCSI_PT_RESULT_OS_ERR 4
/* highest numbered applicable category returned */
extern int get_scsi_pt_result_category(const struct sg_pt_base * objp);

/* If not available return 0 */
extern int get_scsi_pt_resid(const struct sg_pt_base * objp);
/* Returns SCSI status value (from device that received the
   command). */
extern int get_scsi_pt_status_response(const struct sg_pt_base * objp);
/* Actual sense length returned. If sense data is present but
   actual sense length is not known, return 'max_sense_len' */
extern int get_scsi_pt_sense_len(const struct sg_pt_base * objp);
/* If not available return 0 */
extern int get_scsi_pt_os_err(const struct sg_pt_base * objp);
extern char * get_scsi_pt_os_err_str(const struct sg_pt_base * objp,
                                     int max_b_len, char * b);
/* If not available return 0 */
extern int get_scsi_pt_transport_err(const struct sg_pt_base * objp);
extern char * get_scsi_pt_transport_err_str(const struct sg_pt_base * objp,
                                            int max_b_len, char * b);

/* If not available return -1 */
extern int get_scsi_pt_duration_ms(const struct sg_pt_base * objp);


/* Should be invoked once per objp after other processing is complete in
 * order to clean up resources. For ever successful construct_scsi_pt_obj()
 * call there should be one destruct_scsi_pt_obj().  */
extern void destruct_scsi_pt_obj(struct sg_pt_base * objp);

#ifdef SG_LIB_WIN32
#define SG_LIB_WIN32_DIRECT 1

/* Request SPT direct interface when state_direct is 1, state_direct set
 * to 0 for the SPT indirect interface. Default setting selected by build
 * (i.e. library compile time) and is usually indirect. */
extern void scsi_pt_win32_direct(int state_direct);

/* Returns current SPT interface state, 1 for direct, 0 for indirect */
extern int scsi_pt_win32_spt_state(void);

#endif

#ifdef __cplusplus
}
#endif

#endif

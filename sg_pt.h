#ifndef SG_PT_H
#define SG_PT_H

/*
 * Copyright (c) 2005-2006 Douglas Gilbert.
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

/* Returns >= 0 if successful. If error in Unix returns negated errno. */
extern int scsi_pt_open_device(const char * device_name, int read_only,
                               int verbose);

/* Returns 0 if successful. If error in Unix returns negated errno. */
extern int scsi_pt_close_device(int device_fd);


/* One scsi_pt_obj per SCSI command issued */
extern void * construct_scsi_pt_obj();

/* Only invoke once per scsi_pt_obj */
extern void set_scsi_pt_cdb(void * scsi_pt_obj, const unsigned char * cdb,
                            int cdb_len);
/* Only invoke once per scsi_pt_obj. Zeroes given 'sense' buffer. */
extern void set_scsi_pt_sense(void * scsi_pt_obj, unsigned char * sense,
                              int max_sense_len);
/* Invoke at most once per scsi_pt_obj */
extern void set_scsi_pt_data_in(void * scsi_pt_obj,     /* from device */
                                unsigned char * dxferp, int dxfer_len);
/* Invoke at most once per scsi_pt_obj */
extern void set_scsi_pt_data_out(void * scsi_pt_obj,    /* to device */
                                 const unsigned char * dxferp, int dxfer_len);
/* The following "set_"s implementations may be dummies */
extern void set_scsi_pt_packet_id(void * scsi_pt_obj, int pack_id);
extern void set_scsi_pt_tag(void * scsi_pt_obj, int tag);
extern void set_scsi_pt_task_management(void * scsi_pt_obj, int tmf_code);
extern void set_scsi_pt_task_attr(void * scsi_pt_obj, int attribute,
                                  int priority);

#define SCSI_PT_DO_START_OK 0
#define SCSI_PT_DO_BAD_PARAMS 1
#define SCSI_PT_DO_TIMEOUT 2
/* If OS start error, negated error value (e.g. Unix '-errno') returned,
   return 0 if okay (i.e. at the very least: command sent). Positive
   return values are errors (see SCSI_PT_DO_* defines). */
extern int do_scsi_pt(void * scsi_pt_obj, int fd, int timeout_secs,
                      int verbose);

#define SCSI_PT_RESULT_GOOD 0
#define SCSI_PT_RESULT_STATUS 1 /* other than GOOD and CHECK CONDITION */
#define SCSI_PT_RESULT_SENSE 2
#define SCSI_PT_RESULT_TRANSPORT_ERR 3
#define SCSI_PT_RESULT_OS_ERR 4
/* highest numbered applicable category returned */
extern int get_scsi_pt_result_category(const void * scsi_pt_obj);

/* If not available return 0 */
extern int get_scsi_pt_resid(const void * scsi_pt_obj);
/* Returns SCSI status value (from device that received the
   command). */
extern int get_scsi_pt_status_response(const void * scsi_pt_obj);
/* Actual sense length returned. If sense data is present but
   actual sense length is not known, return 'max_sense_len' */
extern int get_scsi_pt_sense_len(const void * scsi_pt_obj);
/* If not available return 0 */
extern int get_scsi_pt_os_err(const void * scsi_pt_obj);
extern char * get_scsi_pt_os_err_str(const void * scsi_pt_obj,
                                     int max_b_len, char * b);
/* If not available return 0 */
extern int get_scsi_pt_transport_err(const void * scsi_pt_obj);
extern char * get_scsi_pt_transport_err_str(const void * scsi_pt_obj,
                                            int max_b_len, char * b);

/* If not available return -1 */
extern int get_scsi_pt_duration_ms(const void * scsi_pt_obj);

/* Should be invoked once per scsi_pt_obj object after other
   processing is complete in order to clean up resources. */
extern void destruct_scsi_pt_obj(void * scsi_pt_obj);


#endif

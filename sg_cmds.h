#ifndef SG_CMDS_H
#define SG_CMDS_H

/*
 * Copyright (c) 2004-2006 Douglas Gilbert.
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


/*
 * Additional sense data categories (to those defined in sg_lib.h).
 */

#define SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO 9 /* Illegal request (other than */
                                /* invalid opcode) plus 'info' field: */
                                /*  [sk,asc,ascq: 0x5,*,*] */
#define SG_LIB_CAT_MEDIUM_HARD_WITH_INFO 10 /* medium or hardware error */
                                /* sense key plus 'info' field: */
                                /*       [sk,asc,ascq: 0x3/0x4,*,*] */


/* Invokes a FORMAT UNIT (SBC-3) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Format unit not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_format_unit(int sg_fd, int fmtpinfo, int rto_req,
                             int longlist, int fmtdata, int cmplist,
                             int dlist_format, int timeout_secs,
                             void * paramp, int param_len, int noisy,
                             int verbose);

/* Invokes a SCSI GET CONFIGURATION command (MMC-3,4,5).
 * Returns 0 when successful, SG_LIB_CAT_INVALID_OP if command not
 * supported, SG_LIB_CAT_ILLEGAL_REQ if field in cdb not supported,
 * else -1 */
extern int sg_ll_get_config(int sg_fd, int rt, int starting, void * resp,
                            int mx_resp_len, int noisy, int verbose);

/* Invokes a SCSI INQUIRY command and yields the response */
/* Returns 0 when successful, -1 -> pass through failed, -2 -> bad response */
extern int sg_ll_inquiry(int sg_fd, int cmddt, int evpd, int pg_op,
                         void * resp, int mx_resp_len, int noisy,
                         int verbose);

/* Invokes a SCSI LOG SELECT command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Log Select not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_log_select(int sg_fd, int pcr, int sp, int pc,
                            unsigned char * paramp, int param_len,
                            int noisy, int verbose);

/* Invokes a SCSI LOG SENSE command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Log Sense not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_log_sense(int sg_fd, int ppc, int sp, int pc, int pg_code,
                           int paramp, unsigned char * resp, int mx_resp_len,
                           int noisy, int verbose);

/* Invokes a SCSI MODE SELECT (6) command.  Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, -1 -> other failure */
extern int sg_ll_mode_select6(int sg_fd, int pf, int sp, void * paramp,
                              int param_len, int noisy, int verbose);

/* Invokes a SCSI MODE SELECT (10) command.  Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, -1 -> other failure */
extern int sg_ll_mode_select10(int sg_fd, int pf, int sp, void * paramp,
                               int param_len, int noisy, int verbose);

/* Invokes a SCSI MODE SENSE (6) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, -1 -> other failure */
extern int sg_ll_mode_sense6(int sg_fd, int dbd, int pc, int pg_code,
                             int sub_pg_code, void * resp, int mx_resp_len,
                             int noisy, int verbose);

/* Invokes a SCSI MODE SENSE (10) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_ILLEGAL_REQ ->
 * bad field in cdb, -1 -> other failure */
extern int sg_ll_mode_sense10(int sg_fd, int llbaa, int dbd, int pc,
                              int pg_code, int sub_pg_code, void * resp,
                              int mx_resp_len, int noisy, int verbose);

/* Invokes a SCSI PERSISTENT RESERVE IN command (SPC). Returns 0
 * when successful, SG_LIB_CAT_INVALID_OP if command not supported,
 * SG_LIB_CAT_ILLEGAL_REQ if field in cdb not supported, else -1 */
extern int sg_ll_persistent_reserve_in(int sg_fd, int rq_servact,
                                       void * resp, int mx_resp_len,
                                       int noisy, int verbose);

/* Invokes a SCSI PERSISTENT RESERVE OUT command (SPC). Returns 0
 * when successful, SG_LIB_CAT_INVALID_OP if command not supported,
 * SG_LIB_CAT_ILLEGAL_REQ if field in cdb not supported, else -1 */
extern int sg_ll_persistent_reserve_out(int sg_fd, int rq_servact,
                                        int rq_scope, unsigned int rq_type,
                                        void * paramp, int param_len,
                                        int noisy, int verbose);

/* Invokes a SCSI PREVENT ALLOW MEDIUM REMOVAL command (SPC-3)
 * prevent==0 allows removal, prevent==1 prevents removal ...
 * Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> command not supported
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_prevent_allow(int sg_fd, int prevent, int noisy,
                               int verbose);

/* Invokes a SCSI READ CAPACITY (10) command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode, SG_LIB_CAT_MEDIA_CHANGED
 * -> media changed, SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb,
 * -1 -> other failure */
extern int sg_ll_readcap_10(int sg_fd, int pmi, unsigned int lba,
                            void * resp, int mx_resp_len, int noisy,
                            int verbose);

/* Invokes a SCSI READ CAPACITY (16) command. Returns 0 -> success,
 * -1 -> failure, SG_LIB_CAT_MEDIA_CHANGED -> repeat, SG_LIB_CAT_INVALID_OP
 *  -> cdb not supported, SG_LIB_CAT_IlLEGAL_REQ -> bad field in cdb */
extern int sg_ll_readcap_16(int sg_fd, int pmi, unsigned long long llba,
                            void * resp, int mx_resp_len, int noisy,
                            int verbose);

/* Invokes a SCSI READ DEFECT DATA (10) command (SBC). Return of 0 ->
 * success, SG_LIB_CAT_INVALID_OP -> invalid opcode,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_read_defect10(int sg_fd, int req_plist, int req_glist,
                               int dl_format, void * resp, int mx_resp_len,
                               int noisy, int verbose);

/* Invokes a SCSI READ LONG (10) command (SBC). Note that 'xfer_len'
 * is in bytes. Returns 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> READ LONG(10) not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO -> bad field in cdb, with info
 * field written to 'offsetp', -1 -> other failure */
extern int sg_ll_read_long10(int sg_fd, int correct, unsigned long lba,
                             void * resp, int xfer_len, int * offsetp,
                             int noisy, int verbose);

/* Invokes a SCSI READ MEDIA SERIAL NUMBER command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Read media serial number not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_read_media_serial_num(int sg_fd, void * resp,
                                       int mx_resp_len, int noisy,
                                       int verbose);

/* Invokes a SCSI REASSIGN BLOCKS command.  Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> invalid opcode,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_reassign_blocks(int sg_fd, int longlba, int longlist,
                                 void * paramp, int param_len, int noisy,
                                 int verbose);

/* Invokes a SCSI RECEIVE DIAGNOSTIC RESULTS command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Receive diagnostic results not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_receive_diag(int sg_fd, int pcv, int pg_code, void * resp,
                              int mx_resp_len, int noisy, int verbose);

/* Invokes a SCSI REPORT DEVICE IDENTIFIER command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Read media serial number not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_report_dev_id(int sg_fd, void * resp, int max_resp_len,
                               int noisy, int verbose);

/* Invokes a SCSI REPORT LUNS command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Report Luns not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_report_luns(int sg_fd, int select_report, void * resp,
                             int mx_resp_len, int noisy, int verbose);

/* Invokes a SCSI REPORT TARGET PORT GROUPS command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Report Target Port Groups not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_report_tgt_prt_grp(int sg_fd, void * resp,
                                    int mx_resp_len, int noisy, int verbose);

/* Invokes a SCSI REQUEST SENSE command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Request Sense not * supported??,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_request_sense(int sg_fd, int desc, void * resp,
                               int mx_resp_len, int noisy, int verbose);

/* Invokes a SCSI SEND DIAGNOSTIC command. Foreground, extended self tests can
 * take a long time, if so set long_duration flag. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Send diagnostic not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_send_diag(int sg_fd, int sf_code, int pf_bit, int sf_bit,
                           int devofl_bit, int unitofl_bit, int long_duration,
                           void * paramp, int param_len, int noisy,
                           int verbose);

/* Invokes a SCSI SET DEVICE IDENTIFIER command. Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Read media serial number not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_set_dev_id(int sg_fd, void * paramp, int param_len,
                               int noisy, int verbose);

/* Invokes a SCSI START STOP UNIT command (MMC + SBC).
 * Return of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Start stop unit not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure */
extern int sg_ll_start_stop_unit(int sg_fd, int immed, int fl_num,
                                 int power_cond, int fl, int loej,
                                 int start, int noisy, int verbose);

/* Invokes a SCSI SYNCHRONIZE CACHE (10) command. Return of 0 -> success,
 * -1 -> failure, SG_LIB_CAT_MEDIA_CHANGED -> repeat, SG_LIB_CAT_INVALID_OP
 * -> cdb not supported, SG_LIB_CAT_IlLEGAL_REQ -> bad field in cdb */
extern int sg_ll_sync_cache_10(int sg_fd, int sync_nv, int immed, int group,
                               unsigned int lba, unsigned int count,
                               int noisy, int verbose);

/* Invokes a SCSI TEST UNIT READY command.
 * 'pack_id' is just for diagnostics, safe to set to 0.
 * Return of 0 -> success, -1 -> failure */
extern int sg_ll_test_unit_ready(int sg_fd, int pack_id, int noisy,
                                 int verbose);

/* Invokes a SCSI TEST UNIT READY command.
 * 'pack_id' is just for diagnostics, safe to set to 0.
 * Looks for progress indicator if 'progress' non-NULL;
 * if found writes value [0..65535] else write -1.
 * Return of 0 -> success, -1 -> failure */
extern int sg_ll_test_unit_ready_progress(int sg_fd, int pack_id,
                                          int * progress, int noisy,
                                          int verbose);

/* Invokes a SCSI VERIFY (10) command (SBC and MMC).
 * Note that 'veri_len' is in blocks while 'data_out_len' is in bytes.
 * Returns of 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> Verify(10) not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_MEDIUM_HARD -> medium or hardware error, no valid info,
 * SG_LIB_CAT_MEDIUM_HARD_WITH_INFO -> as previous, with valid info,
 * -1 -> other failure */
extern int sg_ll_verify10(int sg_fd, int dpo, int bytechk, unsigned long lba,
                          int veri_len, void * data_out, int data_out_len,
                          unsigned long * infop, int noisy, int verbose);

/* Invokes a SCSI WRITE LONG (10) command (SBC). Note that 'xfer_len'
 * is in bytes. Returns 0 -> success,
 * SG_LIB_CAT_INVALID_OP -> WRITE LONG(10) not supported,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb,
 * SG_LIB_CAT_ILLEGAL_REQ_WITH_INFO -> bad field in cdb, with info
 * field written to 'offsetp', -1 -> other failure */
extern int sg_ll_write_long10(int sg_fd, int cor_dis, unsigned long lba,
                              void * data_out, int xfer_len, int * offsetp,
                              int noisy, int verbose);


struct sg_simple_inquiry_resp {
    unsigned char peripheral_qualifier;
    unsigned char peripheral_type;
    unsigned char rmb;
    unsigned char version;      /* as per recent drafts: whole of byte 2 */
    unsigned char byte_3;
    unsigned char byte_5;
    unsigned char byte_6;
    unsigned char byte_7;
    char vendor[9];
    char product[17];
    char revision[5];
};

/* Yields most of first 36 bytes of a standard INQUIRY (evpd==0) response. */
/* Returns 0 when successful, -1 -> pass through failed, -2 -> bad response */
extern int sg_simple_inquiry(int sg_fd,
                             struct sg_simple_inquiry_resp * inq_data,
                             int noisy, int verbose);

/* MODE SENSE commands yield a response that has block descriptors followed
 * by mode pages. In most cases users are interested in the first mode page.
 * This function returns the (byte) offset of the start of the first mode
 * page. Set mode_sense_6 to 1 for MODE SENSE (6) and 0 for MODE SENSE (10).
 * Returns >= 0 is successful or -1 if failure. If there is a failure
 * a message is written to err_buff. */
extern int sg_mode_page_offset(const unsigned char * resp, int resp_len,
                               int mode_sense_6, char * err_buff,
                               int err_buff_len);

/* Fetches current, changeable, default and/or saveable modes pages as
 * indicated by pcontrol_arr for given pg_code and sub_pg_code. If
 * mode6==0 then use MODE SENSE (10) else use MODE SENSE (6). If
 * flexible set and mode data length seems wrong then try and
 * fix (compensating hack for bad device or driver). pcontrol_arr
 * should have 4 elements for output of current, changeable, default
 * and saved values respectively. Each element should be NULL or
 * at least mx_mpage_len bytes long.
 * Return of 0 -> overall success, SG_LIB_CAT_INVALID_OP -> invalid opcode,
 * SG_LIB_CAT_ILLEGAL_REQ -> bad field in cdb, -1 -> other failure.
 * If success_mask pointer is not NULL then zeroes it then sets bit 0, 1,
 * 2 and/or 3 if the current, changeable, default and saved values
 * respectively have been fetched. If error on current page
 * then stops and returns that error; otherwise continues if an error is
 * detected but returns the first error encountered.  */
extern int sg_get_mode_page_controls(int sg_fd, int mode6, int pg_code,
                              int sub_pg_code, int dbd, int flexible,
                              int mx_mpage_len, int * success_mask,
                              void * pcontrol_arr[], int * reported_len,
                              int verbose);

/* Returns file descriptor >= 0 if successful. If error in Unix returns
   negated errno. Implementation calls scsi_pt_open_device(). */
extern int sg_cmds_open_device(const char * device_name, int read_only,
                               int verbose);

/* Returns 0 if successful. If error in Unix returns negated errno.
   Implementation calls scsi_pt_close_device(). */
extern int sg_cmds_close_device(int device_fd);

extern const char * sg_cmds_version();

#endif

/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _UAPI_SCSI_SG_H
#define _UAPI_SCSI_SG_H

/*
 * History:
 *  Started: Aug 9 by Lawrence Foard (entropy@world.std.com), to allow user
 *  process control of SCSI devices.
 *  Development Sponsored by Killy Corp. NY NY
 *
 * Original driver (sg.h):
 *   Copyright (C) 1992 Lawrence Foard
 * Version 2 and 3 extensions to driver:
 *   Copyright (C) 1998 - 2018 Douglas Gilbert
 *
 *   Version: 3.9.02 (20181203)
 *  This version is for Linux 2.6, 3 and 4 series kernels.
 *
 * Documentation
 * =============
 * A web site for the SG device driver can be found at:
 *   http://sg.danny.cz/sg  [alternatively check the MAINTAINERS file]
 * The documentation for the sg version 3 driver can be found at:
 *   http://sg.danny.cz/sg/p/sg_v3_ho.html
 * Also see: <kernel_source>/Documentation/scsi/scsi-generic.txt
 *
 * For utility and test programs see: http://sg.danny.cz/sg/sg3_utils.html
 */

#include <linux/types.h>
#include <linux/major.h>

/* bsg.h contains the sg v4 user space interface structure. */
#include <linux/bsg.h>

/*
 * Same structure as used by readv() call. It defines one scatter-gather
 * element. "Scatter-gather" is abbreviated to "sgat" in this driver to
 * avoid confusion with this driver's name.
 */
typedef struct sg_iovec	{
	void __user *iov_base;	/* Starting address (of a byte) */
	size_t iov_len;		/* Length in bytes */
} sg_iovec_t;


typedef struct sg_io_hdr {
	int interface_id;	/* [i] 'S' for SCSI generic (required) */
	int dxfer_direction;	/* [i] data transfer direction  */
	unsigned char cmd_len;	/* [i] SCSI command length */
	unsigned char mx_sb_len;/* [i] max length to write to sbp */
	unsigned short iovec_count;	/* [i] 0 implies no sgat list */
	unsigned int dxfer_len;	/* [i] byte count of data transfer */
	/* points to data transfer memory or scatter gather list */
	void __user *dxferp;	/* [i], [*io] */
	unsigned char __user *cmdp;/* [i], [*i] points to command to perform */
	void __user *sbp;	/* [i], [*o] points to sense_buffer memory */
	unsigned int timeout;	/* [i] MAX_UINT->no timeout (unit: millisec) */
	unsigned int flags;	/* [i] 0 -> default, see SG_FLAG... */
	int pack_id;		/* [i->o] unused internally (normally) */
	void __user *usr_ptr;	/* [i->o] unused internally */
	unsigned char status;	/* [o] scsi status */
	unsigned char masked_status;/* [o] shifted, masked scsi status */
	unsigned char msg_status;/* [o] messaging level data (optional) */
	unsigned char sb_len_wr; /* [o] byte count actually written to sbp */
	unsigned short host_status; /* [o] errors from host adapter */
	unsigned short driver_status;/* [o] errors from software driver */
	int resid;		/* [o] dxfer_len - actual_transferred */
	/* unit may be nanoseconds after SG_SET_GET_EXTENDED ioctl use */
	unsigned int duration;	/* [o] time taken by cmd (unit: millisec) */
	unsigned int info;	/* [o] auxiliary information */
} sg_io_hdr_t;

#define SG_INTERFACE_ID_ORIG 'S'

/* Use negative values to flag difference from original sg_header structure */
#define SG_DXFER_NONE (-1)	/* e.g. a SCSI Test Unit Ready command */
#define SG_DXFER_TO_DEV (-2)	/* data-out buffer e.g. SCSI WRITE command */
#define SG_DXFER_FROM_DEV (-3)	/* data-in buffer e.g. SCSI READ command */
/*
 * treated like SG_DXFER_FROM_DEV with the additional property than during
 * indirect IO the user buffer is copied into the kernel buffers _before_
 * the transfer from the device takes place. Useful if short DMA transfers
 * (less than requested) are not reported (e.g. resid always 0).
 */
#define SG_DXFER_TO_FROM_DEV (-4)
#define SG_DXFER_UNKNOWN (-5)	/* Unknown data direction, do not use */

/* following flag values can be OR-ed together */
#define SG_FLAG_DIRECT_IO 1	/* default is indirect IO */
#define SG_FLAG_UNUSED_LUN_INHIBIT 2	/* default is overwrite lun in SCSI */
				/* command block (when <= SCSI_2) */
#define SG_FLAG_MMAP_IO 4	/* request memory mapped IO */
/* no transfer of kernel buffers to/from user space; to debug indirect IO */
#define SG_FLAG_NO_DXFER 0x10000
/* defaults: for sg driver (v3): Q_AT_HEAD; for block layer: Q_AT_TAIL */
#define SG_FLAG_Q_AT_TAIL 0x10
#define SG_FLAG_Q_AT_HEAD 0x20

/*
 * Flags used by ioctl(SG_IOSUBMIT) [abbrev: SG_IOS] and ioctl(SG_IORECEIVE)
 * [abbrev: SG_IOR] OR-ed into sg_io_v4::flags, also with ioctl(SG_IO) when
 * sg_io_v4::guard is 'Q' in which case SGV4_FLAG_SYNC is implicitly set.
 * These flags apply for SG_IOS unless otherwise noted. May be OR-ed together.
 */
#define SGV4_FLAG_DIRECT_IO SG_FLAG_DIRECT_IO
#define SGV4_FLAG_MMAP_IO SG_FLAG_MMAP_IO
#define SGV4_FLAG_YIELD_TAG 0x8  /* sg_io_v4::request_attr set after SG_IOS */
#define SGV4_FLAG_Q_AT_TAIL SG_FLAG_Q_AT_TAIL
#define SGV4_FLAG_Q_AT_HEAD SG_FLAG_Q_AT_HEAD
#define SGV4_FLAG_FIND_BY_TAG 0x100  /* in SG_IOR, def: find by pack_id */
/* Flag value 0x200 not currently used */
#define SGV4_FLAG_IMMED 0x400	/* for polling with SG_IOR else ignored */
/* Flag value 0x800 not currently used */
#define SGV4_FLAG_DEV_SCOPE 0x1000 /* permit SG_IOABORT to have wider scope */
#define SGV4_FLAG_SHARE 0x2000	/* share IO buffer; needs SG_SEIM_SHARE_FD */
#define SGV4_FLAG_NO_DXFER SG_FLAG_NO_DXFER

/* following 'info' values are OR-ed together */
#define SG_INFO_OK_MASK 0x1
#define SG_INFO_OK 0x0		/* no sense, host nor driver "noise" */
#define SG_INFO_CHECK 0x1	/* something abnormal happened */

#define SG_INFO_DIRECT_IO_MASK 0x6
#define SG_INFO_INDIRECT_IO 0x0	/* data xfer via kernel buffers (or no xfer) */
#define SG_INFO_DIRECT_IO 0x2	/* direct IO requested and performed */
#define SG_INFO_MIXED_IO 0x4	/* part direct, part indirect IO */
#define SG_INFO_DEVICE_DETACHING 0x8	/* completed successfully but ... */
#define SG_INFO_ANOTHER_WAITING 0x10	/* needs SG_CTL_FLAGM_CHECK_FOR_MORE */


typedef struct sg_scsi_id {	/* used by SG_GET_SCSI_ID ioctl() */
	int host_no;	/* as in "scsi<n>" where 'n' is one of 0, 1, 2 etc */
	int channel;
	int scsi_id;	/* scsi id of target device */
	int lun;
	int scsi_type;	/* TYPE_... defined in scsi/scsi.h */
	short h_cmd_per_lun;/* host (adapter) maximum commands per lun */
	short d_queue_depth;/* device (or adapter) maximum queue length */
	int unused[2];	/* probably find a good use, set 0 for now */
} sg_scsi_id_t;

typedef struct sg_req_info {	/* used by SG_GET_REQUEST_TABLE ioctl() */
	char req_state;	/* 0 -> not used, 1 -> written, 2 -> ready to read */
	char orphan;	/* 0 -> normal request, 1 -> from interrupted SG_IO */
	char sg_io_owned;/* 0 -> complete with read(), 1 -> owned by SG_IO */
	char problem;	/* 0 -> no problem detected, 1 -> error to report */
	int pack_id;	/* pack_id associated with request */
	void __user *usr_ptr;	/* user provided pointer (in new interface) */
	/*
	 * millisecs elapsed since the command started (req_state==1) or
	 * command duration (req_state==2). May be in nanoseconds after
	 * the SG_SET_GET_EXTENDED ioctl.
	 */
	unsigned int duration;
	int unused;
} sg_req_info_t;

/*
 * The following defines may help when using struct sg_extended_info which
 * is abbreviated to "SEI". A following "M" (i.e. "_SEIM_") indicates a
 * mask. Most mask values correspond to a integer (usually a __u32) apart
 * from SG_SEIM_CTL_FLAGS which is for a collection of boolean values
 * packed into an integer. The mask values for those booleans start with
 * "SG_CTL_FLAGM_". The scope of these settings, like most other ioctls,
 * is usually that of the file descriptor the ioctl is executed on. Masks
 * marked with "rd" are read-only, attempts to write to them are ignored.
 */
#define SG_SEIM_RESERVED_SIZE	0x1	/* reserved_sz field valid */
#define SG_SEIM_RQ_REM_THRESH	0x2	/* rq_rem_sgat_thresh field valid */
#define SG_SEIM_TOT_FD_THRESH	0x4	/* tot_fd_thresh field valid */
#define SG_SEIM_CTL_FLAGS	0x8	/* ctl_flags_mask bits in ctl_flags */
#define SG_SEIM_MINOR_INDEX	0x10	/* sg device minor index number */
#define SG_SEIM_READ_VAL	0x20	/* write SG_SEIRV, read related */
#define SG_SEIM_SHARE_FD	0x40	/* slave gives fd of master, sharing */
#define SG_SEIM_SGAT_ELEM_SZ	0x80	/* sgat element size (>= PAGE_SIZE) */
#define SG_SEIM_ALL_BITS	0xff	/* should be OR of previous items */

#define SG_CTL_FLAGM_TIME_IN_NS	0x1	/* time: nanosecs (def: millisecs) */
#define SG_CTL_FLAGM_TAG_FOR_PACK_ID 0x2
#define SG_CTL_FLAGM_OTHER_OPENS 0x4	/* rd: other sg fd_s on this dev */
#define SG_CTL_FLAGM_ORPHANS	0x8	/* rd: orphaned requests on this fd */
#define SG_CTL_FLAGM_Q_TAIL	0x10	/* used for future cmds on this fd */
#define SG_CTL_FLAGM_IS_SHARE	0x20	/* rd: fd is master or slave share */
#define SG_CTL_FLAGM_IS_MASTER	0x40	/* rd: this fd is share master */
#define SG_CTL_FLAGM_UNSHARE	0x80	/* undo share after inflight cmd */
#define SG_CTL_FLAGM_MASTER_FINI 0x100	/* share: master finished; 1: finish */
#define SG_CTL_FLAGM_MASTER_ERR	0x200	/* rd: sharing, master got error */
#define SG_CTL_FLAGM_CHECK_FOR_MORE 0x400 /* additional ready to read? */
#define SG_CTL_FLAGM_ALL_BITS	0x7ff	/* should be OR of previous items */

/* Write one of the following values to sg_extended_info::read_value, get... */
#define SG_SEIRV_INT_MASK	0x0	/* get SG_SEIM_ALL_BITS */
#define SG_SEIRV_BOOL_MASK	0x1	/* get SG_CTL_FLAGM_ALL_BITS */
#define SG_SEIRV_VERS_NUM	0x2	/* get driver version number as int */
#define SG_SEIRV_FL_RQS		0x3	/* number of requests in free list */
#define SG_SEIRV_DEV_FL_RQS	0x4	/* sum of rqs on all fds on this dev */
#define SG_SEIRV_TRC_SZ		0x5	/* current size of trace buffer */
#define SG_SEIRV_TRC_MAX_SZ	0x6	/* maximum size of trace buffer */

/*
 * A pointer to the following structure is passed as the third argument to 
 * ioctl(SG_SET_GET_EXTENDED). Each bit in the *_wr_mask fields causes the
 * corresponding integer (e.g. reserved_sz) or bit (e.g. the
 * SG_CTL_FLAG_TIME_IN_NS bit in ctl_flags) to be read from the user space
 * and modify the driver. Each bit in the *_rd_mask fields causes the
 * corresponding integer or bit to be fetched from the driver and written
 * back to the user space. If the same bit is set in both the *_wr_mask and
 * corresponding *_rd_mask fields, then the write action takes place before
 * the read action and no other operation will split the two. This structure
 * is padded to 96 bytes to allow for new values to be added in the future.
 */
struct sg_extended_info {
	__u32	valid_wr_mask;	/* OR-ed SG_SEIM_* user->driver values */
	__u32	valid_rd_mask;	/* OR-ed SG_SEIM_* driver->user values */
	__u32	reserved_sz;	/* data/sgl size of pre-allocated request */
	__u32	rq_rem_sgat_thresh;/* request re-use: clear data/sgat if > */
	__u32	tot_fd_thresh;	/* total data/sgat for this fd, 0: no limit */
	__u32	ctl_flags_wr_mask;	/* OR-ed SG_CTL_FLAGM_* values */
	__u32	ctl_flags_rd_mask;	/* OR-ed SG_CTL_FLAGM_* values */
	__u32	ctl_flags;	/* bit values OR-ed, see SG_CTL_FLAGM_* */
	__u32	minor_index;	/* rd: kernel's sg device minor number */
	__u32	read_value;	/* write known value, read back related */
	__u32	share_fd;	/* slave provided fd of master */
	__u32	sgat_elem_sz;	/* sgat element size (must be power of 2 */
	__u8	pad_to_96[52];	/* pad so struct is 96 bytes long */
};

/*
 * IOCTLs: Those ioctls that are relevant to the SG 3.x drivers follow.
 * [Those that only apply to the SG 2.x drivers are at the end of the file.]
 * (_GET_s yield result via 'int *' 3rd argument unless otherwise indicated)
 */

#define SG_EMULATED_HOST 0x2203	/* true for emulated host adapter (ATAPI) */

/*
 * Used to configure SCSI command transformation layer for ATAPI devices.
 * Only supported by the ide-scsi driver. 20181014 No longer supported, this
 * driver passes them to the mid-level which returns a EINVAL (22) errno.
 *
 * Original note: N.B. 3rd arg is not pointer but value: 3rd arg = 0 to
 * disable transform, 1 to enable it
 */
#define SG_SET_TRANSFORM 0x2204
#define SG_GET_TRANSFORM 0x2205

#define SG_SET_RESERVED_SIZE 0x2275  /* request new reserved buffer size */
#define SG_GET_RESERVED_SIZE 0x2272  /* actual size of reserved buffer */

/*
 * Historically the scsi/sg driver has used 0x22 as it ioctl base number.
 * Add a define for that value and use it for several new ioctls added in
 * version 3.9.01 sg driver.
 */
#define SG_IOCTL_MAGIC_NUM 0x22

#define SG_SET_GET_EXTENDED _IOWR(SG_IOCTL_MAGIC_NUM, 0x51,	\
				  struct sg_extended_info)

/* The following ioctl has a 'sg_scsi_id_t *' object as its 3rd argument. */
#define SG_GET_SCSI_ID 0x2276   /* Yields fd's bus, chan, dev, lun + type */
/* SCSI id information can also be obtained from SCSI_IOCTL_GET_IDLUN */

/* Override host setting and always DMA using low memory ( <16MB on i386) */
#define SG_SET_FORCE_LOW_DMA 0x2279  /* 0-> use adapter setting, 1-> force */
#define SG_GET_LOW_DMA 0x227a	/* 0-> use all ram for dma; 1-> low dma ram */

/*
 * When SG_SET_FORCE_PACK_ID set to 1, pack_id (or tag) is input to read() or
 * ioctl(SG_IO_RECEIVE). These functions wait until matching packet (request/
 * command) is finished but they will return with EAGAIN quickly if the file
 * descriptor was opened O_NONBLOCK or (in v4) if SGV4_FLAG_IMMED is given.
 * The tag is used when SGV4_FLAG_FIND_BY_TAG is given (default: use pack_id).
 * If pack_id or tag is -1 then read oldest waiting. When FORCE_PACK_ID is
 * cleared to 0 the oldest readable request/command is fetched. In v4 the
 * pack_id is placed in sg_io_v4::request_extra .
 */
#define SG_SET_FORCE_PACK_ID 0x227b	/* pack_id or in v4 can be tag */
#define SG_GET_PACK_ID 0x227c	/* Yields oldest readable pack_id (or -1) */

#define SG_GET_NUM_WAITING 0x227d /* Number of commands awaiting read() */

/* Yields max scatter gather tablesize allowed by current host adapter */
#define SG_GET_SG_TABLESIZE 0x227F  /* 0 implies can't do scatter gather */

#define SG_GET_VERSION_NUM 0x2282 /* Example: version 2.1.34 yields 20134 */

/* Returns -EBUSY if occupied. 3rd argument pointer to int (see next) */
#define SG_SCSI_RESET 0x2284
/*
 * Associated values that can be given to SG_SCSI_RESET follow.
 * SG_SCSI_RESET_NO_ESCALATE may be OR-ed to the _DEVICE, _TARGET, _BUS
 * or _HOST reset value so only that action is attempted.
 */
#define		SG_SCSI_RESET_NOTHING	0
#define		SG_SCSI_RESET_DEVICE	1
#define		SG_SCSI_RESET_BUS	2
#define		SG_SCSI_RESET_HOST	3
#define		SG_SCSI_RESET_TARGET	4
#define		SG_SCSI_RESET_NO_ESCALATE	0x100

/* synchronous SCSI command ioctl, (only in version 3 interface) */
#define SG_IO 0x2285	/* similar effect as write() followed by read() */

#define SG_GET_REQUEST_TABLE 0x2286	/* yields table of active requests */

/* How to treat EINTR during SG_IO ioctl(), only in SG 3.x series */
#define SG_SET_KEEP_ORPHAN 0x2287 /* 1 -> hold for read(), 0 -> drop (def) */
#define SG_GET_KEEP_ORPHAN 0x2288

/*
 * Yields scsi midlevel's access_count for this SCSI device. 20181014 No
 * longer available, always yields 1.
 */
#define SG_GET_ACCESS_COUNT 0x2289


/*
 * Largest size (in bytes) a single scatter-gather list element can have.
 * The value used by the driver is 'max(SG_SCATTER_SZ, PAGE_SIZE)'.
 * This value should be a power of 2 (and may be rounded up internally).
 * If scatter-gather is not supported by adapter then this value is the
 * largest data block that can be read/written by a single scsi command.
 */
#define SG_SCATTER_SZ (8 * 4096)

#define SG_DEFAULT_RETRIES 0

/* Defaults, commented if they differ from original sg driver */
#define SG_DEF_FORCE_PACK_ID 0
#define SG_DEF_KEEP_ORPHAN 0
#define SG_DEF_RESERVED_SIZE SG_SCATTER_SZ /* load time option */

/*
 * Maximum outstanding requests (i.e write()s without corresponding read()s)
 * yields EDOM from write() if exceeded. This limit only applies prior to
 * version 3.9 . It is still used as a maximum number of sg_req_info objects
 * that are returned from the SG_GET_REQUEST_TABLE ioctl.
 */
#define SG_MAX_QUEUE 16

#define SG_BIG_BUFF SG_DEF_RESERVED_SIZE    /* for backward compatibility */

/*
 * Alternate style type names, "..._t" variants (as found in the
 * 'typedef struct * {};' definitions above) are preferred to these:
 */
typedef struct sg_io_hdr Sg_io_hdr;
typedef struct sg_io_vec Sg_io_vec;
typedef struct sg_scsi_id Sg_scsi_id;
typedef struct sg_req_info Sg_req_info;


/* vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv */
/*   The older SG interface based on the 'sg_header' structure follows.   */
/* ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ */

#define SG_MAX_SENSE 16	/* this only applies to the sg_header interface */

struct sg_header {
	int pack_len;	/* [o] reply_len (ie useless), ignored as input */
	int reply_len;	/* [i] max length of expected reply (inc. sg_header) */
	int pack_id;	/* [io] id number of packet (use ints >= 0) */
	int result;	/* [o] 0==ok, else (+ve) Unix errno (best ignored) */
	unsigned int twelve_byte:1;
	    /* [i] Force 12 byte command length for group 6 & 7 commands  */
	unsigned int target_status:5;	/* [o] scsi status from target */
	unsigned int host_status:8;	/* [o] host status (see "DID" codes) */
	unsigned int driver_status:8;	/* [o] driver status+suggestion */
	unsigned int other_flags:10;	/* unused */
	unsigned char sense_buffer[SG_MAX_SENSE];
	/*
	 * [o] Output in 3 cases:
	 *	when target_status is CHECK_CONDITION or
	 *	when target_status is COMMAND_TERMINATED or
	 *	when (driver_status & DRIVER_SENSE) is true.
	 */
};

/*
 * IOCTLs: The following are not required (or ignored) when the sg_io_hdr_t
 *  interface is used. They are kept for backward compatibility with
 * the original and version 2 drivers.
 */

#define SG_SET_TIMEOUT 0x2201  /* unit: jiffies (10ms on i386) */
#define SG_GET_TIMEOUT 0x2202  /* yield timeout as _return_ value */

/*
 * Get/set command queuing state per fd (default is SG_DEF_COMMAND_Q.
 * Each time a sg_io_hdr_t object is seen on this file descriptor, this
 * command queuing flag is set on (overriding the previous setting).
 */
#define SG_GET_COMMAND_Q 0x2270   /* Yields 0 (queuing off) or 1 (on) */
#define SG_SET_COMMAND_Q 0x2271   /* Change queuing state with 0 or 1 */

/*
 * Turn on/off error sense trace (1 and 0 respectively, default is off).
 * Try using: "# cat /proc/scsi/sg/debug" instead in the v3 driver
 */
#define SG_SET_DEBUG 0x227e    /* 0 -> turn off debug */

/*
 * override SCSI command length with given number on the next write() on
 * this file descriptor
 */
#define SG_NEXT_CMD_LEN 0x2283

/*
 * New ioctls to replace async write()/read() interface. Present in version
 * 4 and later of the sg driver [>20181014]. These two ioctls accept both
 * the sg_v3 interface (structure defined above) and the sg_v4 interface
 * (structure defined in <include/uapi/linux/bsg.h> ). Following "read" and
 * "write" terms are from the driver's POV, the _IO macros from users' POV.
 */
/* via pointer reads sg v3 or v4 object, optionally writes tag, so _IOWR */
#define SG_IOSUBMIT _IOWR(SG_IOCTL_MAGIC_NUM, 0x41, struct sg_io_v4)
/* via pointer optionally reads tag, writes sg v3 or v4 object, so _IOWR */
#define SG_IORECEIVE _IOWR(SG_IOCTL_MAGIC_NUM, 0x42, struct sg_io_v4)
/* via pointer reads v4 object (including tag), writes nothing, so _IOW */
#define SG_IOABORT _IOW(SG_IOCTL_MAGIC_NUM, 0x43, struct sg_io_v4)

/* command queuing is always on when the new interface is used */
#define SG_DEF_COMMAND_Q 0

#define SG_DEF_UNDERRUN_FLAG 0

#define SG_DEFAULT_TIMEOUT	(60*HZ)	/* HZ == 'jiffies in 1 second' */

#endif

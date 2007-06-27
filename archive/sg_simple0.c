#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <scsi/sg.h>   /* take care: fetches glibc's /usr/include/scsi/sg.h */

/* This is a simple program executing a SCSI INQUIRY command using the
   sg_io_hdr interface of the SCSI generic (sg) driver.

*  Copyright (C) 2001 D. Gilbert
*  This program is free software.   Version 1.00 (20011204)
*/

#define INQ_REPLY_LEN 96 
#define INQ_CMD_CODE 0x12
#define INQ_CMD_LEN 6

int main(int argc, char * argv[])
{
    int sg_fd, k;
    unsigned char inqCmdBlk[INQ_CMD_LEN] =
                    {INQ_CMD_CODE, 0, 0, 0, INQ_REPLY_LEN, 0};
/* This is a "standard" SCSI INQUIRY command. It is standard because the
 * CMDDT and EVPD bits (in the second byte) are zero. All SCSI targets
 * should respond promptly to a standard INQUIRY */
    unsigned char inqBuff[INQ_REPLY_LEN];
    unsigned char sense_buffer[32];
    sg_io_hdr_t io_hdr;

    if (2 != argc) {
        printf("Usage: 'sg_simple0 <sg_device>'\n");
        return 1;
    }
    if ((sg_fd = open(argv[1], O_RDONLY)) < 0) {
        perror("error opening given file name");
        return 1;
    }
    /* It is prudent to check we have a sg device by trying an ioctl */
    if ((ioctl(sg_fd, SG_GET_VERSION_NUM, &k) < 0) || (k < 30000)) {
        printf("%s is not an sg device, or old sg driver\n", argv[1]);
        return 1;
    }
    /* Prepare INQUIRY command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(inqCmdBlk);
    /* io_hdr.iovec_count = 0; */  /* memset takes care of this */
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = INQ_REPLY_LEN;
    io_hdr.dxferp = inqBuff;
    io_hdr.cmdp = inqCmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */
    /* io_hdr.flags = 0; */     /* take defaults: indirect IO, etc */
    /* io_hdr.pack_id = 0; */
    /* io_hdr.usr_ptr = NULL; */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("sg_simple0: Inquiry SG_IO ioctl error");
        return 1;
    }

    /* now for the error processing */
    if ((io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
        if (io_hdr.sb_len_wr > 0) {
            printf("INQUIRY sense data: ");
            for (k = 0; k < io_hdr.sb_len_wr; ++k) {
                if ((k > 0) && (0 == (k % 10)))
                    printf("\n  ");
                printf("0x%02x ", sense_buffer[k]);
            }
            printf("\n");
        }
        if (io_hdr.masked_status)
            printf("INQUIRY SCSI status=0x%x\n", io_hdr.status);
        if (io_hdr.host_status)
            printf("INQUIRY host_status=0x%x\n", io_hdr.host_status);
        if (io_hdr.driver_status)
            printf("INQUIRY driver_status=0x%x\n", io_hdr.driver_status);
    }
    else {  /* assume INQUIRY response is present */
        char * p = (char *)inqBuff;
        printf("Some of the INQUIRY command's response:\n");
        printf("    %.8s  %.16s  %.4s\n", p + 8, p + 16, p + 32);
        printf("INQUIRY duration=%u millisecs, resid=%d\n",
               io_hdr.duration, io_hdr.resid);
    }
    close(sg_fd);
    return 0;
}

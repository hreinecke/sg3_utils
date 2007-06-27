#include <scsi/sg.h>


#define READ10_REPLY_LEN 512
#define READ10_CMD_LEN 10

// read 0x102 blocks from block # 0x3040506
//     [just to to you where the fields are]
..............

    unsigned char r10CmdBlk [READ10_CMD_LEN] =
		{0x28, 0, 3, 4, 5, 6, 0, 1, 2, 0};
    sg_io_hdr_t io_hdr;
    unsigned char inBuff[READ10_REPLY_LEN];
    unsigned char sense_buffer[32];

    /* Prepare READ_10 command */
    memset(&io_hdr, 0, sizeof(sg_io_hdr_t));
    io_hdr.interface_id = 'S';
    io_hdr.cmd_len = sizeof(r10CmdBlk);
    io_hdr.mx_sb_len = sizeof(sense_buffer);
    io_hdr.dxfer_direction = SG_DXFER_FROM_DEV;
    io_hdr.dxfer_len = READ10_REPLY_LEN;
    io_hdr.dxferp = inBuff;
    io_hdr.cmdp = r10CmdBlk;
    io_hdr.sbp = sense_buffer;
    io_hdr.timeout = 20000;     /* 20000 millisecs == 20 seconds */

    if (ioctl(sg_fd, SG_IO, &io_hdr) < 0) {
        perror("READ_10 SG_IO ioctl error");
        .....
    }
    // block should now be in 'inBuff'

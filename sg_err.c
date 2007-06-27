#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sg_include.h"
#include "sg_err.h"


/* This file is a huge cut, paste and hack from linux/drivers/scsi/constant.c
*  which I guess was written by:
*         Copyright (C) 1993, 1994, 1995 Eric Youngdale

* The rest of this is:
*  Copyright (C) 1999 - 2004 D. Gilbert
*
*  This program is free software; you can redistribute it and/or modify
*  it under the terms of the GNU General Public License as published by
*  the Free Software Foundation; either version 2, or (at your option)
*  any later version.
*
*  ASCII values for a number of symbolic constants, printing functions, etc.
*
*  Some of the tables have been updated for SCSI 2.
*  Additions for SCSI 3+ (SPC-3 T10/1416-D Rev 12 18 March 2003)
*
*  Version 0.91 (20031116)
*      sense key specific field (bytes 15-17) decoding [Trent Piepho]
*  Version 0.92 (20031203)
*      add sg_decode_sense()
*  Version 0.93 (20040708)
*      broaden command naming, maintenance/service in/out + variable length
*/

#define OUTP stderr

static const unsigned char scsi_command_size[8] = { 6, 10, 10, 12,
                                                   16, 12, 10, 10 };

#define COMMAND_SIZE(opcode) scsi_command_size[((opcode) >> 5) & 7]

static const char unknown[] = "UNKNOWN";

/* Commands with service actions that change the command name */
#define SG_MAINTENANCE_IN 0xa3
#define SG_MAINTENANCE_OUT 0xa4
#define SG_SERVICE_ACTION_IN_12 0xab
#define SG_SERVICE_ACTION_OUT_12 0xa9
#define SG_SERVICE_ACTION_IN_16 0x9e
#define SG_SERVICE_ACTION_OUT_16 0x9f
#define SG_VARIABLE_LENGTH_CMD 0x7f

struct value_name_t {
    int value;
    int peri_dev_type; /* only non-zero to disambiguate */
    const char * name;
};

static const struct value_name_t group_0_opcodes[] = {
    {0, 0, "Test Unit Ready"},
    {0x1, 0, "Rezero Unit"},
    {0x1, 1, "Rewind"},
    {0x3, 0, "Request Sense"},
    {0x4, 0, "Format Unit"},
    {0x4, 1, "Format medium"},
    {0x4, 2, "Format"},
    {0x5, 0, "Read Block Limits"},
    {0x7, 0, "Reassign Blocks"},
    {0x7, 8, "Initialize element status"},
    {0x8, 0, "Read(6)"},
    {0x8, 3, "Receive"},
    {0xa, 0, "Write(6)"},
    {0xa, 3, "Send"},
    {0xb, 0, "Seek(6)"},
    {0xb, 1, "Set capacity"},
    {0xb, 2, "Slew and print"},
    {0xf, 0, "Read reverse(6)"},
    {0x10, 0, "Write filemarks(6)"},
    {0x10, 2, "Synchronize buffer"},
    {0x11, 0, "Space(6)"},
    {0x12, 0, "Inquiry"},
    {0x13, 0, "Verify"},
    {0x14, 0, "Recover buffered data"},
    {0x15, 0, "Mode select(6)"},
    {0x16, 0, "Reserve(6)"},
    {0x16, 8, "Reserve element(6)"},
    {0x17, 0, "Release(6)"},
    {0x17, 8, "Release element(6)"},
    {0x18, 0, "Copy"},
    {0x19, 0, "Erase(6)"},
    {0x1a, 0, "Mode sense(6)"},
    {0x1b, 0, "Start stop unit"},
    {0x1b, 1, "Load unload"},
    {0x1b, 0x12, "Load unload"},
    {0x1b, 2, "Stop print"},
    {0x1c, 0, "Receive diagnostic results"},
    {0x1d, 0, "Send diagnostic results"},
    {0x1e, 0, "Prevent allow medium removal"},
};

#define GROUP_0_OPCODES_SZ \
        (int)(sizeof(group_0_opcodes) / sizeof(group_0_opcodes[0]))


static const struct value_name_t group_1_opcodes[] = {
    {0x23, 0, "Read Format capacities"},
    {0x24, 0, "Set window"},
    {0x25, 0, "Read capacity(10)"},
    {0x25, 0xf, "Read card capacity"},
    {0x28, 0, "Read(10)"},
    {0x29, 0, "Read generation"},
    {0x2a, 0, "Write(10)"},
    {0x2b, 0, "Seek(10)"},
    {0x2b, 1, "Locate(10)"},
    {0x2b, 8, "Position to element"},
    {0x2c, 0, "Erase(10)"},
    {0x2d, 0, "Read updated block"},
    {0x2e, 0, "Write and verify(10)"},
    {0x2f, 0, "Verify(10)"},
    {0x30, 0, "Search data high(10)"},
    {0x31, 0, "Search data equal(10)"},
    {0x32, 0, "Search data low(10)"},
    {0x33, 0, "Set limits(10)"},
    {0x34, 0, "Pre-fetch(10)"},
    {0x35, 0, "Synchronize cache(10)"},
    {0x36, 0, "Lock unlock cache(10)"},
    {0x37, 0, "Read defect data(10)"},
    {0x37, 8, "Initialize element status with range"},
    {0x38, 0, "Medium scan"},
    {0x39, 0, "Compare"},
    {0x3a, 0, "Copy and verify"},
    {0x3b, 0, "Write buffer"},
    {0x3c, 0, "Read buffer"},
    {0x3d, 0, "Update block"},
    {0x3e, 0, "Read long(10)"},
    {0x3f, 0, "Write long(10)"},
};

#define GROUP_1_OPCODES_SZ \
        (int)(sizeof(group_1_opcodes) / sizeof(group_1_opcodes[0]))


static const struct value_name_t group_2_opcodes[] = {
    {0x40, 0, "Change definition"},
    {0x41, 0, "Write same(10)"},
    {0x42, 0, "Read sub-channel"},
    {0x43, 0, "Read TOC/PMA/ATIP"},
    {0x44, 0, "Report density support"},
    {0x45, 0, "Play audio(10)"},
    {0x46, 0, "Get configuration"},
    {0x47, 0, "Play audio msf"},
    {0x4a, 0, "Get event status notification"},
    {0x4b, 0, "Pause/resume"},
    {0x4c, 0, "Log select"},
    {0x4d, 0, "Log sense"},
    {0x4e, 0, "Stop play/scan"},
    {0x50, 0, "Xdwrite(10)"},
    {0x51, 0, "Xpwrite(10)"},
    {0x51, 5, "Read disk information"},
    {0x52, 0, "Xdread(10)"},
    {0x52, 5, "Read track information"},
    {0x53, 0, "Reserve track"},
    {0x54, 0, "Send OPC information"},
    {0x55, 0, "Mode select(10)"},
    {0x56, 0, "Reserve(10)"},
    {0x57, 0, "Release(10)"},
    {0x58, 0, "Repair track"},
    {0x5a, 0, "Mode sense(10)"},
    {0x5b, 0, "Close track/session"},
    {0x5c, 0, "Read buffer capacity"},
    {0x5d, 0, "Send cue sheet"},
    {0x5e, 0, "Persistent reserve in"},
    {0x5f, 0, "Persistent reserve out"},
};

#define GROUP_2_OPCODES_SZ \
        (int)(sizeof(group_2_opcodes) / sizeof(group_2_opcodes[0]))


/* The following are 16 byte commands in group 4 */
static const struct value_name_t group_4_opcodes[] = {
    {0x80, 0, "Xdwrite extended(16)"},
    {0x80, 1, "Write filemarks(16)"},
    {0x81, 0, "Rebuild(16)"},
    {0x81, 1, "Read reverse(16)"},
    {0x82, 0, "Regenerate(16)"},
    {0x83, 0, "Extended copy"},
    {0x84, 0, "Receive copy results"},
    {0x86, 0, "Access control in"},
    {0x87, 0, "Access control out"},
    {0x88, 0, "Read(16)"},
    {0x8a, 0, "Write(16)"},
    {0x8c, 0, "Read attribute"},
    {0x8d, 0, "Write attribute"},
    {0x8e, 0, "Write and verify(16)"},
    {0x8f, 0, "Verify(16)"},
    {0x90, 0, "Pre-fetch(16)"},
    {0x91, 0, "Synchronize cache(16)"},
    {0x91, 1, "Space(16)"},
    {0x92, 0, "Lock unlock cache(16)"},
    {0x92, 1, "Locate(16)"},
    {0x93, 0, "Write same(16)"},
    {0x93, 1, "Erase(16)"},
    {0x9e, 0, "Service action in(16)"},
    {0x9f, 0, "Service action out(16)"},
};

#define GROUP_4_OPCODES_SZ \
        (int)(sizeof(group_4_opcodes) / sizeof(group_4_opcodes[0]))


/* The following are 12 byte commands in group 5 */
static const struct value_name_t group_5_opcodes[] = {
    {0xa0, 0, "Report luns"},
    {0xa1, 0, "Blank"},
    {0xa3, 0, "Maintenance in"},
    {0xa3, 5, "Send key"},
    {0xa4, 0, "Maintenance out"},
    {0xa4, 5, "Report key"},
    {0xa5, 0, "Move medium"},
    {0xa5, 5, "Play audio(12)"},
    {0xa6, 0, "Exchange medium"},
    {0xa6, 5, "Load/unload cd/dvd"},
    {0xa7, 0, "Move medium attached"},
    {0xa7, 1, "Set read ahead"},
    {0xa8, 0, "Read(12)"},
    {0xa9, 0, "Service action out(12)"},
    {0xaa, 0, "Write(12)"},
    {0xab, 0, "Service action in(12)"},
    {0xac, 0, "erase(12)"},
    {0xac, 5, "Get performance"},
    {0xad, 0, "Read dvd structure"},
    {0xae, 0, "Write and verify(12)"},
    {0xaf, 0, "Verify(12)"},
    {0xb0, 0, "Search data high(12)"},
    {0xb1, 0, "Search data equal(12)"},
    {0xb2, 0, "Search data low(12)"},
    {0xb3, 0, "Set limits(12)"},
    {0xb4, 0, "Read element status attached"},
    {0xb5, 0, "Request volume element address"},
    {0xb6, 0, "Set volume tag"},
    {0xb7, 0, "Read defect data(12)"},
    {0xb8, 0, "Read element status"},
    {0xb9, 0, "Read CD msf"},
    {0xba, 0, "Redundancy group in"},
    {0xba, 5, "Scan"},
    {0xbb, 0, "Redundancy group out"},
    {0xbb, 5, "Set CD speed"},
    {0xbc, 0, "Spare in"},
    {0xbd, 0, "Spare out"},
    {0xbd, 5, "Mechanism status"},
    {0xbe, 0, "Volume set in"},
    {0xbe, 5, "Read CD"},
    {0xbf, 0, "Volume set out"},
    {0xbf, 5, "Send DVD structure"},
};

#define GROUP_5_OPCODES_SZ \
        (int)(sizeof(group_5_opcodes) / sizeof(group_5_opcodes[0]))


static const struct value_name_t maint_in_arr[] = {
    {0x5, 0, "Report device identifier"},
    {0xa, 0, "Report target port groups"},
    {0xb, 0, "Report aliases"},
    {0xc, 0, "Report supported operation codes"},
    {0xd, 0, "Report supported task management functions"},
    {0xe, 0, "Report priority"},
};

#define MAINT_IN_SZ \
        (int)(sizeof(maint_in_arr) / sizeof(maint_in_arr[0]))

static const struct value_name_t maint_out_arr[] = {
    {0x6, 0, "Set device identifier"},
    {0xa, 0, "Set target port groups"},
    {0xb, 0, "Change aliases"},
    {0xe, 0, "Set priority"},
};

#define MAINT_OUT_SZ \
        (int)(sizeof(maint_out_arr) / sizeof(maint_out_arr[0]))

static const struct value_name_t serv_in12_arr[] = {
    {0x1, 0, "Read media serial number"},
};

#define SERV_IN12_SZ  \
        (int)(sizeof(serv_in12_arr) / sizeof(serv_in12_arr[0]))

static const struct value_name_t serv_out12_arr[] = {
    {0xff, 0, "Impossible command name"},
};

#define SERV_OUT12_SZ \
        (int)(sizeof(serv_out12_arr) / sizeof(serv_in12_arr[0]))

static const struct value_name_t serv_in16_arr[] = {
    {0x10, 1, "Read capacity(16)"},
    {0x11, 1, "Read long(16)"},
};

#define SERV_IN16_SZ  \
        (int)(sizeof(serv_in16_arr) / sizeof(serv_in16_arr[0]))

static const struct value_name_t serv_out16_arr[] = {
    {0x11, 1, "Write long(16)"},
};

#define SERV_OUT16_SZ \
        (int)(sizeof(serv_out16_arr) / sizeof(serv_in16_arr[0]))

static const struct value_name_t variable_length_arr[] = {
    {0x1, 0, "Rebuild(32)"},
    {0x2, 0, "Regenerate(32)"},
    {0x3, 0, "Xdread(32)"},
    {0x4, 0, "Xdwrite(32)"},
    {0x5, 0, "Xdwrite extended(32)"},
    {0x6, 0, "Xpwrite(32)"},
    {0x7, 0, "Xdwriteread(32)"},
    {0x8, 0, "Xdwrite extended(64)"},
    {0x9, 0, "Read(32)"},
    {0xa, 0, "Verify(32)"},
    {0xb, 0, "Write(32)"},
    {0xc, 0, "Write an verify(32)"},
    {0xd, 0, "Write same(32)"},
};

#define VARIABLE_LENGTH_SZ \
        (int)(sizeof(variable_length_arr) / sizeof(variable_length_arr[0]))


#define group(opcode) (((opcode) >> 5) & 7)

#define RESERVED_GROUP  (-1)
#define VENDOR_GROUP    (-2)

static const struct value_name_t reserved_arr[] = {
    {RESERVED_GROUP, 0, "RESERVED"},
};

static const struct value_name_t vendor_arr[] = {
    {VENDOR_GROUP, 0, "VENDOR SPECIFIC"},
};

static const struct value_name_t *opcode_grp_arr[] = {
    group_0_opcodes, group_1_opcodes, group_2_opcodes,
    reserved_arr, group_4_opcodes, group_5_opcodes, 
    vendor_arr, vendor_arr
};

static int opcode_grp_sz[] = {
    GROUP_0_OPCODES_SZ, GROUP_1_OPCODES_SZ, GROUP_2_OPCODES_SZ,
    1, GROUP_4_OPCODES_SZ, GROUP_5_OPCODES_SZ, 1, 1
};

/* searches 'arr' for match on 'value' then 'peri_type'. If matches
   'value' but not 'peri_type' the yields first 'value' match entry.
   There are 'arr_sz' elements of 'arr', if no match yields NULL. */
static const struct value_name_t * get_value_name(
        const struct value_name_t * arr, int arr_sz, int value, int peri_type)
{
    const struct value_name_t * maxp = arr + arr_sz;
    const struct value_name_t * vp = arr;
    const struct value_name_t * holdp;

    for (; vp < maxp; ++vp) {
        if (value == vp->value) {
            if (peri_type == vp->peri_dev_type)
                return vp;
            holdp = vp;
            while (((vp + 1) < maxp) && 
                   (value == (vp + 1)->value)) {
                ++vp;
                if (peri_type == vp->peri_dev_type)
                    return vp;
            }
            return holdp;
        }
    }
    return NULL;
}


#if 0
static void print_opcode(const unsigned char * command) {
    const char **table = opcode_arr[ group(opcode) ];

    switch ((unsigned long) table) {
    case RESERVED_GROUP:
        fprintf(OUTP, "%s(0x%02x)", reserved, opcode);
        break;
    case VENDOR_GROUP:
        fprintf(OUTP, "%s(0x%02x)", vendor, opcode);
        break;
    default:
        fprintf(OUTP, "%s",table[opcode & 0x1f]);
        break;
    }
}
#endif

#define CMD_BUFF_LEN 64

void sg_print_command(const unsigned char * command) 
{
    int k, sz;
    char buff[CMD_BUFF_LEN];

    sg_get_command_name(command, 0, CMD_BUFF_LEN, buff);
    buff[CMD_BUFF_LEN - 1] = '\0';

    fprintf(OUTP, "%s [", buff);
    if (SG_VARIABLE_LENGTH_CMD == command[0]) 
        sz = command[7] + 8;
    else
        sz = COMMAND_SIZE(command[0]);
    for (k = 0; k < sz; ++k)
        fprintf(OUTP, "%02x ", command[k]);
    fprintf(OUTP, "]\n");
}

void sg_print_status(int masked_status) 
{
    int scsi_status = (masked_status << 1) & 0x7e;

    sg_print_scsi_status(scsi_status);
}

void sg_print_scsi_status(int scsi_status) 
{
    const char * ccp;

    scsi_status &= 0x7e; /* sanitize as much as possible */
    switch (scsi_status) {
        case 0: ccp = "Good"; break;
        case 0x2: ccp = "Check Condition"; break;
        case 0x4: ccp = "Condition Met"; break;
        case 0x8: ccp = "Busy"; break;
        case 0x10: ccp = "Intermediate"; break;
        case 0x14: ccp = "Intermediate-Condition Met"; break;
        case 0x18: ccp = "Reservation Conflict"; break;
        case 0x22: ccp = "Command Terminated (obsolete)"; break;
        case 0x28: ccp = "Task set Full"; break;
        case 0x30: ccp = "ACA Active"; break;
        case 0x40: ccp = "Task Aborted"; break;
        default: ccp = "Unknown status"; break;
    }
    fprintf(OUTP, "%s ", ccp);
}

/* In brackets is the related SCSI document (see www.t10.org) with the */
/* peripheral device type after the colon */
/* No programmatic use is made of these flags currently */
#define D 0x0001  /* DIRECT ACCESS DEVICE (disk) [SBC-2: 0] */
#define T 0x0002  /* SEQUENTIAL ACCESS DEVICE (tape) [SSC: 1] */
#define L 0x0004  /* PRINTER DEVICE [SSC: 2] */
#define P 0x0008  /* PROCESSOR DEVICE [SPC-2: 3] */
#define W 0x0010  /* WRITE ONCE READ MULTIPLE DEVICE [SBC-2: 4] */
#define R 0x0020  /* CD/DVD DEVICE [MMC-2: 5] */
#define S 0x0040  /* SCANNER DEVICE [SCSI-2 (obsolete): 6] */
#define O 0x0080  /* OPTICAL MEMORY DEVICE [SBC-2: 7] */
#define M 0x0100  /* MEDIA CHANGER DEVICE [SMC-2: 8] */
#define C 0x0200  /* COMMUNICATION DEVICE [SCSI-2 (obsolete): 9] */
#define A 0x0400  /* ARRAY STORAGE [SCC-2: 12] */
#define E 0x0800  /* ENCLOSURE SERVICES DEVICE [SES: 13] */
#define B 0x1000  /* SIMPLIFIED DIRECT ACCESS DEVICE [RBC: 14] */
#define K 0x2000  /* OPTICAL CARD READER/WRITER DEVICE [OCRW: 15] */
#define V 0x4000  /* AUTOMATION/DRIVE INTERFACE [ADC] */
#define F 0x4000  /* OBJECT-BASED STORAGE [OSD] */

#define SC_ALL_DEVS ( D|T|L|P|W|R|S|O|M|C|A|E|B|K|V|F )


struct error_info{
    unsigned char code1, code2;
    unsigned short int devices;
    const char * text;
};

struct error_info2{
    unsigned char code1, code2_min, code2_max;
    unsigned short int devices;
    const char * text;
};

static struct error_info2 additional2[] =
{
  {0x40,0x00,0x7f,D,"Ram failure [0x%x]"},
  {0x40,0x80,0xff,SC_ALL_DEVS,"Diagnostic failure on component [0x%x]"},
  {0x41,0x00,0xff,D,"Data path failure [0x%x]"},
  {0x42,0x00,0xff,D,"Power-on or self-test failure [0x%x]"},
  {0x4d,0x00,0xff,SC_ALL_DEVS,"Tagged overlapped commands [0x%x]"},
  {0x70,0x00,0xff,T,"Decompression exception short algorithm id of 0x%x"},
  {0, 0, 0, 0, NULL}
};

static struct error_info additional[] =
{
  {0x00,0x00,SC_ALL_DEVS,"No additional sense information"},
  {0x00,0x01,T,"Filemark detected"},
  {0x00,0x02,T|S,"End-of-partition/medium detected"},
  {0x00,0x03,T,"Setmark detected"},
  {0x00,0x04,T|S,"Beginning-of-partition/medium detected"},
  {0x00,0x05,T|L|S,"End-of-data detected"},
  {0x00,0x06,SC_ALL_DEVS,"I/O process terminated"},
  {0x00,0x11,R,"Audio play operation in progress"},
  {0x00,0x12,R,"Audio play operation paused"},
  {0x00,0x13,R,"Audio play operation successfully completed"},
  {0x00,0x14,R,"Audio play operation stopped due to error"},
  {0x00,0x15,R,"No current audio status to return"},
  {0x00,0x16,SC_ALL_DEVS,"operation in progress"},
  {0x00,0x17,D|T|L|W|R|S|O|M|A|E|B|K|V|F,"Cleaning requested"},
  {0x00,0x18,T,"Erase operation in progress"},
  {0x00,0x19,T,"Locate operation in progress"},
  {0x00,0x1a,T,"Rewind operation in progress"},
  {0x00,0x1b,T,"Set capacity operation in progress"},
  {0x00,0x1c,T,"Verify operation in progress"},
  {0x01,0x00,D|W|O|B|K,"No index/sector signal"},
  {0x02,0x00,D|W|R|O|M|B|K,"No seek complete"},
  {0x03,0x00,D|T|L|W|S|O|B|K,"Peripheral device write fault"},
  {0x03,0x01,T,"No write current"},
  {0x03,0x02,T,"Excessive write errors"},
  {0x04,0x00,SC_ALL_DEVS,"Logical unit not ready, cause not reportable"},
  {0x04,0x01,SC_ALL_DEVS,"Logical unit is in progress of becoming ready"},
  {0x04,0x02,SC_ALL_DEVS,"Logical unit not ready, " 
                "initializing command required"},
  {0x04,0x03,SC_ALL_DEVS,"Logical unit not ready, " 
                "manual intervention required"},
  {0x04,0x04,D|T|L|R|O|B,"Logical unit not ready, format in progress"},
  {0x04,0x05,D|T|W|O|M|C|A|B|K,"Logical unit not ready, " 
                "rebuild in progress"},
  {0x04,0x06,D|T|W|O|M|C|A|B|K,"Logical unit not ready, " 
                "recalculation in progress"},
  {0x04,0x07,SC_ALL_DEVS,"Logical unit not ready, operation in progress"},
  {0x04,0x08,R,"Logical unit not ready, long write in progress"},
  {0x04,0x09,SC_ALL_DEVS,"Logical unit not ready, self-test in progress"},
  {0x04,0x0a,SC_ALL_DEVS,"Logical unit " 
                "not accessible, asymmetric access state transition"},
  {0x04,0x0b,SC_ALL_DEVS,"Logical unit " 
                "not accessible, target port in standby state"},
  {0x04,0x0c,SC_ALL_DEVS,"Logical unit " 
                "not accessible, target port in unavailable state"},
  {0x04,0x10,SC_ALL_DEVS,"Logical unit not ready, "
                "auxiliary memory not accessible"},
  {0x04,0x11,SC_ALL_DEVS,"Logical unit not ready, "
                "notofy (enable spinup) required"},
  {0x05,0x00,D|T|L|W|R|S|O|M|C|A|E|B|K|V|F,"Logical unit " 
                "does not respond to selection"},
  {0x06,0x00,D|W|R|O|M|B|K,"No reference position found"},
  {0x07,0x00,D|T|L|W|R|S|O|M|B|K,"Multiple peripheral devices selected"},
  {0x08,0x00,D|T|L|W|R|S|O|M|C|A|E|B|K|V|F,"Logical unit " 
                "communication failure"},
  {0x08,0x01,D|T|L|W|R|S|O|M|C|A|E|B|K|V|F,"Logical unit " 
                "communication time-out"},
  {0x08,0x02,D|T|L|W|R|S|O|M|C|A|E|B|K|V|F,"Logical unit " 
                "communication parity error"},
  {0x08,0x03,D|T|R|O|M|B|K,"Logical unit " 
                "communication CRC error (Ultra-DMA/32)"},
  {0x08,0x04,D|T|L|P|W|R|S|O|C|K,"Unreachable copy target"},
  {0x09,0x00,D|T|W|R|O|B,"Track following error"},
  {0x09,0x01,W|R|O|K,"Tracking servo failure"},
  {0x09,0x02,W|R|O|K,"Focus servo failure"},
  {0x09,0x03,W|R|O,"Spindle servo failure"},
  {0x09,0x04,D|T|W|R|O|B,"Head select fault"},
  {0x0A,0x00,SC_ALL_DEVS,"Error log overflow"},
  {0x0B,0x00,SC_ALL_DEVS,"Warning"},
  {0x0B,0x01,SC_ALL_DEVS,"Warning - specified temperature exceeded"},
  {0x0B,0x02,SC_ALL_DEVS,"Warning - enclosure degraded"},
  {0x0C,0x00,T|R|S,"Write error"},
  {0x0C,0x01,K,"Write error - recovered with auto reallocation"},
  {0x0C,0x02,D|W|O|B|K,"Write error - auto reallocation failed"},
  {0x0C,0x03,D|W|O|B|K,"Write error - recommend reassignment"},
  {0x0C,0x04,D|T|W|O|B,"Compression check miscompare error"},
  {0x0C,0x05,D|T|W|O|B,"Data expansion occurred during compression"},
  {0x0C,0x06,D|T|W|O|B,"Block not compressible"},
  {0x0C,0x07,R,"Write error - recovery needed"},
  {0x0C,0x08,R,"Write error - recovery failed"},
  {0x0C,0x09,R,"Write error - loss of streaming"},
  {0x0C,0x0A,R,"Write error - padding blocks added"},
  {0x0C,0x0B,D|T|W|R|O|M|B,"Auxiliary memory write error"},
  {0x0C,0x0C,SC_ALL_DEVS,"Write error - unexpected unsolicited data"},
  {0x0C,0x0D,SC_ALL_DEVS,"Write error - not enough unsolicited data"},
  {0x0D,0x00,D|T|L|P|W|R|S|O|C|A|K,
                "Error detected by third party temporary initiator"},
  {0x0D,0x01,D|T|L|P|W|R|S|O|C|A|K, "Third party device failure"},
  {0x0D,0x02,D|T|L|P|W|R|S|O|C|A|K, "Copy target device not reachable"},
  {0x0D,0x03,D|T|L|P|W|R|S|O|C|A|K, "Incorrect copy target device"},
  {0x0D,0x04,D|T|L|P|W|R|S|O|C|A|K, "Copy target device underrun"},
  {0x0D,0x05,D|T|L|P|W|R|S|O|C|A|K, "Copy target device overrun"},
  {0x10,0x00,D|W|O|B|K,"Id CRC or ECC error"},
  {0x10,0x01,D|T|W|O,"Data block guard check failed"},
  {0x10,0x02,D|T|W|O,"Data block application tag check failed"},
  {0x10,0x03,D|T|W|O,"Data block reference tag check failed"},
  {0x11,0x00,D|T|W|R|S|O|B|K,"Unrecovered read error"},
  {0x11,0x01,D|T|W|R|S|O|B|K,"Read retries exhausted"},
  {0x11,0x02,D|T|W|R|S|O|B|K,"Error too long to correct"},
  {0x11,0x03,D|T|W|S|O|B|K,"Multiple read errors"},
  {0x11,0x04,D|W|O|B|K,"Unrecovered read error - auto reallocate failed"},
  {0x11,0x05,W|R|O|B,"L-EC uncorrectable error"},
  {0x11,0x06,W|R|O|B,"CIRC unrecovered error"},
  {0x11,0x07,W|O|B,"Data re-synchronization error"},
  {0x11,0x08,T,"Incomplete block read"},
  {0x11,0x09,T,"No gap found"},
  {0x11,0x0A,D|T|O|B|K,"Miscorrected error"},
  {0x11,0x0B,D|W|O|B|K,"Unrecovered read error - recommend reassignment"},
  {0x11,0x0C,D|W|O|B|K,"Unrecovered read error - recommend rewrite the data"},
  {0x11,0x0D,D|T|W|R|O|B,"De-compression CRC error"},
  {0x11,0x0E,D|T|W|R|O|B,"Cannot decompress using declared algorithm"},
  {0x11,0x0F,R,"Error reading UPC/EAN number"},
  {0x11,0x10,R,"Error reading ISRC number"},
  {0x11,0x11,R,"Read error - loss of streaming"},
  {0x11,0x12,D|T|W|R|O|M|B,"Auxiliary memory read error"},
  {0x11,0x13,SC_ALL_DEVS,"Read error - failed retransmission request"},
  {0x12,0x00,D|W|O|B|K,"Address mark not found for id field"},
  {0x13,0x00,D|W|O|B|K,"Address mark not found for data field"},
  {0x14,0x00,D|T|L|W|R|S|O|B|K,"Recorded entity not found"},
  {0x14,0x01,D|T|W|R|O|B|K,"Record not found"},
  {0x14,0x02,T,"Filemark or setmark not found"},
  {0x14,0x03,T,"End-of-data not found"},
  {0x14,0x04,T,"Block sequence error"},
  {0x14,0x05,D|T|W|O|B|K,"Record not found - recommend reassignment"},
  {0x14,0x06,D|T|W|O|B|K,"Record not found - data auto-reallocated"},
  {0x14,0x07,T,"Locate operation failure"},
  {0x15,0x00,D|T|L|W|R|S|O|M|B|K,"Random positioning error"},
  {0x15,0x01,D|T|L|W|R|S|O|M|B|K,"Mechanical positioning error"},
  {0x15,0x02,D|T|W|R|O|B|K,"Positioning error detected by read of medium"},
  {0x16,0x00,D|W|O|B|K,"Data synchronization mark error"},
  {0x16,0x01,D|W|O|B|K,"Data sync error - data rewritten"},
  {0x16,0x02,D|W|O|B|K,"Data sync error - recommend rewrite"},
  {0x16,0x03,D|W|O|B|K,"Data sync error - data auto-reallocated"},
  {0x16,0x04,D|W|O|B|K,"Data sync error - recommend reassignment"},
  {0x17,0x00,D|T|W|R|S|O|B|K,"Recovered data " 
                "with no error correction applied"},
  {0x17,0x01,D|T|W|R|S|O|B|K,"Recovered data with retries"},
  {0x17,0x02,D|T|W|R|O|B|K,"Recovered data with positive head offset"},
  {0x17,0x03,D|T|W|R|O|B|K,"Recovered data with negative head offset"},
  {0x17,0x04,W|R|O|B,"Recovered data with retries and/or circ applied"},
  {0x17,0x05,D|W|R|O|B|K,"Recovered data using previous sector id"},
  {0x17,0x06,D|W|O|B|K,"Recovered data without ecc - data auto-reallocated"},
  {0x17,0x07,D|W|R|O|B|K,"Recovered data " 
                "without ecc - recommend reassignment"},
  {0x17,0x08,D|W|R|O|B|K,"Recovered data without ecc - recommend rewrite"},
  {0x17,0x09,D|W|R|O|B|K,"Recovered data without ecc - data rewritten"},
  {0x18,0x00,D|T|W|R|O|B|K,"Recovered data with error correction applied"},
  {0x18,0x01,D|W|R|O|B|K,"Recovered data " 
                "with error corr. & retries applied"},
  {0x18,0x02,D|W|R|O|B|K,"Recovered data - data auto-reallocated"},
  {0x18,0x03,R,"Recovered data with CIRC"},
  {0x18,0x04,R,"Recovered data with L-EC"},
  {0x18,0x05,D|W|R|O|B|K,"Recovered data - recommend reassignment"},
  {0x18,0x06,D|W|R|O|B|K,"Recovered data - recommend rewrite"},
  {0x18,0x07,D|W|O|B|K,"Recovered data with ecc - data rewritten"},
  {0x18,0x08,R,"Recovered data with linking"},
  {0x19,0x00,D|O|K,"Defect list error"},
  {0x19,0x01,D|O|K,"Defect list not available"},
  {0x19,0x02,D|O|K,"Defect list error in primary list"},
  {0x19,0x03,D|O|K,"Defect list error in grown list"},
  {0x1A,0x00,SC_ALL_DEVS,"Parameter list length error"},
  {0x1B,0x00,SC_ALL_DEVS,"Synchronous data transfer error"},
  {0x1C,0x00,D|O|B|K,"Defect list not found"},
  {0x1C,0x01,D|O|B|K,"Primary defect list not found"},
  {0x1C,0x02,D|O|B|K,"Grown defect list not found"},
  {0x1D,0x00,D|T|W|R|O|B|K,"Miscompare during verify operation"},
  {0x1E,0x00,D|W|O|B|K,"Recovered id with ecc correction"},
  {0x1F,0x00,D|O|K,"Partial defect list transfer"},
  {0x20,0x00,SC_ALL_DEVS,"Invalid command operation code"},
  {0x20,0x01,D|T|P|W|R|O|M|A|E|B|K,
        "Access denied - initiator pending-enrolled"},
  {0x20,0x02,D|T|P|W|R|O|M|A|E|B|K,"Access denied - no access rights"},
  {0x20,0x03,D|T|P|W|R|O|M|A|E|B|K,"Access denied - no mgmt id key"},
  {0x20,0x04,T,"Illegal command while in write capable state"},
  {0x20,0x05,T,"Obsolete"},
  {0x20,0x06,T,"Illegal command while in explicit address mode"},
  {0x20,0x07,T,"Illegal command while in implicit address mode"},
  {0x20,0x08,D|T|P|W|R|O|M|A|E|B|K,"Access denied - enrollment conflict"},
  {0x20,0x09,D|T|P|W|R|O|M|A|E|B|K,"Access denied - invalid LU identifier"},
  {0x20,0x0A,D|T|P|W|R|O|M|A|E|B|K,"Access denied - invalid proxy token"},
  {0x20,0x0B,D|T|P|W|R|O|M|A|E|B|K,"Access denied - ACL LUN conflict"},
  {0x21,0x00,D|T|W|R|O|M|B|K,"Logical block address out of range"},
  {0x21,0x01,D|T|W|R|O|M|B|K,"Invalid element address"},
  {0x21,0x02,R,"Invalid address for write"},
  {0x22,0x00,D,"Illegal function (use 20 00,24 00,or 26 00)"},
  {0x24,0x00,SC_ALL_DEVS,"Invalid field in cdb"},
  {0x24,0x01,SC_ALL_DEVS,"CDB decryption error"},
  {0x25,0x00,SC_ALL_DEVS,"Logical unit not supported"},
  {0x26,0x00,SC_ALL_DEVS,"Invalid field in parameter list"},
  {0x26,0x01,SC_ALL_DEVS,"Parameter not supported"},
  {0x26,0x02,SC_ALL_DEVS,"Parameter value invalid"},
  {0x26,0x03,D|T|L|P|W|R|S|O|M|C|A|E|K,"Threshold parameters not supported"},
  {0x26,0x04,SC_ALL_DEVS,"Invalid release of persistent reservation"},
  {0x26,0x05,D|T|L|P|W|R|S|O|M|C|A|B|K,"Data decryption error"},
  {0x26,0x06,D|T|L|P|W|R|S|O|C|K,"Too many target descriptors"},
  {0x26,0x07,D|T|L|P|W|R|S|O|C|K,"Unsupported target descriptor type code"},
  {0x26,0x08,D|T|L|P|W|R|S|O|C|K,"Too many segment descriptors"},
  {0x26,0x09,D|T|L|P|W|R|S|O|C|K,"Unsupported segment descriptor type code"},
  {0x26,0x0A,D|T|L|P|W|R|S|O|C|K,"Unexpected inexact segment"},
  {0x26,0x0B,D|T|L|P|W|R|S|O|C|K,"Inline data length exceeded"},
  {0x26,0x0C,D|T|L|P|W|R|S|O|C|K,
                "Invalid operation for copy source or destination"},
  {0x26,0x0D,D|T|L|P|W|R|S|O|C|K,"Copy segment granularity violation"},
  {0x26,0x0E,D|T|P|W|R|O|M|A|E|B|K,"Invalid parameter while port is enabled"},
  {0x26,0x0F,F,"Invalid data-out buffer integrity"},
  {0x27,0x00,D|T|W|R|O|B|K,"Write protected"},
  {0x27,0x01,D|T|W|R|O|B|K,"Hardware write protected"},
  {0x27,0x02,D|T|W|R|O|B|K,"Logical unit software write protected"},
  {0x27,0x03,T|R,"Associated write protect"},
  {0x27,0x04,T|R,"Persistent write protect"},
  {0x27,0x05,T|R,"Permanent write protect"},
  {0x27,0x06,R,"Conditional write protect"},
  {0x28,0x00,SC_ALL_DEVS,"Not ready to ready change, medium may have changed"},
  {0x28,0x01,D|T|W|R|O|M|B,"Import or export element accessed"},
  {0x29,0x00,SC_ALL_DEVS,"Power on, reset, or bus device reset occurred"},
  {0x29,0x01,SC_ALL_DEVS,"Power on occurred"},
  {0x29,0x02,SC_ALL_DEVS,"Scsi bus reset occurred"},
  {0x29,0x03,SC_ALL_DEVS,"Bus device reset function occurred"},
  {0x29,0x04,SC_ALL_DEVS,"Device internal reset"},
  {0x29,0x05,SC_ALL_DEVS,"Transceiver mode changed to single-ended"},
  {0x29,0x06,SC_ALL_DEVS,"Transceiver mode changed to lvd"},
  {0x29,0x07,SC_ALL_DEVS,"I_T nexus loss occurred"},
  {0x2A,0x00,D|T|L|W|R|S|O|M|C|A|E|B|K|V|F,"Parameters changed"},
  {0x2A,0x01,D|T|L|W|R|S|O|M|C|A|E|B|K|V|F,"Mode parameters changed"},
  {0x2A,0x02,D|T|L|W|R|S|O|M|C|A|E|K,"Log parameters changed"},
  {0x2A,0x03,D|T|L|P|W|R|S|O|M|C|A|E|K,"Reservations preempted"},
  {0x2A,0x04,D|T|L|P|W|R|S|O|M|C|A|E,"Reservations released"},
  {0x2A,0x05,D|T|L|P|W|R|S|O|M|C|A|E,"Registrations preempted"},
  {0x2A,0x06,SC_ALL_DEVS,"Asymmetric access state changed"},
  {0x2A,0x07,SC_ALL_DEVS,"Implicit asymmetric access state transition failed"},
  {0x2A,0x08,D|T|W|R|O|M|A|E|B|K|V|F,"Priority changed"},
  {0x2B,0x00,D|T|L|P|W|R|S|O|C|K,
                "Copy cannot execute since host cannot disconnect"},
  {0x2C,0x00,SC_ALL_DEVS,"Command sequence error"},
  {0x2C,0x01,S,"Too many windows specified"},
  {0x2C,0x02,S,"Invalid combination of windows specified"},
  {0x2C,0x03,R,"Current program area is not empty"},
  {0x2C,0x04,R,"Current program area is empty"},
  {0x2C,0x05,B,"Illegal power condition request"},
  {0x2C,0x06,R,"Persistent prevent conflict"},
  {0x2C,0x07,SC_ALL_DEVS,"Previous busy status"},
  {0x2C,0x08,SC_ALL_DEVS,"Previous task set full status"},
  {0x2C,0x09,D|T|L|P|W|R|S|O|M|E|B|K|V|F,
                "Previous reservation conflict status"},
  {0x2C,0x0A,F,"Partition or collection contains user objects"},
  {0x2C,0x0B,T,"Not reserved"},
  {0x2D,0x00,T,"Overwrite error on update in place"},
  {0x2E,0x00,R,"Insufficient time for operation"},
  {0x2F,0x00,SC_ALL_DEVS,"Commands cleared by another initiator"},
  {0x30,0x00,D|T|W|R|O|M|B|K,"Incompatible medium installed"},
  {0x30,0x01,D|T|W|R|O|B|K,"Cannot read medium - unknown format"},
  {0x30,0x02,D|T|W|R|O|B|K,"Cannot read medium - incompatible format"},
  {0x30,0x03,D|T|R|K,"Cleaning cartridge installed"},
  {0x30,0x04,D|T|W|R|O|B|K,"Cannot write medium - unknown format"},
  {0x30,0x05,D|T|W|R|O|B|K,"Cannot write medium - incompatible format"},
  {0x30,0x06,D|T|W|R|O|B,"Cannot format medium - incompatible medium"},
  {0x30,0x07,D|T|L|W|R|S|O|M|A|E|B|K|V|F,"Cleaning failure"},
  {0x30,0x08,R,"Cannot write - application code mismatch"},
  {0x30,0x09,R,"Current session not fixated for append"},
  {0x30,0x0A,D|T|W|R|O|M|A|E|B|K,"Cleaning request rejected"},
  {0x30,0x10,R,"Medium not formatted"}, /* should ascq be 0xa ?? */
  {0x31,0x00,D|T|W|R|O|B|K,"Medium format corrupted"},
  {0x31,0x01,D|L|R|O|B,"Format command failed"},
  {0x31,0x02,R,"Zoned formatting failed due to spare linking"},
  {0x32,0x00,D|W|O|B|K,"No defect spare location available"},
  {0x32,0x01,D|W|O|B|K,"Defect list update failure"},
  {0x33,0x00,T,"Tape length error"},
  {0x34,0x00,SC_ALL_DEVS,"Enclosure failure"},
  {0x35,0x00,SC_ALL_DEVS,"Enclosure services failure"},
  {0x35,0x01,SC_ALL_DEVS,"Unsupported enclosure function"},
  {0x35,0x02,SC_ALL_DEVS,"Enclosure services unavailable"},
  {0x35,0x03,SC_ALL_DEVS,"Enclosure services transfer failure"},
  {0x35,0x04,SC_ALL_DEVS,"Enclosure services transfer refused"},
  {0x35,0x05,SC_ALL_DEVS,"Enclosure services checksum error"},
  {0x36,0x00,L,"Ribbon,ink,or toner failure"},
  {0x37,0x00,D|T|L|W|R|S|O|M|C|A|E|B|K|V|F,"Rounded parameter"},
  {0x38,0x00,B,"Event status notification"},
  {0x38,0x02,B,"Esn - power management class event"},
  {0x38,0x04,B,"Esn - media class event"},
  {0x38,0x06,B,"Esn - device busy class event"},
  {0x39,0x00,D|T|L|W|R|S|O|M|C|A|E|K,"Saving parameters not supported"},
  {0x3A,0x00,D|T|L|W|R|S|O|M|B|K,"Medium not present"},
  {0x3A,0x01,D|T|W|R|O|M|B|K,"Medium not present - tray closed"},
  {0x3A,0x02,D|T|W|R|O|M|B|K,"Medium not present - tray open"},
  {0x3A,0x03,D|T|W|R|O|M|B,"Medium not present - loadable"},
  {0x3A,0x04,D|T|W|R|O|M|B,
                "Medium not present - medium auxiliary memory accessible"},
  {0x3B,0x00,T|L,"Sequential positioning error"},
  {0x3B,0x01,T,"Tape position error at beginning-of-medium"},
  {0x3B,0x02,T,"Tape position error at end-of-medium"},
  {0x3B,0x03,L,"Tape or electronic vertical forms unit not ready, "},
  {0x3B,0x04,L,"Slew failure"},
  {0x3B,0x05,L,"Paper jam"},
  {0x3B,0x06,L,"Failed to sense top-of-form"},
  {0x3B,0x07,L,"Failed to sense bottom-of-form"},
  {0x3B,0x08,T,"Reposition error"},
  {0x3B,0x09,S,"Read past end of medium"},
  {0x3B,0x0A,S,"Read past beginning of medium"},
  {0x3B,0x0B,S,"Position past end of medium"},
  {0x3B,0x0C,T|S,"Position past beginning of medium"},
  {0x3B,0x0D,D|T|W|R|O|M|B|K,"Medium destination element full"},
  {0x3B,0x0E,D|T|W|R|O|M|B|K,"Medium source element empty"},
  {0x3B,0x0F,R,"End of medium reached"},
  {0x3B,0x11,D|T|W|R|O|M|B|K,"Medium magazine not accessible"},
  {0x3B,0x12,D|T|W|R|O|M|B|K,"Medium magazine removed"},
  {0x3B,0x13,D|T|W|R|O|M|B|K,"Medium magazine inserted"},
  {0x3B,0x14,D|T|W|R|O|M|B|K,"Medium magazine locked"},
  {0x3B,0x15,D|T|W|R|O|M|B|K,"Medium magazine unlocked"},
  {0x3B,0x16,R,"Mechanical positioning or changer error"},
  {0x3B,0x17,F,"Read past end of user object"},
  {0x3D,0x00,D|T|L|P|W|R|S|O|M|C|A|E|K,"Invalid bits in identify message"},
  {0x3E,0x00,SC_ALL_DEVS,"Logical unit has not self-configured yet"},
  {0x3E,0x01,SC_ALL_DEVS,"Logical unit failure"},
  {0x3E,0x02,SC_ALL_DEVS,"Timeout on logical unit"},
  {0x3E,0x03,SC_ALL_DEVS,"Logical unit failed self-test"},
  {0x3E,0x04,SC_ALL_DEVS,"Logical unit unable to update self-test log"},
  {0x3F,0x00,SC_ALL_DEVS,"Target operating conditions have changed"},
  {0x3F,0x01,SC_ALL_DEVS,"Microcode has been changed"},
  {0x3F,0x02,D|T|L|P|W|R|S|O|M|C|B|K,"Changed operating definition"},
  {0x3F,0x03,SC_ALL_DEVS,"Inquiry data has changed"},
  {0x3F,0x04,D|T|W|R|O|M|C|A|E|B|K,"Component device attached"},
  {0x3F,0x05,D|T|W|R|O|M|C|A|E|B|K,"Device identifier changed"},
  {0x3F,0x06,D|T|W|R|O|M|C|A|E|B,"Redundancy group created or modified"},
  {0x3F,0x07,D|T|W|R|O|M|C|A|E|B,"Redundancy group deleted"},
  {0x3F,0x08,D|T|W|R|O|M|C|A|E|B,"Spare created or modified"},
  {0x3F,0x09,D|T|W|R|O|M|C|A|E|B,"Spare deleted"},
  {0x3F,0x0A,D|T|W|R|O|M|C|A|E|B|K,"Volume set created or modified"},
  {0x3F,0x0B,D|T|W|R|O|M|C|A|E|B|K,"Volume set deleted"},
  {0x3F,0x0C,D|T|W|R|O|M|C|A|E|B|K,"Volume set deassigned"},
  {0x3F,0x0D,D|T|W|R|O|M|C|A|E|B|K,"Volume set reassigned"},
  {0x3F,0x0E,D|T|L|P|W|R|S|O|M|C|A|E,"Reported luns data has changed"},
  {0x3F,0x10,D|T|W|R|O|M|B,"Medium loadable"},
  {0x3F,0x11,D|T|W|R|O|M|B,"Medium auxiliary memory accessible"},
  /*
   * ASC 0x40, 0x41 and 0x42 overridden by "additional2" array entries
   * so there is no need to have them here.
   */
  /* {0x40,0x00,D,"Ram failure (should use 40 nn)"}, */
  /* {0x40,0x80,SC_ALL_DEVS,"Diagnostic failure on component nn (80h-ffh)"}, */
  /* {0x41,0x00,D,"Data path failure (should use 40 nn)"}, */
  {0x42,0x00,D,"Power-on or self-test failure (should use 40 nn)"},
  {0x43,0x00,SC_ALL_DEVS,"Message error"},
  {0x44,0x00,SC_ALL_DEVS,"Internal target failure"},
  {0x45,0x00,SC_ALL_DEVS,"Select or reselect failure"},
  {0x46,0x00,D|T|L|P|W|R|S|O|M|C|B|K,"Unsuccessful soft reset"},
  {0x47,0x00,SC_ALL_DEVS,"Scsi parity error"},
  {0x47,0x01,SC_ALL_DEVS,"Data phase CRC error detected"},
  {0x47,0x02,SC_ALL_DEVS,"Scsi parity error detected during st data phase"},
  {0x47,0x03,SC_ALL_DEVS,"Information unit CRC error detected"},
  {0x47,0x04,SC_ALL_DEVS,"Asynchronous information protection error detected"},
  {0x47,0x05,SC_ALL_DEVS,"Protocol service CRC error"},
  {0x47,0xFF,SC_ALL_DEVS,"Some commands cleared by iSCSI protocol event"},
  {0x48,0x00,SC_ALL_DEVS,"Initiator detected error message received"},
  {0x49,0x00,SC_ALL_DEVS,"Invalid message error"},
  {0x4A,0x00,SC_ALL_DEVS,"Command phase error"},
  {0x4B,0x00,SC_ALL_DEVS,"Data phase error"},
  {0x4B,0x01,SC_ALL_DEVS,"Invalid target port transfer tag received"},
  {0x4B,0x02,SC_ALL_DEVS,"Too much write data"},
  {0x4B,0x03,SC_ALL_DEVS,"Ack/nak timeout"},
  {0x4B,0x04,SC_ALL_DEVS,"Nak received"},
  {0x4B,0x05,SC_ALL_DEVS,"Data offset error"},
  {0x4B,0x06,SC_ALL_DEVS,"Initiator response timeout"},
  {0x4C,0x00,SC_ALL_DEVS,"Logical unit failed self-configuration"},
  /*
   * ASC 0x4D overridden by an "additional2" array entry
   * so there is no need to have them here.
   */
  /* {0x4D,0x00,SC_ALL_DEVS,"Tagged overlapped commands (nn = queue tag)"}, */
  {0x4E,0x00,SC_ALL_DEVS,"Overlapped commands attempted"},
  {0x50,0x00,T,"Write append error"},
  {0x50,0x01,T,"Write append position error"},
  {0x50,0x02,T,"Position error related to timing"},
  {0x51,0x00,T|R|O,"Erase failure"},
  {0x51,0x01,R,"Erase failure - incomplete erase operation detected"},
  {0x52,0x00,T,"Cartridge fault"},
  {0x53,0x00,D|T|L|W|R|S|O|M|B|K,"Media load or eject failed"},
  {0x53,0x01,T,"Unload tape failure"},
  {0x53,0x02,D|T|W|R|O|M|B|K,"Medium removal prevented"},
  {0x54,0x00,P,"Scsi to host system interface failure"},
  {0x55,0x00,P,"System resource failure"},
  {0x55,0x01,D|O|B|K,"System buffer full"},
  {0x55,0x02,D|T|L|P|W|R|S|O|M|A|E|K,"Insufficient reservation resources"},
  {0x55,0x03,D|T|L|P|W|R|S|O|M|C|A|E,"Insufficient resources"},
  {0x55,0x04,D|T|L|P|W|R|S|O|M|A|E,"Insufficient registration resources"},
  {0x55,0x05,D|T|P|W|R|O|M|A|E|B|K,"Insufficient access control resources"},
  {0x55,0x06,D|T|W|R|O|M|B,"Auxiliary memory out of space"},
  {0x55,0x07,F,"Quota error"},
  {0x57,0x00,R,"Unable to recover table-of-contents"},
  {0x58,0x00,O,"Generation does not exist"},
  {0x59,0x00,O,"Updated block read"},
  {0x5A,0x00,D|T|L|P|W|R|S|O|M|B|K,"Operator request or state change input"},
  {0x5A,0x01,D|T|W|R|O|M|B|K,"Operator medium removal request"},
  {0x5A,0x02,D|T|W|R|O|A|B|K,"Operator selected write protect"},
  {0x5A,0x03,D|T|W|R|O|A|B|K,"Operator selected write permit"},
  {0x5B,0x00,D|T|L|P|W|R|S|O|M|K,"Log exception"},
  {0x5B,0x01,D|T|L|P|W|R|S|O|M|K,"Threshold condition met"},
  {0x5B,0x02,D|T|L|P|W|R|S|O|M|K,"Log counter at maximum"},
  {0x5B,0x03,D|T|L|P|W|R|S|O|M|K,"Log list codes exhausted"},
  {0x5C,0x00,D|O,"Rpl status change"},
  {0x5C,0x01,D|O,"Spindles synchronized"},
  {0x5C,0x02,D|O,"Spindles not synchronized"},
  {0x5D,0x00,SC_ALL_DEVS,"Failure prediction threshold exceeded"},
  {0x5D,0x01,R|B,"Media failure prediction threshold exceeded"},
  {0x5D,0x02,R,"Logical unit failure prediction threshold exceeded"},
  {0x5D,0x03,R,"spare area exhaustion prediction threshold exceeded"},
  {0x5D,0x10,D|B,"Hardware impending failure general hard drive failure"},
  {0x5D,0x11,D|B,"Hardware impending failure drive error rate too high" },
  {0x5D,0x12,D|B,"Hardware impending failure data error rate too high" },
  {0x5D,0x13,D|B,"Hardware impending failure seek error rate too high" },
  {0x5D,0x14,D|B,"Hardware impending failure too many block reassigns"},
  {0x5D,0x15,D|B,"Hardware impending failure access times too high" },
  {0x5D,0x16,D|B,"Hardware impending failure start unit times too high" },
  {0x5D,0x17,D|B,"Hardware impending failure channel parametrics"},
  {0x5D,0x18,D|B,"Hardware impending failure controller detected"},
  {0x5D,0x19,D|B,"Hardware impending failure throughput performance"},
  {0x5D,0x1A,D|B,"Hardware impending failure seek time performance"},
  {0x5D,0x1B,D|B,"Hardware impending failure spin-up retry count"},
  {0x5D,0x1C,D|B,"Hardware impending failure drive calibration retry count"},
  {0x5D,0x20,D|B,"Controller impending failure general hard drive failure"},
  {0x5D,0x21,D|B,"Controller impending failure drive error rate too high" },
  {0x5D,0x22,D|B,"Controller impending failure data error rate too high" },
  {0x5D,0x23,D|B,"Controller impending failure seek error rate too high" },
  {0x5D,0x24,D|B,"Controller impending failure too many block reassigns"},
  {0x5D,0x25,D|B,"Controller impending failure access times too high" },
  {0x5D,0x26,D|B,"Controller impending failure start unit times too high" },
  {0x5D,0x27,D|B,"Controller impending failure channel parametrics"},
  {0x5D,0x28,D|B,"Controller impending failure controller detected"},
  {0x5D,0x29,D|B,"Controller impending failure throughput performance"},
  {0x5D,0x2A,D|B,"Controller impending failure seek time performance"},
  {0x5D,0x2B,D|B,"Controller impending failure spin-up retry count"},
  {0x5D,0x2C,D|B,"Controller impending failure drive calibration retry count"},
  {0x5D,0x30,D|B,"Data channel impending failure general hard drive failure"},
  {0x5D,0x31,D|B,"Data channel impending failure drive error rate too high" },
  {0x5D,0x32,D|B,"Data channel impending failure data error rate too high" },
  {0x5D,0x33,D|B,"Data channel impending failure seek error rate too high" },
  {0x5D,0x34,D|B,"Data channel impending failure too many block reassigns"},
  {0x5D,0x35,D|B,"Data channel impending failure access times too high" },
  {0x5D,0x36,D|B,"Data channel impending failure start unit times too high" },
  {0x5D,0x37,D|B,"Data channel impending failure channel parametrics"},
  {0x5D,0x38,D|B,"Data channel impending failure controller detected"},
  {0x5D,0x39,D|B,"Data channel impending failure throughput performance"},
  {0x5D,0x3A,D|B,"Data channel impending failure seek time performance"},
  {0x5D,0x3B,D|B,"Data channel impending failure spin-up retry count"},
  {0x5D,0x3C,D|B,"Data channel impending failure drive calibration "
                "retry count"},
  {0x5D,0x40,D|B,"Servo impending failure general hard drive failure"},
  {0x5D,0x41,D|B,"Servo impending failure drive error rate too high" },
  {0x5D,0x42,D|B,"Servo impending failure data error rate too high" },
  {0x5D,0x43,D|B,"Servo impending failure seek error rate too high" },
  {0x5D,0x44,D|B,"Servo impending failure too many block reassigns"},
  {0x5D,0x45,D|B,"Servo impending failure access times too high" },
  {0x5D,0x46,D|B,"Servo impending failure start unit times too high" },
  {0x5D,0x47,D|B,"Servo impending failure channel parametrics"},
  {0x5D,0x48,D|B,"Servo impending failure controller detected"},
  {0x5D,0x49,D|B,"Servo impending failure throughput performance"},
  {0x5D,0x4A,D|B,"Servo impending failure seek time performance"},
  {0x5D,0x4B,D|B,"Servo impending failure spin-up retry count"},
  {0x5D,0x4C,D|B,"Servo impending failure drive calibration retry count"},
  {0x5D,0x50,D|B,"Spindle impending failure general hard drive failure"},
  {0x5D,0x51,D|B,"Spindle impending failure drive error rate too high" },
  {0x5D,0x52,D|B,"Spindle impending failure data error rate too high" },
  {0x5D,0x53,D|B,"Spindle impending failure seek error rate too high" },
  {0x5D,0x54,D|B,"Spindle impending failure too many block reassigns"},
  {0x5D,0x55,D|B,"Spindle impending failure access times too high" },
  {0x5D,0x56,D|B,"Spindle impending failure start unit times too high" },
  {0x5D,0x57,D|B,"Spindle impending failure channel parametrics"},
  {0x5D,0x58,D|B,"Spindle impending failure controller detected"},
  {0x5D,0x59,D|B,"Spindle impending failure throughput performance"},
  {0x5D,0x5A,D|B,"Spindle impending failure seek time performance"},
  {0x5D,0x5B,D|B,"Spindle impending failure spin-up retry count"},
  {0x5D,0x5C,D|B,"Spindle impending failure drive calibration retry count"},
  {0x5D,0x60,D|B,"Firmware impending failure general hard drive failure"},
  {0x5D,0x61,D|B,"Firmware impending failure drive error rate too high" },
  {0x5D,0x62,D|B,"Firmware impending failure data error rate too high" },
  {0x5D,0x63,D|B,"Firmware impending failure seek error rate too high" },
  {0x5D,0x64,D|B,"Firmware impending failure too many block reassigns"},
  {0x5D,0x65,D|B,"Firmware impending failure access times too high" },
  {0x5D,0x66,D|B,"Firmware impending failure start unit times too high" },
  {0x5D,0x67,D|B,"Firmware impending failure channel parametrics"},
  {0x5D,0x68,D|B,"Firmware impending failure controller detected"},
  {0x5D,0x69,D|B,"Firmware impending failure throughput performance"},
  {0x5D,0x6A,D|B,"Firmware impending failure seek time performance"},
  {0x5D,0x6B,D|B,"Firmware impending failure spin-up retry count"},
  {0x5D,0x6C,D|B,"Firmware impending failure drive calibration retry count"},
  {0x5D,0xFF,SC_ALL_DEVS,"Failure prediction threshold exceeded (false)"},
  {0x5E,0x00,D|T|L|P|W|R|S|O|C|A|K,"Low power condition on"},
  {0x5E,0x01,D|T|L|P|W|R|S|O|C|A|K,"Idle condition activated by timer"},
  {0x5E,0x02,D|T|L|P|W|R|S|O|C|A|K,"Standby condition activated by timer"},
  {0x5E,0x03,D|T|L|P|W|R|S|O|C|A|K,"Idle condition activated by command"},
  {0x5E,0x04,D|T|L|P|W|R|S|O|C|A|K,"Standby condition activated by command"},
  {0x5E,0x41,B,"Power state change to active"},
  {0x5E,0x42,B,"Power state change to idle"},
  {0x5E,0x43,B,"Power state change to standby"},
  {0x5E,0x45,B,"Power state change to sleep"},
  {0x5E,0x47,B|K,"Power state change to device control"},
  {0x60,0x00,S,"Lamp failure"},
  {0x61,0x00,S,"Video acquisition error"},
  {0x61,0x01,S,"Unable to acquire video"},
  {0x61,0x02,S,"Out of focus"},
  {0x62,0x00,S,"Scan head positioning error"},
  {0x63,0x00,R,"End of user area encountered on this track"},
  {0x63,0x01,R,"Packet does not fit in available space"},
  {0x64,0x00,R,"Illegal mode for this track"},
  {0x64,0x01,R,"Invalid packet size"},
  {0x65,0x00,SC_ALL_DEVS,"Voltage fault"},
  {0x66,0x00,S,"Automatic document feeder cover up"},
  {0x66,0x01,S,"Automatic document feeder lift up"},
  {0x66,0x02,S,"Document jam in automatic document feeder"},
  {0x66,0x03,S,"Document miss feed automatic in document feeder"},
  {0x67,0x00,A,"Configuration failure"},
  {0x67,0x01,A,"Configuration of incapable logical units failed"},
  {0x67,0x02,A,"Add logical unit failed"},
  {0x67,0x03,A,"Modification of logical unit failed"},
  {0x67,0x04,A,"Exchange of logical unit failed"},
  {0x67,0x05,A,"Remove of logical unit failed"},
  {0x67,0x06,A,"Attachment of logical unit failed"},
  {0x67,0x07,A,"Creation of logical unit failed"},
  {0x67,0x08,A,"Assign failure occurred"},
  {0x67,0x09,A,"Multiply assigned logical unit"},
  {0x67,0x0A,SC_ALL_DEVS,"Set target port groups command failed"},
  {0x68,0x00,A,"Logical unit not configured"},
  {0x69,0x00,A,"Data loss on logical unit"},
  {0x69,0x01,A,"Multiple logical unit failures"},
  {0x69,0x02,A,"Parity/data mismatch"},
  {0x6A,0x00,A,"Informational,refer to log"},
  {0x6B,0x00,A,"State change has occurred"},
  {0x6B,0x01,A,"Redundancy level got better"},
  {0x6B,0x02,A,"Redundancy level got worse"},
  {0x6C,0x00,A,"Rebuild failure occurred"},
  {0x6D,0x00,A,"Recalculate failure occurred"},
  {0x6E,0x00,A,"Command to logical unit failed"},
  {0x6F,0x00,R,"Copy protection key exchange failure - authentication failure"},
  {0x6F,0x01,R,"Copy protection key exchange failure - key not present"},
  {0x6F,0x02,R,"Copy protection key exchange failure - key not established"},
  {0x6F,0x03,R,"Read of scrambled sector without authentication"},
  {0x6F,0x04,R,"Media region code is mismatched to logical unit region"},
  {0x6F,0x05,R,"Drive region must be permanent/region reset count error"},
  /*
   * ASC 0x70 overridden by an "additional2" array entry
   * so there is no need to have them here.
   */
  /* {0x70,0x00,T,"Decompression exception short algorithm id of nn"}, */
  {0x71,0x00,T,"Decompression exception long algorithm id"},
  {0x72,0x00,R,"Session fixation error"},
  {0x72,0x01,R,"Session fixation error writing lead-in"},
  {0x72,0x02,R,"Session fixation error writing lead-out"},
  {0x72,0x03,R,"Session fixation error - incomplete track in session"},
  {0x72,0x04,R,"Empty or partially written reserved track"},
  {0x72,0x05,R,"No more track reservations allowed"},
  {0x73,0x00,R,"Cd control error"},
  {0x73,0x01,R,"Power calibration area almost full"},
  {0x73,0x02,R,"Power calibration area is full"},
  {0x73,0x03,R,"Power calibration area error"},
  {0x73,0x04,R,"Program memory area update failure"},
  {0x73,0x05,R,"Program memory area is full"},
  {0x73,0x06,R,"RMA/PMA is full"},
  {0, 0, 0, NULL}
};

static const char *snstext[] = {
    "No Sense",                 /* There is no sense information */
    "Recovered Error",          /* The last command completed successfully
                                   but used error correction */
    "Not Ready",                /* The addressed target is not ready */
    "Medium Error",             /* Data error detected on the medium */
    "Hardware Error",           /* Controller or device failure */
    "Illegal Request",
    "Unit Attention",           /* Removable medium was changed, or
                                   the target has been reset */
    "Data Protect",             /* Access to the data is blocked */
    "Blank Check",              /* Reached unexpected written or unwritten
                                   region of the medium */
    "Key=9",                    /* Vendor specific */
    "Copy Aborted",             /* COPY or COMPARE was aborted */
    "Aborted Command",          /* The target aborted the command */
    "Equal",                    /* SEARCH DATA found data equal (obsolete) */
    "Volume Overflow",          /* Medium full with still data to be written */
    "Miscompare",               /* Source data and data on the medium
                                   do not agree */
    "Key=15"                    /* Reserved */
};

static
void sg_print_asc_ascq(unsigned char asc, unsigned char ascq)
{
    int k;
    char obuff[256];
    int found = 0;

    for (k = 0; additional2[k].text; ++k) {
        if ((additional2[k].code1 == asc) &&
            (ascq >= additional2[k].code2_min)  &&
            (ascq <= additional2[k].code2_max)) {
            found = 1;
            fprintf(OUTP, "Additional sense: ");
            fprintf(OUTP, additional2[k].text, ascq);
            fprintf(OUTP, "\n");
        }
    }
    if (found)
        return;

    for (k = 0; additional[k].text; ++k) {
        if (additional[k].code1 == asc &&
            additional[k].code2 == ascq) {
            found = 1;
            strncpy(obuff, additional[k].text, sizeof(obuff));
            obuff[sizeof(obuff) - 1] = '\0';
            fprintf(OUTP, "Additional sense: %s\n", obuff);
        }
    }
    if (! found)
        fprintf(OUTP, "ASC=%2x ASCQ=%2x\n", asc, ascq);
}

/* Print sense information */
void sg_print_sense(const char * leadin, const unsigned char * sense_buffer,
                    int sb_len)
{
    int k, s;
    int sense_key, sense_class, valid, code;
    int descriptor_format = 0;
    const char * error = NULL;

    if (sb_len < 1) {
            fprintf(OUTP, "sense buffer empty\n");
            return;
    }
    sense_class = (sense_buffer[0] >> 4) & 0x07;
    code = sense_buffer[0] & 0xf;
    valid = sense_buffer[0] & 0x80;
    if (leadin)
        fprintf(OUTP, "%s: ", leadin);

    if (sense_class == 7) {     /* extended sense data */
        s = sense_buffer[7] + 8;
        if(s > sb_len)  /* device has more available which we ignore */
            s = sb_len;

        switch (code) {
        case 0x0:
            error = "Current";  /* error concerns current command */
            break;
        case 0x1:
            error = "Deferred"; /* error concerns some earlier command */
                /* e.g., an earlier write to disk cache succeeded, but
                   now the disk discovers that it cannot write the data */
            break;
        case 0x2:
            descriptor_format = 1;
            error = "Descriptor current";
            /* new descriptor sense format */
            break;
        case 0x3:
            descriptor_format = 1;
            error = "Descriptor deferred";
            /* new descriptor sense format (deferred report) */
            break;
        default:
            error = "Invalid";
        }
        sense_key = sense_buffer[ descriptor_format ? 1 : 2 ] & 0xf;
        fprintf(OUTP, "%s, Sense key: %s\n", error, snstext[sense_key]);

        if (descriptor_format)
            sg_print_asc_ascq(sense_buffer[2], sense_buffer[3]);
        else {
            if (!valid)
                fprintf(OUTP, "[valid=0] ");
            fprintf(OUTP, "Info fld=0x%x, ", (int)((sense_buffer[3] << 24) |
                    (sense_buffer[4] << 16) | (sense_buffer[5] << 8) |
                    sense_buffer[6]));

            if (sense_buffer[2] & 0x80)
               fprintf(OUTP, "FMK "); /* current command has read a filemark */
            if (sense_buffer[2] & 0x40)
               fprintf(OUTP, "EOM "); /* end-of-medium condition exists */
            if (sense_buffer[2] & 0x20)
               fprintf(OUTP, "ILI "); /* incorrect block length requested */

            if (s > 13) {
                if (sense_buffer[12] || sense_buffer[13])
                    sg_print_asc_ascq(sense_buffer[12], sense_buffer[13]);
            }
            if (sense_key == 5 && s >= 18 && (sense_buffer[15]&0x80)) {
                fprintf(OUTP, "Sense Key Specific: Error in %s byte %d",
                        (sense_buffer[15]&0x40)?"Command":"Data",
                        (sense_buffer[16]<<8)|sense_buffer[17]);
                if(sense_buffer[15]&0x08) {
                    fprintf(OUTP, " bit %d\n", sense_buffer[15]&0x07);
                } else {
                    fprintf(OUTP, "\n");
                }
            }
        }

    } else {    /* non-extended sense data */

         /*
          * Standard says:
          *    sense_buffer[0] & 0200 : address valid
          *    sense_buffer[0] & 0177 : vendor-specific error code
          *    sense_buffer[1] & 0340 : vendor-specific
          *    sense_buffer[1..3] : 21-bit logical block address
          */

        if (sb_len < 4) {
            fprintf(OUTP, "sense buffer too short (4 byte minimum)\n");
            return;
        }
        if (leadin)
            fprintf(OUTP, "%s: ", leadin);
        if (sense_buffer[0] < 15)
            fprintf(OUTP, 
                    "old sense: key %s\n", snstext[sense_buffer[0] & 0x0f]);
        else
            fprintf(OUTP, "sns = %2x %2x\n", sense_buffer[0], sense_buffer[2]);

        fprintf(OUTP, "Non-extended sense class %d code 0x%0x ", 
                sense_class, code);
        s = 4;
    }

    fprintf(OUTP, "Raw sense data (in hex):\n  ");
    for (k = 0; k < s; ++k) {
        if ((k > 0) && (0 == (k % 24)))
            fprintf(OUTP, "\n  ");
        fprintf(OUTP, "%02x ", sense_buffer[k]);
    }
    fprintf(OUTP, "\n");
}

static const char * hostbyte_table[]={
"DID_OK", "DID_NO_CONNECT", "DID_BUS_BUSY", "DID_TIME_OUT", "DID_BAD_TARGET",
"DID_ABORT", "DID_PARITY", "DID_ERROR", "DID_RESET", "DID_BAD_INTR",
"DID_PASSTHROUGH", "DID_SOFT_ERROR", NULL};

void sg_print_host_status(int host_status)
{   static int maxcode=0;
    int i;

    if(! maxcode) {
        for(i = 0; hostbyte_table[i]; i++) ;
        maxcode = i-1;
    }
    fprintf(OUTP, "Host_status=0x%02x", host_status);
    if(host_status > maxcode) {
        fprintf(OUTP, "is invalid ");
        return;
    }
    fprintf(OUTP, "(%s) ",hostbyte_table[host_status]);
}

static const char * driverbyte_table[]={
"DRIVER_OK", "DRIVER_BUSY", "DRIVER_SOFT",  "DRIVER_MEDIA", "DRIVER_ERROR",
"DRIVER_INVALID", "DRIVER_TIMEOUT", "DRIVER_HARD", "DRIVER_SENSE", NULL};

static const char * driversuggest_table[]={"SUGGEST_OK",
"SUGGEST_RETRY", "SUGGEST_ABORT", "SUGGEST_REMAP", "SUGGEST_DIE",
unknown,unknown,unknown, "SUGGEST_SENSE",NULL};


void sg_print_driver_status(int driver_status)
{
    static int driver_max =0 , suggest_max=0;
    int i;
    int dr = driver_status & SG_ERR_DRIVER_MASK;
    int su = (driver_status & SG_ERR_SUGGEST_MASK) >> 4;

    if(! driver_max) {
        for(i = 0; driverbyte_table[i]; i++) ;
        driver_max = i;
        for(i = 0; driversuggest_table[i]; i++) ;
        suggest_max = i;
    }
    fprintf(OUTP, "Driver_status=0x%02x",driver_status);
    fprintf(OUTP, " (%s,%s) ",
            dr < driver_max  ? driverbyte_table[dr]:"invalid",
            su < suggest_max ? driversuggest_table[su]:"invalid");
}

static int sg_sense_print(const char * leadin, int scsi_status,
                          int host_status, int driver_status,
                          const unsigned char * sense_buffer, int sb_len)
{
    int done_leadin = 0;
    int done_sense = 0;

    scsi_status &= 0x7e; /*sanity */
    if ((0 == scsi_status) && (0 == host_status) &&
        (0 == driver_status))
        return 1;       /* No problems */
    if (0 != scsi_status) {
        if (leadin)
            fprintf(OUTP, "%s: ", leadin);
        done_leadin = 1;
        fprintf(OUTP, "scsi status: ");
        sg_print_scsi_status(scsi_status);
        fprintf(OUTP, "\n");
        if (sense_buffer && ((scsi_status == SCSI_CHECK_CONDITION) ||
                             (scsi_status == SCSI_COMMAND_TERMINATED))) {
            sg_print_sense(0, sense_buffer, sb_len);
            done_sense = 1;
        }
    }
    if (0 != host_status) {
        if (leadin && (! done_leadin))
            fprintf(OUTP, "%s: ", leadin);
        if (done_leadin)
            fprintf(OUTP, "plus...: ");
        else
            done_leadin = 1;
        sg_print_host_status(host_status);
        fprintf(OUTP, "\n");
    }
    if (0 != driver_status) {
        if (leadin && (! done_leadin))
            fprintf(OUTP, "%s: ", leadin);
        if (done_leadin)
            fprintf(OUTP, "plus...: ");
        else
            done_leadin = 1;
        sg_print_driver_status(driver_status);
        fprintf(OUTP, "\n");
        if (sense_buffer && (! done_sense) &&
            (SG_ERR_DRIVER_SENSE == (0xf & driver_status)))
            sg_print_sense(0, sense_buffer, sb_len);
    }
    return 0;
}

#ifdef SG_IO

/* Returns 0 if nothing to decode or some problem, else returns 1 with
   non-NULL members of the last 4 arguments output to as appropriate */
int sg_decode_sense(const struct sg_io_hdr * hp,
                    unsigned char * response_code,
                    unsigned char * sense_key,
                    unsigned char * asc,
                    unsigned char * ascq)
{
    if ((NULL == hp) || (NULL == hp->sbp) || (0 == hp->sb_len_wr) ||
        (0x70 != (0x70 & hp->sbp[0]))) {
        if (response_code)
            *response_code = 0;
        if (sense_key)
            *sense_key = 0;
        return 0;
    }
    if (response_code)
        *response_code = (0x7f & hp->sbp[0]);
    if ((0x7f & hp->sbp[0]) >= 0x72) {  /* descriptor format */
        if (sense_key)
            *sense_key = (0xf & hp->sbp[1]);
        if (asc)
            *asc = hp->sbp[2];
        if (ascq)
            *ascq = hp->sbp[3];
        return 1;
    }
    /* fixed format */
    if (sense_key)
        *sense_key = (0xf & hp->sbp[2]);
    if (asc)
        *asc = (hp->sb_len_wr > 12) ? hp->sbp[12] : 0;
    if (ascq)
        *ascq = (hp->sb_len_wr > 13) ? hp->sbp[13] : 0;
    return 1;
}

int sg_chk_n_print3(const char * leadin, struct sg_io_hdr * hp)
{
    return sg_sense_print(leadin, hp->status, hp->host_status,
                          hp->driver_status, hp->sbp, hp->sb_len_wr);
}
#endif

int sg_chk_n_print(const char * leadin, int masked_status,
                   int host_status, int driver_status,
                   const unsigned char * sense_buffer, int sb_len)
{
    int scsi_status = (masked_status << 1) & 0x7e;

    return sg_sense_print(leadin, scsi_status, host_status, driver_status,
                          sense_buffer, sb_len);
}

#ifdef SG_IO
int sg_err_category3(struct sg_io_hdr * hp)
{
    return sg_err_category_new(hp->status, hp->host_status,
                               hp->driver_status, hp->sbp, hp->sb_len_wr);
}
#endif

int sg_err_category(int masked_status, int host_status,
                    int driver_status, const unsigned char * sense_buffer,
                    int sb_len)
{
    int scsi_status = (masked_status << 1) & 0x7e;

    return sg_err_category_new(scsi_status, host_status, driver_status,
                               sense_buffer, sb_len);
}

int sg_err_category_new(int scsi_status, int host_status, int driver_status, 
                        const unsigned char * sense_buffer, int sb_len)
{
    scsi_status &= 0x7e;
    if ((0 == scsi_status) && (0 == host_status) &&
        (0 == driver_status))
        return SG_ERR_CAT_CLEAN;
    if ((SCSI_CHECK_CONDITION == scsi_status) ||
        (SCSI_COMMAND_TERMINATED == scsi_status) ||
        (SG_ERR_DRIVER_SENSE == (0xf & driver_status))) {
        if (sense_buffer && (sb_len > 2)) {
            int sense_key;
            unsigned char asc;

            if (sense_buffer[0] & 0x2) {
                sense_key = sense_buffer[1] & 0xf;
                asc = sense_buffer[2];
            }
            else {
                sense_key = sense_buffer[2] & 0xf;
                asc = (sb_len > 12) ? sense_buffer[12] : 0;
            }

            if(RECOVERED_ERROR == sense_key)
                return SG_ERR_CAT_RECOVERED;
            else if (UNIT_ATTENTION == sense_key) {
                if (0x28 == asc)
                    return SG_ERR_CAT_MEDIA_CHANGED;
                if (0x29 == asc)
                    return SG_ERR_CAT_RESET;
            }
        }
        return SG_ERR_CAT_SENSE;
    }
    if (0 != host_status) {
        if ((SG_ERR_DID_NO_CONNECT == host_status) ||
            (SG_ERR_DID_BUS_BUSY == host_status) ||
            (SG_ERR_DID_TIME_OUT == host_status))
            return SG_ERR_CAT_TIMEOUT;
    }
    if (0 != driver_status) {
        if (SG_ERR_DRIVER_TIMEOUT == driver_status)
            return SG_ERR_CAT_TIMEOUT;
    }
    return SG_ERR_CAT_OTHER;
}

/* gives wrong answer for variable length command (opcode=0x7f) */
int sg_get_command_size(unsigned char opcode)
{
    return COMMAND_SIZE(opcode);
}

void sg_get_command_name(const unsigned char * cmdp, int peri_type,
                         int buff_len, char * buff)
{
    unsigned char service_action;

    if ((NULL == buff) || (buff_len < 1))
        return;
    if (NULL == cmdp) {
        strncpy(buff, "<null> command pointer", buff_len);
        return;
    }
    service_action = (SG_VARIABLE_LENGTH_CMD == cmdp[0]) ?
                     (cmdp[1] & 0x1f) : ((cmdp[8] << 8) | cmdp[9]);
    sg_get_opcode_sa_name(cmdp[0], service_action, peri_type, buff_len, buff);
}


void sg_get_opcode_sa_name(unsigned char cmd_byte0, int service_action,
                           int peri_type, int buff_len, char * buff)
{
    const struct value_name_t * vnp;

    if ((NULL == buff) || (buff_len < 1))
        return;
    switch ((int)cmd_byte0) {
    case SG_VARIABLE_LENGTH_CMD:
        vnp = get_value_name(variable_length_arr, VARIABLE_LENGTH_SZ,
                             service_action, peri_type);
        if (vnp)
            strncpy(buff, vnp->name, buff_len);
        else
            snprintf(buff, buff_len, "Variable length service action=0x%x",
                     service_action);
        break;
    case SG_MAINTENANCE_IN:
        vnp = get_value_name(maint_in_arr, MAINT_IN_SZ, service_action, 
                             peri_type);
        if (vnp)
            strncpy(buff, vnp->name, buff_len);
        else
            snprintf(buff, buff_len, "Maintenance in service action=0x%x",
                     service_action);
        break;
    case SG_MAINTENANCE_OUT:
        vnp = get_value_name(maint_out_arr, MAINT_OUT_SZ, service_action, 
                             peri_type);
        if (vnp)
            strncpy(buff, vnp->name, buff_len);
        else
            snprintf(buff, buff_len, "Maintenance out service action=0x%x",
                     service_action);
        break;
    case SG_SERVICE_ACTION_IN_12:
        vnp = get_value_name(serv_in12_arr, SERV_IN12_SZ, service_action, 
                             peri_type);
        if (vnp)
            strncpy(buff, vnp->name, buff_len);
        else
            snprintf(buff, buff_len, "Service action in(12)=0x%x",
                     service_action);
        break;
    case SG_SERVICE_ACTION_OUT_12:
        vnp = get_value_name(serv_out12_arr, SERV_OUT12_SZ, service_action,
                             peri_type);
        if (vnp)
            strncpy(buff, vnp->name, buff_len);
        else
            snprintf(buff, buff_len, "Service action out(12)=0x%x",
                     service_action);
        break;
    case SG_SERVICE_ACTION_IN_16:
        vnp = get_value_name(serv_in16_arr, SERV_IN16_SZ, service_action, 
                             peri_type);
        if (vnp)
            strncpy(buff, vnp->name, buff_len);
        else
            snprintf(buff, buff_len, "Service action in(16)=0x%x",
                     service_action);
        break;
    case SG_SERVICE_ACTION_OUT_16:
        vnp = get_value_name(serv_out16_arr, SERV_OUT16_SZ, service_action,
                             peri_type);
        if (vnp)
            strncpy(buff, vnp->name, buff_len);
        else
            snprintf(buff, buff_len, "Service action out(16)=0x%x",
                     service_action);
        break;
    default:
        sg_get_opcode_name(cmd_byte0, peri_type, buff_len, buff);
    }
}

void sg_get_opcode_name(unsigned char cmd_byte0, int peri_type, 
                        int buff_len, char * buff)
{
    const struct value_name_t * vnp;
    int grp;

    if ((NULL == buff) || (buff_len < 1))
        return;
    if (SG_VARIABLE_LENGTH_CMD == cmd_byte0) {
        strncpy(buff, "Variable length", buff_len);
        return;
    }
    grp = group(cmd_byte0);
    vnp = opcode_grp_arr[grp];
    switch (vnp->value) {
    case RESERVED_GROUP:
        snprintf(buff, buff_len, "Reserved [0x%x]", (int)cmd_byte0);
        break;
    case VENDOR_GROUP:
        snprintf(buff, buff_len, "Vendor specific [0x%x]", (int)cmd_byte0);
        break;
    default:
        vnp = get_value_name(vnp, opcode_grp_sz[grp], cmd_byte0, peri_type);
        if (vnp)
            strncpy(buff, vnp->name, buff_len);
        else
            snprintf(buff, buff_len, "Opcode=0x%x", (int)cmd_byte0);
        break;
    }
}

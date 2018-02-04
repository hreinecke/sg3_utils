#ifndef SG_PT_WIN32_H
#define SG_PT_WIN32_H
/*
 * The information in this file was obtained from scsi-wnt.h by
 * Richard Stemmer, rs@epost.de . He in turn gives credit to
 * Jay A. Key (for scsipt.c).
 * The plscsi program (by Pat LaVarre <p.lavarre@ieee.org>) has
 * also been used as a reference.
 * Much of the information in this header can also be obtained
 * from msdn.microsoft.com .
 * Updated for cygwin version 1.7.17 changes 20121026
 */

/* WIN32_LEAN_AND_MEAN may be required to prevent inclusion of <winioctl.h> */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SCSI_MAX_SENSE_LEN 64
#define SCSI_MAX_CDB_LEN 16
#define SCSI_MAX_INDIRECT_DATA 16384

typedef struct {
        USHORT          Length;
        UCHAR           ScsiStatus;
        UCHAR           PathId;
        UCHAR           TargetId;
        UCHAR           Lun;
        UCHAR           CdbLength;
        UCHAR           SenseInfoLength;
        UCHAR           DataIn;
        ULONG           DataTransferLength;
        ULONG           TimeOutValue;
        ULONG_PTR       DataBufferOffset;  /* was ULONG; problem in 64 bit */
        ULONG           SenseInfoOffset;
        UCHAR           Cdb[SCSI_MAX_CDB_LEN];
} SCSI_PASS_THROUGH, *PSCSI_PASS_THROUGH;


typedef struct {
        USHORT          Length;
        UCHAR           ScsiStatus;
        UCHAR           PathId;
        UCHAR           TargetId;
        UCHAR           Lun;
        UCHAR           CdbLength;
        UCHAR           SenseInfoLength;
        UCHAR           DataIn;
        ULONG           DataTransferLength;
        ULONG           TimeOutValue;
        PVOID           DataBuffer;
        ULONG           SenseInfoOffset;
        UCHAR           Cdb[SCSI_MAX_CDB_LEN];
} SCSI_PASS_THROUGH_DIRECT, *PSCSI_PASS_THROUGH_DIRECT;


typedef struct {
        SCSI_PASS_THROUGH spt;
        /* plscsi shows a follow on 16 bytes allowing 32 byte cdb */
        ULONG           Filler;
        UCHAR           ucSenseBuf[SCSI_MAX_SENSE_LEN];
        UCHAR           ucDataBuf[SCSI_MAX_INDIRECT_DATA];
} SCSI_PASS_THROUGH_WITH_BUFFERS, *PSCSI_PASS_THROUGH_WITH_BUFFERS;


typedef struct {
        SCSI_PASS_THROUGH_DIRECT spt;
        ULONG           Filler;
        UCHAR           ucSenseBuf[SCSI_MAX_SENSE_LEN];
} SCSI_PASS_THROUGH_DIRECT_WITH_BUFFER, *PSCSI_PASS_THROUGH_DIRECT_WITH_BUFFER;



typedef struct {
        UCHAR           NumberOfLogicalUnits;
        UCHAR           InitiatorBusId;
        ULONG           InquiryDataOffset;
} SCSI_BUS_DATA, *PSCSI_BUS_DATA;


typedef struct {
        UCHAR           NumberOfBusses;
        SCSI_BUS_DATA   BusData[1];
} SCSI_ADAPTER_BUS_INFO, *PSCSI_ADAPTER_BUS_INFO;


typedef struct {
        UCHAR           PathId;
        UCHAR           TargetId;
        UCHAR           Lun;
        BOOLEAN         DeviceClaimed;
        ULONG           InquiryDataLength;
        ULONG           NextInquiryDataOffset;
        UCHAR           InquiryData[1];
} SCSI_INQUIRY_DATA, *PSCSI_INQUIRY_DATA;


typedef struct {
        ULONG           Length;
        UCHAR           PortNumber;
        UCHAR           PathId;
        UCHAR           TargetId;
        UCHAR           Lun;
} SCSI_ADDRESS, *PSCSI_ADDRESS;

/*
 * Standard IOCTL define
 */
#ifndef CTL_CODE
#define CTL_CODE(DevType, Function, Method, Access)             \
        (((DevType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method))
#endif

/*
 * file access values
 */
#ifndef FILE_ANY_ACCESS
#define FILE_ANY_ACCESS         0
#endif
#ifndef FILE_READ_ACCESS
#define FILE_READ_ACCESS        0x0001
#endif
#ifndef FILE_WRITE_ACCESS
#define FILE_WRITE_ACCESS       0x0002
#endif

// IOCTL_STORAGE_QUERY_PROPERTY

#define FILE_DEVICE_MASS_STORAGE    0x0000002d
#define IOCTL_STORAGE_BASE          FILE_DEVICE_MASS_STORAGE
#define FILE_ANY_ACCESS             0

// #define METHOD_BUFFERED             0

#define IOCTL_STORAGE_QUERY_PROPERTY \
    CTL_CODE(IOCTL_STORAGE_BASE, 0x0500, METHOD_BUFFERED, FILE_ANY_ACCESS)


#ifndef _DEVIOCTL_
typedef enum _STORAGE_BUS_TYPE {
    BusTypeUnknown      = 0x00,
    BusTypeScsi         = 0x01,
    BusTypeAtapi        = 0x02,
    BusTypeAta          = 0x03,
    BusType1394         = 0x04,
    BusTypeSsa          = 0x05,
    BusTypeFibre        = 0x06,
    BusTypeUsb          = 0x07,
    BusTypeRAID         = 0x08,
    BusTypeiScsi        = 0x09,
    BusTypeSas          = 0x0A,
    BusTypeSata         = 0x0B,
    BusTypeSd           = 0x0C,
    BusTypeMmc          = 0x0D,
    BusTypeVirtual             = 0xE,
    BusTypeFileBackedVirtual   = 0xF,
    BusTypeSpaces       = 0x10,
    BusTypeNvme         = 0x11,
    BusTypeSCM          = 0x12,
    BusTypeUfs          = 0x13,
    BusTypeMax          = 0x14,
    BusTypeMaxReserved  = 0x7F
} STORAGE_BUS_TYPE, *PSTORAGE_BUS_TYPE;

typedef enum _STORAGE_PROTOCOL_TYPE {
    ProtocolTypeUnknown = 0,
    ProtocolTypeScsi,
    ProtocolTypeAta,
    ProtocolTypeNvme,
    ProtocolTypeSd
} STORAGE_PROTOCOL_TYPE;

typedef enum _STORAGE_PROTOCOL_NVME_DATA_TYPE {
    NVMeDataTypeUnknown = 0,
    NVMeDataTypeIdentify,
    NVMeDataTypeLogPage,
    NVMeDataTypeFeature
} STORAGE_PROTOCOL_NVME_DATA_TYPE;

typedef struct _STORAGE_PROTOCOL_SPECIFIC_DATA {
    STORAGE_PROTOCOL_TYPE ProtocolType;
    ULONG DataType;
    ULONG ProtocolDataRequestValue;
    ULONG ProtocolDataRequestSubValue;
    ULONG ProtocolDataOffset;
    ULONG ProtocolDataLength;
    ULONG FixedProtocolReturnData;
    ULONG Reserved[3];
} STORAGE_PROTOCOL_SPECIFIC_DATA;


typedef struct _STORAGE_DEVICE_DESCRIPTOR {
    ULONG Version;
    ULONG Size;
    UCHAR DeviceType;
    UCHAR DeviceTypeModifier;
    BOOLEAN RemovableMedia;
    BOOLEAN CommandQueueing;
    ULONG VendorIdOffset;       /* 0 if not available */
    ULONG ProductIdOffset;      /* 0 if not available */
    ULONG ProductRevisionOffset;/* 0 if not available */
    ULONG SerialNumberOffset;   /* -1 if not available ?? */
    STORAGE_BUS_TYPE BusType;
    ULONG RawPropertiesLength;
    UCHAR RawDeviceProperties[1];
} STORAGE_DEVICE_DESCRIPTOR, *PSTORAGE_DEVICE_DESCRIPTOR;
#endif		/* _DEVIOCTL_ */

typedef struct _STORAGE_DEVICE_UNIQUE_IDENTIFIER {
    ULONG  Version;
    ULONG  Size;
    ULONG  StorageDeviceIdOffset;
    ULONG  StorageDeviceOffset;
    ULONG  DriveLayoutSignatureOffset;
} STORAGE_DEVICE_UNIQUE_IDENTIFIER, *PSTORAGE_DEVICE_UNIQUE_IDENTIFIER;

// Use CompareStorageDuids(PSTORAGE_DEVICE_UNIQUE_IDENTIFIER duid1, duid2)
// to test for equality

#ifndef _DEVIOCTL_
typedef enum _STORAGE_QUERY_TYPE {
    PropertyStandardQuery = 0,
    PropertyExistsQuery,
    PropertyMaskQuery,
    PropertyQueryMaxDefined
} STORAGE_QUERY_TYPE, *PSTORAGE_QUERY_TYPE;

typedef enum _STORAGE_PROPERTY_ID {
    StorageDeviceProperty = 0,
    StorageAdapterProperty,
    StorageDeviceIdProperty,
    StorageDeviceUniqueIdProperty,
    StorageDeviceWriteCacheProperty,
    StorageMiniportProperty,
    StorageAccessAlignmentProperty
} STORAGE_PROPERTY_ID, *PSTORAGE_PROPERTY_ID;

typedef struct _STORAGE_PROPERTY_QUERY {
    STORAGE_PROPERTY_ID PropertyId;
    STORAGE_QUERY_TYPE QueryType;
    UCHAR AdditionalParameters[1];
} STORAGE_PROPERTY_QUERY, *PSTORAGE_PROPERTY_QUERY;
#endif		/* _DEVIOCTL_ */


// NVME_PASS_THROUGH

#ifndef STB_IO_CONTROL
typedef struct _SRB_IO_CONTROL {
        ULONG HeaderLength;
        UCHAR Signature[8];
        ULONG Timeout;
        ULONG ControlCode;
        ULONG ReturnCode;
        ULONG Length;
} SRB_IO_CONTROL, *PSRB_IO_CONTROL;
#endif

#ifndef NVME_PASS_THROUGH_SRB_IO_CODE

#define NVME_SIG_STR "NvmeMini"
#define NVME_STORPORT_DRIVER 0xe000

#define NVME_PASS_THROUGH_SRB_IO_CODE \
  CTL_CODE(NVME_STORPORT_DRIVER, 0x0800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#pragma pack(1)
typedef struct _NVME_PASS_THROUGH_IOCTL
{
        SRB_IO_CONTROL SrbIoCtrl;
        ULONG VendorSpecific[6];
        ULONG NVMeCmd[16];      /* Command DW[0...15] */
        ULONG CplEntry[4];      /* Completion DW[0...3] */
        ULONG Direction;        /* 0=None, 1=Out, 2=In, 3=I/O */
        ULONG QueueId;          /* 0=AdminQ */
        ULONG DataBufferLen;    /* sizeof(DataBuffer) if Data In */
        ULONG MetaDataLen;
        ULONG ReturnBufferLen;  /* offsetof(DataBuffer), plus
                                 * sizeof(DataBuffer) if Data Out */
        UCHAR DataBuffer[1];
} NVME_PASS_THROUGH_IOCTL;
#pragma pack()

#endif // NVME_PASS_THROUGH_SRB_IO_CODE


/*
 * method codes
 */
#define METHOD_BUFFERED         0
#define METHOD_IN_DIRECT        1
#define METHOD_OUT_DIRECT       2
#define METHOD_NEITHER          3


#define IOCTL_SCSI_BASE    0x00000004

/*
 * constants for DataIn member of SCSI_PASS_THROUGH* structures
 */
#define SCSI_IOCTL_DATA_OUT             0
#define SCSI_IOCTL_DATA_IN              1
#define SCSI_IOCTL_DATA_UNSPECIFIED     2

#define IOCTL_SCSI_PASS_THROUGH         CTL_CODE(IOCTL_SCSI_BASE, 0x0401, \
        METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_MINIPORT             CTL_CODE(IOCTL_SCSI_BASE, 0x0402, \
        METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_GET_INQUIRY_DATA     CTL_CODE(IOCTL_SCSI_BASE, 0x0403, \
        METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_GET_CAPABILITIES     CTL_CODE(IOCTL_SCSI_BASE, 0x0404, \
        METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_SCSI_PASS_THROUGH_DIRECT  CTL_CODE(IOCTL_SCSI_BASE, 0x0405, \
        METHOD_BUFFERED, FILE_READ_ACCESS | FILE_WRITE_ACCESS)
#define IOCTL_SCSI_GET_ADDRESS          CTL_CODE(IOCTL_SCSI_BASE, 0x0406, \
        METHOD_BUFFERED, FILE_ANY_ACCESS)

#ifdef __cplusplus
}
#endif

#endif

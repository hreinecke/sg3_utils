/*
 * Copyright (c) 2022 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <stdlib.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#else
#define SG_SCSI_STRINGS 1
#endif

#include "sg_lib.h"
#include "sg_lib_data.h"
#include "sg_lib_names.h"

/* List of SPC, then SBC, the ZBC mode page names. Tape and other mode pages
 * are squeezed into this list as long as they don't conflict.
 * The value is: (mode_page << 8) | mode_subpage
 * Maintain the list in numerical order to allow binary search. */
struct sg_lib_simple_value_name_t sg_lib_names_mode_arr[] = {
    {0x0000, "Unit Attention condition"},  /* common vendor specific page */
    {0x0100, "Read-Write error recovery"},      /* SBC */
    {0x0200, "Disconnect-Reconnect"},           /* SPC */
    {0x0300, "Format (obsolete)"},              /* SBC */
    {0x0400, "Rigid disk geometry (obsolete)"}, /* SBC */
    {0x0500, "Flexible disk (obsolete)"},       /* SBC */
    {0x0700, "Verify error recovery"},          /* SBC */
    {0x0800, "Caching"},                        /* SBC */
    {0x0900, "Peripheral device (obsolete)"},   /* SPC */
    {0x0a00, "Control"},                        /* SPC */
    {0x0a01, "Control extension"},              /* SPC */
    {0x0a02, "Application tag"},                /* SBC */
    {0x0a03, "Command duration limit A"},       /* SPC */
    {0x0a04, "Command duration limit B"},       /* SPC */
    {0x0a05, "IO Advice Hints Grouping"},       /* SBC */
    {0x0a06, "Background operation control"},   /* SBC */
    {0x0af0, "Control data protection"},        /* SSC */
    {0x0af1, "PATA control"},                   /* SAT */
    {0x0b00, "Medium Types Supported (obsolete)"},   /* SSC */
    {0x0c00, "Notch and partition (obsolete)"}, /* SBC */
    {0x0d00, "Power condition (obsolete), CD device parameters"},
    {0x0e00, "CD audio control"},               /* MMC */
    {0x0e01, "Target device"},                  /* ADC */
    {0x0e02, "DT device primary port"},         /* ADC */
    {0x0e03, "Logical unit"},                   /* ADC */
    {0x0e04, "Target device serial number"},    /* ADC */
    {0x0f00, "Data compression"},               /* SSC */
    {0x1000, "XOR control (obsolete, Device configuration"}, /* SBC,SSC */
    {0x1001, "Device configuration extension"}, /* SSC */
    {0x1100, "Medium partition (1)"},           /* SSC */
    {0x1400, "Enclosure services management"},  /* SES */
    {0x1800, "Protocol specific logical unit"}, /* transport */
    {0x1900, "Protocol specific port"},         /* transport */
    {0x1901, "Phy control and discovery"},      /* SPL */
    {0x1902, "Shared port control"},            /* SPL */
    {0x1903, "Enhanced phy control"},           /* SPL */
    {0x1904, "Out of band  management control"}, /* SPL */
    {0x1A00, "Power condition"},                /* SPC */
    {0x1A01, "Power consumption"},              /* SPC */
    {0x1Af1, "ATA Power condition"},            /* SPC */
    {0x1b00, "LUN mapping"},                    /* ADC */
    {0x1c00, "Information exceptions control"}, /* SPC */
    {0x1c01, "Background control"},             /* SBC */
    {0x1c02, "Logical block provisioning"},     /* SBC */
    {0x1c02, "Logical block provisioning"},     /* SBC */
    {0x1d00, "Medium configuration, CD/DVD timeout, "
             "element address assignments"},    /* SSC,MMC,SMC */
    {0x1e00, "Transport geometry assignments"}, /* SMC */
    {0x1f00, "Device capabilities"},            /* SMC */

    {-1, NULL},                                 /* sentinel */
};

/* Don't count sentinel when doing binary searches, etc */
const size_t sg_lib_names_mode_len =
                SG_ARRAY_SIZE(sg_lib_names_mode_arr) - 1;

/* List of SPC, then SBC, the ZBC VPD page names. Tape and other VPD pages
 * are squeezed into this list as long as they don't conflict.
 * For VPDs > 0 the value is: (vpd << 8) | vpd_number
 * Maintain the list in numerical order to allow binary search. */
struct sg_lib_simple_value_name_t sg_lib_names_vpd_arr[] = {
    {0x00, "Supported VPD pages"},              /* SPC */
    {0x80, "Unit serial number"},               /* SPC */
    {0x81, "Implemented operating definition (obsolete)"}, /* SPC */
    {0x82, "ASCII implemented operating definition (obsolete)"}, /* SPC */
    {0x83, "Device identification"},            /* SPC */
    {0x84, "Software interface identification"}, /* SPC */
    {0x85, "Management network addresses"},     /* SPC */
    {0x86, "Extended INQUIRY data"},            /* SPC */
    {0x87, "Mode page policy"},                 /* SPC */
    {0x88, "SCSI ports"},                       /* SPC */
    {0x89, "ATA information"},                  /* SAT */
    {0x8a, "Power condition"},                  /* SPC */
    {0x8b, "Device constituents"},              /* SSC */
    {0x8c, "CFA profile information"},          /* SPC */
    {0x8d, "Power consumption"},                /* SPC */
    {0x8f, "Third party copy"},                 /* SPC */
    {0x90, "Protocol specific logical unit information"}, /* transport */
    {0x91, "Protocol specific port information"}, /* transport */
    {0x92, "SCSI feature sets"},                /* SPC,SBC */
    {0xb0, "Block limits"},                     /* SBC */
    {0xb1, "Block device characteristics"},     /* SBC */
    {0xb2, "Logical block provisioning"},       /* SBC */
    {0xb3, "Referrals"},                        /* SBC */
    {0xb4, "Supported Block Lengths and Protection Types"}, /* SBC */
    {0xb5, "Block device characteristics extension"}, /* SBC */
    {0xb6, "Zoned block device characteristics"}, /* ZBC */
    {0xb7, "Block limits extension"},           /* SBC */
    {0xb8, "Format presets"},                   /* SBC */
    {0xb9, "Concurrent positioning ranges"},    /* SBC */
    {0x01b0, "Sequential access Device Capabilities"}, /* SSC */
    {0x01b1, "Manufacturer-assigned serial number"}, /* SSC */
    {0x01b2, "TapeAlert supported flags"},      /* SSC */
    {0x01b3, "Automation device serial number"}, /* SSC */
    {0x01b4, "Data transfer device element address"}, /* SSC */
    {0x01b5, "Data transfer device element address"}, /* SSC */
    {0x11b0, "OSD information"},                /* OSD */
    {0x11b1, "Security token"},                 /* OSD */

    {-1, NULL},                                 /* sentinel */
};

/* Don't count sentinel when doing binary searches, etc */
const size_t sg_lib_names_vpd_len =
                SG_ARRAY_SIZE(sg_lib_names_vpd_arr) - 1;

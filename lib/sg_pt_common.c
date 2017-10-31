/*
 * Copyright (c) 2009-2017 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <stdlib.h>

#include "sg_pt.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


static const char * scsi_pt_version_str = "2.14 20171030";

const char *
scsi_pt_version()
{
    return scsi_pt_version_str;
}

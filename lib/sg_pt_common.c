/*
 * Copyright (c) 2009-2011 Douglas Gilbert.
 * All rights reserved.
 * Use of this source code is governed by a BSD-style
 * license that can be found in the BSD_LICENSE file.
 */

#include <stdlib.h>

#include "sg_pt.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif


static const char * scsi_pt_version_str = "2.08 20110207";

const char *
scsi_pt_version()
{
    return scsi_pt_version_str;
}


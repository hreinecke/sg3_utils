#!/bin/sh
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

MODPARM=/sys/module/scsi_mod/parameters
if [ -w "$MODPARM/scan" ] ; then
    scan_type=$(cat $MODPARM/scan)
    if [ "$scan_type" = "manual" ] ; then
	echo sync > $MODPARM/scan

	for shost in /sys/class/scsi_host/host* ; do
	    echo '- - -' > ${shost}/scan
	done
    fi
fi

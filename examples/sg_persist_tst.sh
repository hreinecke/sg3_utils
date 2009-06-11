#!/bin/sh
# This script is meant as an example of using the sg_persist utility
# in the sg3_utils package. This script works as expected on the
# author's Fujitsu MAM3184, Seagate ST373455 and ST9146803SS disks.
#
#  Version 1.6 20090608

# N.B. make sure the device name is correct for your environment.

if [ ! -n "$1" ];then
        echo "Usage: `basename $0` <device_name>"
        echo
        echo "Tests various SCSI Persistent Reserve (in + out) commands."
        echo "Should be harmless (unless key 0x123abc is already in use)."
        exit 1
fi

echo ">>> try to report capabilities:"
sg_persist -c $1
res=$?
case "$res" in
    0) ;;
    1) echo "  syntax error" ;;
    2) echo "  not ready" ;;
    3) echo "  medium error" ;;
    5) echo "  illegal request, report capabilities not supported?" ;;
    6) echo "  unit attention" ;;
    9) echo "  illegal request, Persistent Reserve (In) not supported" ;;
    11) echo "  aborted command" ;;
    15) echo "  file error with $1 " ;;
    20) echo "  no sense" ;;
    21) echo "  recovered error" ;;
    33) echo "  timeout" ;;
    97) echo "  response fails sanity" ;;
    98) echo "  other SCSI error" ;;
    99) echo "  other error" ;;
    *) echo "  unknown exit status for sg_persist: $res" ;;
esac
echo ""
sleep 1

echo ">>> check if any keys are registered:"
sg_persist --no-inquiry --read-keys $1
sleep 1

echo
echo ">>> register a key:"
sg_persist -n --out --register --param-sark=123abc $1
sleep 1

echo
echo ">>> now key 123abc should be registered:"
sg_persist -n --read-keys $1
sleep 1

echo
echo ">>> reserve the device (based on key 123abc):"
sg_persist -n --out --reserve --param-rk=123abc --prout-type=1 $1
sleep 1

echo
echo ">>> check if the device is reserved (it should be now):"
sg_persist -n --read-reservation $1
sleep 1

echo
echo ">>> try to 'read full status' (may not be supported):"
sg_persist -n --read-full-status $1
sleep 1

echo
echo ">>> now release reservation:"
sg_persist -n --out --release --param-rk=123abc --prout-type=1 $1
sleep 1

echo
echo ">>> check if the device is reserved (it should _not_ be now):"
sg_persist -n --read-reservation $1
sleep 1

echo
echo ">>> unregister key 123abc:"
sg_persist -n --out --register --param-rk=123abc $1
sleep 1

echo
echo ">>> now key 123abc should not be registered:"
sg_persist -n -k $1
sleep 1

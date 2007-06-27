#!/bin/sh
# This script is meant as an example of using the sg_persist utility
# in the sg3_utils package. This script works as expected on the
# author's Fujitsu MAM3184 and a Seagate ST373455 disk.

# N.B. make sure the device name is correct for your environment.

if [ ! -n "$1" ];then
        echo "Usage: `basename $0` <device_name>"
        echo
        echo "Tests various SCSI Persistent Reserve (in + out) commands."
        echo "Should be harmless (unless key 0x123abc is already in use)."
        exit 1
fi

echo ">>> check if any keys are registered:"
sg_persist -k $1
sleep 1

echo
echo ">>> register a key:"
sg_persist -n --out --register --param-sark=123abc $1
sleep 1

echo
echo ">>> now key 123abc should be registered:"
sg_persist -n -k $1
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

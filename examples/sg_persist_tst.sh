#/bin/sh
# This script is meant as an example of using the sg_persist utility
# in the sg3_utils package. This script works as expected on the
# author's Fujitsu MAM3184 disk.

# N.B. make sure the device name is correct for your environment.

echo "check if any keys are registered:"
sg_persist -k /dev/sdb
sleep 1

echo
echo "register a key:"
sg_persist -n --out --register --param-sark=123abc /dev/sdb
sleep 1

echo
echo "now key 123abc should be registered:"
sg_persist -n -k /dev/sdb
sleep 1

echo
echo "reserve the device (based on key 123abc):"
sg_persist -n --out --reserve --param-rk=123abc --prout-type=1 /dev/sdb
sleep 1

echo
echo "check if the device is reserved (it should be now):"
sg_persist -n --read-reservation /dev/sdb
sleep 1

echo
echo "now release reservation:"
sg_persist -n --out --release --param-rk=123abc --prout-type=1 /dev/sdb
sleep 1

echo
echo "check if the device is reserved (it should _not_ be now):"
sg_persist -n --read-reservation /dev/sdb
sleep 1

echo
echo "unregister key 123abc:"
sg_persist -n --out --register --param-rk=123abc /dev/sdb
sleep 1

echo
echo "now key 123abc should not be registered:"
sg_persist -n -k /dev/sdb
sleep 1

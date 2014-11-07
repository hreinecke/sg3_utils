#!/bin/sh
# This script is meant as an example of using the sg_persist utility
# in the sg3_utils package. This script works as expected on the
# author's Fujitsu MAM3184, Seagate ST373455 and ST9146803SS disks.
#
#  Version 1.9 20140612

# N.B. make sure the device name is correct for your environment.

key="123abc"
key2="333aaa"
kk=${key}
rtype="1"
verbose=""

usage()
{
  echo "Usage: sg_persist_tst.sh [-e] [-h] [-s] [-v] <device>"
  echo "  where:"
  echo -n "    -e, --exclusive      exclusive access (def: write "
  echo "exclusive)"
  echo "    -h, --help           print usage message"
  echo "    -s, --second         use second key"
  echo "    -v, --verbose        more verbose output"
  echo "    -vv                  even more verbose output"
  echo "    -vvv                 even more verbose output"
  echo ""
  echo "Test SCSI Persistent Reservations with sg_persist utility."
  echo "Default key is ${key} and alternate, second key is ${key2} ."
  echo "Should be harmless (unless one of those keys is already in use)."
  echo "The APTPL bit is not set in the PR register so a power cycle"
  echo "on the device will clear the reservation if this script stops"
  echo "(or is stopped) before clearing it. Tape drives only seem to "
  echo "support 'exclusive access' type (so use '-e')."
}

opt="$1"
while test ! -z "$opt" -a -z "${opt##-*}"; do
  opt=${opt#-}
  case "$opt" in
    e|-exclusive) rtype="3" ;;
    h|-help) usage ; exit 0 ;;
    s|-second) kk=${key2} ;;
    vvv) verbose="-vvv" ;;
    vv) verbose="-vv" ;;
    v|-verbose) verbose="-v" ;;
    *) echo "Unknown option: -$opt " ; exit 1 ;;
  esac
  shift
  opt="$1"
done

if [ $# -lt 1 ]
  then
    usage
    exit 1
fi

echo ">>> try to report capabilities:"
sg_persist -c ${verbose} $1
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
sg_persist --no-inquiry --read-keys ${verbose} $1
sleep 1

echo
echo ">>> register a key:"
sg_persist -n --out --register --param-sark=${kk} ${verbose} $1
sleep 1

echo
echo ">>> now key ${kk} should be registered:"
sg_persist -n --read-keys ${verbose} $1
sleep 1

echo
echo ">>> reserve the device (based on key ${kk}):"
sg_persist -n --out --reserve --param-rk=${kk} --prout-type=${rtype} ${verbose} $1
sleep 1

echo
echo ">>> check if the device is reserved (it should be now):"
sg_persist -n --read-reservation ${verbose} $1
sleep 1

echo
echo ">>> try to 'read full status' (may not be supported):"
sg_persist -n --read-full-status ${verbose} $1
sleep 1

echo
echo ">>> now release reservation:"
sg_persist -n --out --release --param-rk=${kk} --prout-type=${rtype} ${verbose} $1
sleep 1

echo
echo ">>> check if the device is reserved (it should _not_ be now):"
sg_persist -n --read-reservation ${verbose} $1
sleep 1

echo
echo ">>> unregister key ${kk}:"
sg_persist -n --out --register --param-rk=${kk} ${verbose} $1
sleep 1

echo
echo ">>> now key ${kk} should not be registered:"
sg_persist -n -k ${verbose} $1
sleep 1

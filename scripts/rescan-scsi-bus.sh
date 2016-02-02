#!/bin/bash
# Skript to rescan SCSI bus, using the 
# scsi add-single-device mechanism
# (c) 1998--2010 Kurt Garloff <kurt@garloff.de>, GNU GPL v2 or v3
# (c) 2006--2015 Hannes Reinecke, GNU GPL v2 or later
# $Id: rescan-scsi-bus.sh,v 1.57 2012/03/31 14:08:48 garloff Exp $

VERSION="20160201"
SCAN_WILD_CARD=4294967295

setcolor ()
{
  red="\e[0;31m"
  green="\e[0;32m"
  yellow="\e[0;33m"
  bold="\e[0;1m"
  norm="\e[0;0m"
}

unsetcolor () 
{
  red=""; green=""
  yellow=""; norm=""
}

echo_debug()
{
  if [ $debug -eq 1 ] ; then
     echo "$1"
  fi
}

# Output some text and return cursor to previous position
# (only works for simple strings)
# Stores length of string in LN and returns it
print_and_scroll_back ()
{
  STRG="$1"
  LN=${#STRG}
  BK=""
  declare -i cntr=0
  while test $cntr -lt $LN; do BK="$BK\e[D"; let cntr+=1; done
  echo -en "$STRG$BK"
  return $LN
}

# Overwrite a text of length $1 (fallback to $LN) with whitespace
white_out ()
{
  BK=""; WH=""
  if test -n "$1"; then LN=$1; fi
  declare -i cntr=0
  while test $cntr -lt $LN; do BK="$BK\e[D"; WH="$WH "; let cntr+=1; done
  echo -en "$WH$BK"
}

# Return hosts. sysfs must be mounted
findhosts_26 ()
{
  hosts=`find /sys/class/scsi_host/host* -maxdepth 4 -type d -o -type l 2> /dev/null | awk -F'/' '{print $5}' | sed -e 's~host~~' | sort -nu` 
  scsi_host_data=`echo "$hosts" | sed -e 's~^~/sys/class/scsi_host/host~'` 
  for hostdir in $scsi_host_data; do 
    hostno=${hostdir#/sys/class/scsi_host/host}
    if [ -f $hostdir/isp_name ] ; then
      hostname="qla2xxx"
    elif [ -f $hostdir/lpfc_drvr_version ] ; then
      hostname="lpfc"
    else
      hostname=`cat $hostdir/proc_name`
    fi
    #hosts="$hosts $hostno"
    echo_debug "Host adapter $hostno ($hostname) found."
  done  
  if [ -z "$hosts" ] ; then
    echo "No SCSI host adapters found in sysfs"
    exit 1;
  fi
  # Not necessary just use double quotes around variable to preserve new lines
  #hosts=`echo $hosts | tr ' ' '\n'`
}

# Return hosts. /proc/scsi/HOSTADAPTER/? must exist
findhosts ()
{
  hosts=
  for driverdir in /proc/scsi/*; do
    driver=${driverdir#/proc/scsi/}
    if test $driver = scsi -o $driver = sg -o $driver = dummy -o $driver = device_info; then continue; fi
    for hostdir in $driverdir/*; do
      name=${hostdir#/proc/scsi/*/}
      if test $name = add_map -o $name = map -o $name = mod_parm; then continue; fi
      num=$name
      driverinfo=$driver
      if test -r $hostdir/status; then
        num=$(printf '%d\n' `sed -n 's/SCSI host number://p' $hostdir/status`)
        driverinfo="$driver:$name"
      fi
      hosts="$hosts $num"
      echo "Host adapter $num ($driverinfo) found."
    done
  done
}

printtype ()
{
  local type=$1

  case "$type" in
    0) echo "Direct-Access" ;;
    1) echo "Sequential-Access" ;;
    2) echo "Printer" ;;
    3) echo "Processor" ;;
    4) echo "WORM" ;;
    5) echo "CD-ROM" ;;
    6) echo "Scanner" ;;
    7) echo "Optical-Device" ;;
    8) echo "Medium-Changer" ;;
    9) echo "Communications" ;;
    10) echo "Unknown" ;;
    11) echo "Unknown" ;;
    12) echo "RAID" ;;
    13) echo "Enclosure" ;;
    14) echo "Direct-Access-RBC" ;;
    *) echo "Unknown" ;;
  esac
}

print02i()
{
    if [ "$1" = "*" ] ; then 
        echo "00"
    else
        printf "%02i" "$1"
    fi
}

# Get /proc/scsi/scsi info for device $host:$channel:$id:$lun
# Optional parameter: Number of lines after first (default = 2), 
# result in SCSISTR, return code 1 means empty.
procscsiscsi ()
{  
  if test -z "$1"; then LN=2; else LN=$1; fi
  CHANNEL=`print02i "$channel"`
  ID=`print02i "$id"`
  LUN=`print02i "$lun"`
  if [ -d /sys/class/scsi_device ]; then
    SCSIPATH="/sys/class/scsi_device/${host}:${channel}:${id}:${lun}"
    if [ -d  "$SCSIPATH" ] ; then
      SCSISTR="Host: scsi${host} Channel: $CHANNEL Id: $ID Lun: $LUN"
      if [ "$LN" -gt 0 ] ; then
        IVEND=$(cat ${SCSIPATH}/device/vendor)
        IPROD=$(cat ${SCSIPATH}/device/model)
        IPREV=$(cat ${SCSIPATH}/device/rev)
        SCSIDEV=$(printf '  Vendor: %-08s Model: %-16s Rev: %-4s' "$IVEND" "$IPROD" "$IPREV")
        SCSISTR="$SCSISTR
$SCSIDEV"
      fi
      if [ "$LN" -gt 1 ] ; then
        ILVL=$(cat ${SCSIPATH}/device/scsi_level)
        type=$(cat ${SCSIPATH}/device/type)
        ITYPE=$(printtype $type)
        SCSITMP=$(printf '  Type:   %-17s                ANSI SCSI revision: %02d' "$ITYPE" "$((ILVL - 1))")
        SCSISTR="$SCSISTR
$SCSITMP"
      fi
    else
      return 1
    fi
  else
    grepstr="scsi$host Channel: $CHANNEL Id: $ID Lun: $LUN"
    SCSISTR=`cat /proc/scsi/scsi | grep -A$LN -e"$grepstr"`
  fi
  if test -z "$SCSISTR"; then return 1; else return 0; fi
}

# Find sg device with 2.6 sysfs support
sgdevice26 ()
{
  if test -e /sys/class/scsi_device/$host\:$channel\:$id\:$lun/device/generic; then
    SGDEV=`readlink /sys/class/scsi_device/$host\:$channel\:$id\:$lun/device/generic`
    SGDEV=`basename $SGDEV`
  else
    for SGDEV in /sys/class/scsi_generic/sg*; do
      DEV=`readlink $SGDEV/device`
      if test "${DEV##*/}" = "$host:$channel:$id:$lun"; then
        SGDEV=`basename $SGDEV`; return
      fi
    done
    SGDEV=""
  fi  
}

# Find sg device with 2.4 report-devs extensions
sgdevice24 ()
{
  if procscsiscsi 3; then
    SGDEV=`echo "$SCSISTR" | grep 'Attached drivers:' | sed 's/^ *Attached drivers: \(sg[0-9]*\).*/\1/'`
  fi
}

# Find sg device that belongs to SCSI device $host $channel $id $lun
# and return in SGDEV
sgdevice ()
{
  SGDEV=
  if test -d /sys/class/scsi_device; then
    sgdevice26
  else  
    DRV=`grep 'Attached drivers:' /proc/scsi/scsi 2>/dev/null`
    repdevstat=$((1-$?))
    if [ $repdevstat = 0 ]; then
      echo "scsi report-devs 1" >/proc/scsi/scsi
      DRV=`grep 'Attached drivers:' /proc/scsi/scsi 2>/dev/null`
      if [ $? = 1 ]; then return; fi
    fi
    if ! `echo $DRV | grep 'drivers: sg' >/dev/null`; then
      modprobe sg
    fi
    sgdevice24
    if [ $repdevstat = 0 ]; then
      echo "scsi report-devs 0" >/proc/scsi/scsi
    fi
  fi
}

# Test if SCSI device is still responding to commands
# Return values:
#   0 device is present
#   1 device has changed
#   2 device has been removed
testonline ()
{
  : testonline
  RC=0
  # Set default values
  IPTYPE=31
  IPQUAL=3
  if test ! -x /usr/bin/sg_turs; then return 0; fi
  sgdevice
  if test -z "$SGDEV"; then return 0; fi
  sg_turs /dev/$SGDEV >/dev/null 2>&1
  RC=$?

  # Handle in progress of becoming ready and unit attention
  while test $RC = 2 -o $RC = 6 && test $ctr -le 30; do
    if test $RC = 2 -a "$RMB" != "1"; then echo -n "."; let LN+=1; sleep 1
    else sleep 0.02; fi
    let ctr+=1
    sg_turs /dev/$SGDEV >/dev/null 2>&1
    RC=$?
    # Check for removable device; TEST UNIT READY obviously will
    # fail for a removable device with no medium
    RMB=`sg_inq /dev/$SGDEV 2>/dev/null | grep 'RMB=' | sed 's/^.*RMB=\(.\).*$/\1/'`
    print_and_scroll_back "$host:$channel:$id:$lun $SGDEV ($RMB) "
    test $RC = 2 -a "$RMB" = "1" && break
  done
  if test $ctr != 0; then white_out; fi
  # echo -e "\e[A\e[A\e[A${yellow}Test existence of $SGDEV = $RC ${norm} \n\n\n"
  if test $RC = 1; then return $RC; fi
  # Reset RC (might be !=0 for passive paths)
  RC=0
  # OK, device online, compare INQUIRY string
  INQ=`sg_inq $sg_len_arg /dev/$SGDEV 2>/dev/null`
  if [ -z "$INQ" ] ; then
    echo -e "\e[A\e[A\e[A\e[A${red}$SGDEV changed: ${bold}INQUIRY failed${norm}    \n\n\n"
    return 2
  fi
  IVEND=`echo "$INQ" | grep 'Vendor identification:' | sed 's/^[^:]*: \(.*\)$/\1/'`
  IPROD=`echo "$INQ" | grep 'Product identification:' | sed 's/^[^:]*: \(.*\)$/\1/'`
  IPREV=`echo "$INQ" | grep 'Product revision level:' | sed 's/^[^:]*: \(.*\)$/\1/'`
  STR=`printf "  Vendor: %-08s Model: %-16s Rev: %-4s" "$IVEND" "$IPROD" "$IPREV"`
  IPTYPE=`echo "$INQ" | sed -n 's/.* Device_type=\([0-9]*\) .*/\1/p'`
  IPQUAL=`echo "$INQ" | sed -n 's/ *PQual=\([0-9]*\)  Device.*/\1/p'`
  if [ "$IPQUAL" != 0 ] ; then
    [ -z "$IPQUAL" ] && IPQUAL=3
    [ -z "$IPTYPE" ] && IPTYPE=31
    echo -e "\e[A\e[A\e[A\e[A${red}$SGDEV changed: ${bold}LU not available (PQual $IPQUAL)${norm}    \n\n\n"
    return 2
  fi

  TYPE=$(printtype $IPTYPE)
  if ! procscsiscsi ; then
    echo -e "\e[A\e[A\e[A\e[A${red}$SGDEV removed.\n\n\n"
    return 2
  fi
  TMPSTR=`echo "$SCSISTR" | grep 'Vendor:'`
  if [ "$TMPSTR" != "$STR" ]; then
    echo -e "\e[A\e[A\e[A\e[A${red}$SGDEV changed: ${bold}\nfrom:${SCSISTR#* } \nto: $STR ${norm} \n\n\n"
    return 1
  fi
  TMPSTR=`echo "$SCSISTR" | sed -n 's/.*Type: *\(.*\) *ANSI.*/\1/p' | sed 's/ *$//g'`
  if [ "$TMPSTR" != "$TYPE" ] ; then
    echo -e "\e[A\e[A\e[A\e[A${red}$SGDEV changed: ${bold}\nfrom:${TMPSTR} \nto: $TYPE ${norm} \n\n\n"
    return 1
  fi
  return $RC
}

# Test if SCSI device $host $channen $id $lun exists
# Outputs description from /proc/scsi/scsi (unless arg passed)
# Returns SCSISTR (empty if no dev)
testexist ()
{
  : testexist
  SCSISTR=
  if procscsiscsi && test -z "$1"; then
    echo "$SCSISTR" | head -n1
    echo "$SCSISTR" | tail -n2 | pr -o4 -l1
  fi
}

# Returns the list of existing channels per host
chanlist ()
{
  local hcil
  local cil
  local chan
  local tmpchan

  for dev in /sys/class/scsi_device/${host}:* ; do
    [ -d $dev ] || continue;
    hcil=${dev##*/}
    cil=${hcil#*:}
    chan=${cil%%:*}
    for tmpchan in $channelsearch ; do
      if test "$chan" -eq $tmpchan ; then
        chan=
      fi
    done
    if test -n "$chan" ; then
      channelsearch="$channelsearch $chan"
    fi
  done
  if test -z "$channelsearch"; then channelsearch="0"; fi
}

# Returns the list of existing targets per host
idlist ()
{
  local hcil
  local target
  local tmpid
  local newid

  idsearch=$(ls /sys/class/scsi_device/ | sed -n "s/${host}:${channel}:\([0-9]*\):[0-9]*/\1/p" | uniq)
  echo "${channel} - -" > /sys/class/scsi_host/host${host}/scan
  # Rescan to check if we found new targets
  newsearch=$(ls /sys/class/scsi_device/ | sed -n "s/${host}:${channel}:\([0-9]*\):[0-9]*/\1/p" | uniq)
  for id in $newsearch ; do
    newid=$id
    for tmpid in $idsearch ; do
      if test $id -eq $tmpid ; then
        newid=
        break
      fi
    done
    if test -n "$newid" ; then
      id=$newid
      for dev in /sys/class/scsi_device/${host}:${channel}:${newid}:* ; do
        [ -d $dev ] || continue;
        hcil=${dev##*/}
        lun=${hcil##*:}
        printf "\r${green}NEW: $norm"
        testexist
        if test "$SCSISTR" ; then
          incrfound "$hcil"
        fi
      done
    fi
  done
}

# Returns the list of existing LUNs from device $host $channel $id $lun
# and returns list to stdout
getluns()
{
  sgdevice
  if test -z "$SGDEV"; then return 1; fi
  if test ! -x /usr/bin/sg_luns; then echo 0; return 1; fi
  LLUN=`sg_luns /dev/$SGDEV 2>/dev/null | sed -n 's/    \(.*\)/\1/p'`
  # Added -z $LLUN condition because $? gets the RC from sed, not sg_luns
  if test $? != 0 -o -z "$LLUN"; then echo 0; return 1; fi
  for lun in $LLUN ; do
      # Swap LUN number
      l0=$(printf '%u' 0x$lun)
      l1=$(( ($l0 >> 48) & 0xffff ))
      l2=$(( ($l0 >> 32) & 0xffff )) 
      l3=$(( ($l0 >> 16) & 0xffff ))
      l4=$(( $l0 & 0xffff ))
      l0=$(( ( ( ($l4 * 0xffff) + $l3 ) * 0xffff + $l2 ) * 0xffff + $l1 ))
      printf "%u\n" $l0
  done
  return 0
}

# Wait for udev to settle (create device nodes etc.)
udevadm_settle()
{
  local tmo=60
  if test -x /sbin/udevadm; then 
    print_and_scroll_back " Calling udevadm settle (can take a while) "
    # Loop for up to 60 seconds if sd devices still are settling..
    # This allows us to continue if udev events are stuck on multipaths in recovery mode
    while [ $tmo -gt 0 ] ; do
      if ! /sbin/udevadm settle --timeout=1 | egrep -q sd[a-z]+ ; then
        break;
      fi
      let tmo=$tmo-1
    done
    white_out
  elif test -x /sbin/udevsettle; then
    print_and_scroll_back " Calling udevsettle (can take a while) "
    /sbin/udevsettle
    white_out
  else
    sleep 0.02
  fi
}

# Perform scan on a single lun $host $channel $id $lun
dolunscan()
{
  local remappedlun0=
  SCSISTR=
  devnr="$host $channel $id $lun"
  echo -e " Scanning for device $devnr ... "
  printf "${yellow}OLD: $norm"
  testexist
  # Device exists: Test whether it's still online
  # (testonline returns 2 if it's gone and 1 if it has changed)
  if test "$SCSISTR" ; then
    testonline
    RC=$?
    # Well known lun transition case. Only for Direct-Access devs (type 0)
    # If block directory exists && and PQUAL != 0, we unmapped lun0 and just have a well-known lun
    # If block directory doesn't exist && PQUAL == 0, we mapped a real lun0
    if test $lun -eq 0 -a $IPTYPE -eq 0 ; then
      if test $RC = 2 ; then
        if test -e /sys/class/scsi_device/${host}:${channel}:${id}:${lun}/device; then
          if test -d /sys/class/scsi_device/${host}:${channel}:${id}:${lun}/device/block ; then
            remappedlun0=2  # Transition from real lun 0 to well-known
          else
            RC=0   # Set this so the system leaves the existing well known lun alone. This is a lun 0 with no block directory
          fi
        fi
      elif test $RC = 0 -a $IPTYPE -eq 0; then
        if test -e /sys/class/scsi_device/${host}:${channel}:${id}:${lun}/device; then
          if test ! -d /sys/class/scsi_device/${host}:${channel}:${id}:${lun}/device/block ; then
            remappedlun0=1  # Transition from well-known to real lun 0
          fi
        fi
      fi
    fi
  fi

  # Special case: lun 0 just got added (for reportlunscan),
  # so make sure we correctly treat it as new
  if test "$lun" = "0" -a "$1" = "1" -a -z "$remappedlun0"; then
    SCSISTR=""
    printf "\r\e[A\e[A\e[A"
  fi

  : f $remove s $SCSISTR
  if test "$remove" -a "$SCSISTR" -o "$remappedlun0" = "1"; then
    if test $RC != 0 -o ! -z "$forceremove" -o -n "$remappedlun0"; then
      if test "$remappedlun0" != "1" ; then
        echo -en "\r\e[A\e[A\e[A${red}REM: "
        echo "$SCSISTR" | head -n1
        echo -e "${norm}\e[B\e[B"
      fi
      if test -e /sys/class/scsi_device/${host}:${channel}:${id}:${lun}/device; then
        # have to preemptively do this so we can figure out the mpath device
        # Don't do this if we're deleting a well known lun to replace it
        if test "$remappedlun0" != "1" ; then
          incrrmvd "$host:$channel:$id:$lun"
        fi
        echo 1 > /sys/class/scsi_device/${host}:${channel}:${id}:${lun}/device/delete
        sleep 0.02
      else
        echo "scsi remove-single-device $devnr" > /proc/scsi/scsi
        if test $RC -eq 1 -o $lun -eq 0 ; then
          # Try readding, should fail if device is gone
          echo "scsi add-single-device $devnr" > /proc/scsi/scsi
        fi
      fi
    fi
    if test $RC = 0 -o "$forcerescan" ; then
      if test -e /sys/class/scsi_device/${host}:${channel}:${id}:${lun}/device; then
        echo 1 > /sys/class/scsi_device/${host}:${channel}:${id}:${lun}/device/rescan
      fi
    fi
    printf "\r\e[A\e[A\e[A${yellow}OLD: $norm"
    testexist
    if test -z "$SCSISTR" -a $RC != 1 -a "$remappedlun0" != "1"; then
      printf "\r${red}DEL: $norm\r\n\n"
      # In the event we're replacing with a well known node, we need to let it continue, to create the replacement node
      test "$remappedlun0" != "2" && return 1
    fi
  fi
  if test -z "$SCSISTR" -o -n "$remappedlun0"; then
    if test "$remappedlun0" != "2" ; then
      # Device does not exist, try to add
      printf "\r${green}NEW: $norm"
    fi
    if test -e /sys/class/scsi_host/host${host}/scan; then
      echo "$channel $id $lun" > /sys/class/scsi_host/host${host}/scan 2> /dev/null
    else
      echo "scsi add-single-device $devnr" > /proc/scsi/scsi
    fi
    testexist
    if test -z "$SCSISTR"; then
      # Device not present
      printf "\r\e[A";
      # Optimization: if lun==0, stop here (only if in non-remove mode)
      if test $lun = 0 -a -z "$remove" -a $optscan = 1; then 
        break;
      fi
    else 
      if test "$remappedlun0" != "2" ; then
        incrfound "$host:$channel:$id:$lun"
      fi
    fi
  fi
}

# Perform report lun scan on $host $channel $id using REPORT_LUNS
doreportlun()
{
  lun=0
  SCSISTR=
  devnr="$host $channel $id $lun"
  echo -en " Scanning for device $devnr ...\r"
  lun0added=
  #printf "${yellow}OLD: $norm"
  # Phase one: If LUN0 does not exist, try to add
  testexist -q
  if test -z "$SCSISTR"; then
    # Device does not exist, try to add
    #printf "\r${green}NEW: $norm"
    if test -e /sys/class/scsi_host/host${host}/scan; then
      echo "$channel $id $lun" > /sys/class/scsi_host/host${host}/scan 2> /dev/null
      udevadm_settle
    else
      echo "scsi add-single-device $devnr" > /proc/scsi/scsi
    fi
    testexist -q
    if test -n "$SCSISTR"; then
      lun0added=1
      #testonline
    else
      # Device not present
      # return
      # Find alternative LUN to send getluns to
      for dev in /sys/class/scsi_device/${host}:${channel}:${id}:*; do
        [ -d "$dev" ] || continue
        lun=${dev##*:}
        break
      done
    fi
  fi
  targetluns=`getluns`
  REPLUNSTAT=$?
  lunremove=
  #echo "getluns reports " $targetluns
  olddev=`find /sys/class/scsi_device/ -name $host:$channel:$id:* 2>/dev/null | sort -t: -k4 -n`
  oldluns=`echo "$olddev" | awk -F'/' '{print $5}' | awk -F':' '{print $4}'`
  oldtargets="$targetluns"
  # OK -- if we don't have a LUN to send a REPORT_LUNS to, we could
  # fall back to wildcard scanning. Same thing if the device does not
  # support REPORT_LUNS
  # TODO: We might be better off to ALWAYS use wildcard scanning if 
  # it works
  if test "$REPLUNSTAT" = "1"; then
    if test -e /sys/class/scsi_host/host${host}/scan; then
      echo "$channel $id -" > /sys/class/scsi_host/host${host}/scan 2> /dev/null
      udevadm_settle
    else
      echo "scsi add-single-device $host $channel $id $SCAN_WILD_CARD" > /proc/scsi/scsi
    fi
    targetluns=`find /sys/class/scsi_device/ -name $host:$channel:$id:* 2>/dev/null | awk -F'/' '{print $5}' | awk -F':' '{print $4}' | sort -n`
    let found+=`echo "$targetluns" | wc -l`
    let found-=`echo "$olddev" | wc -l`
  fi
  if test -z "$targetluns"; then targetluns="$oldtargets"; fi
  # Check existing luns
  for dev in $olddev; do
    [ -d "$dev" ] || continue
    lun=${dev##*:}
    newsearch=
    inlist=
    # OK, is existing $lun (still) in reported list
    for tmplun in $targetluns; do
      if test $tmplun -eq $lun ; then
        inlist=1
        dolunscan $lun0added
      else
        newsearch="$newsearch $tmplun"
      fi
    done
    # OK, we have now done a lunscan on $lun and 
    # $newsearch is the old $targetluns without $lun
    if [ -z "$inlist" ]; then
      # Stale lun
      lunremove="$lunremove $lun"
    fi
    # $lun removed from $lunsearch (echo for whitespace cleanup)
    targetluns=`echo $newsearch`
  done
  # Add new ones and check stale ones
  for lun in $targetluns $lunremove; do
    dolunscan $lun0added
  done
}

# Perform search (scan $host)
dosearch ()
{
  if test -z "$channelsearch" ; then
    chanlist
  fi
  for channel in $channelsearch; do
    if test -z "$idsearch" ; then
      idlist
    fi
    for id in $idsearch; do
      if test -z "$lunsearch" ; then
        doreportlun
      else
        for lun in $lunsearch; do
          dolunscan
        done
      fi
    done
  done
}
 
expandlist ()
{
  list=$1
  result=""
  first=${list%%,*}
  rest=${list#*,}
  while test ! -z "$first"; do 
    beg=${first%%-*};
    if test "$beg" = "$first"; then
      result="$result $beg";
    else
      end=${first#*-}
      result="$result `seq $beg $end`"
    fi
    test "$rest" = "$first" && rest=""
    first=${rest%%,*}
    rest=${rest#*,}
  done
  echo $result
}

searchexisting()
{
  local tmpch;
  local tmpid
  local match=0
  local targets=`ls -d /sys/class/scsi_device/$host:* 2> /dev/null | egrep -o $host:[0-9]+:[0-9]+ | sort | uniq`

  # Nothing came back on this host, so we should skip it
  test -z "$targets" && return

  local target=;
  for target in $targets ; do
    channel=`echo $target | cut -d":" -f2`
    id=`echo $target | cut -d":" -f 3`
    if [ -n "$channelsearch" ] ; then
      for tmpch in $channelsearch ; do
        test $tmpch -eq $channel && match=1
      done
    else
      match=1
    fi

    test $match -eq 0 && continue
    match=0

    if [ $filter_ids -eq 1 ] ; then
      for tmpid in $idsearch ; do
        if [ $tmpid -eq $id ] ; then
          match=1
        fi
      done
    else
      match=1
    fi
    test $match -eq 1 && doreportlun
  done
}

# Go through all of the existing devices and figure out any that have been remapped
findremapped()
{
  local hctl=;
  local devs=`ls /sys/class/scsi_device/`
  local sddev=
  local id_serial=
  local id_serial_old=
  local sysfs_devpath=
  local mpath_uuid=
  local remapped=
  mpaths=""
  local tmpfile=$(mktemp /tmp/rescan-scsi-bus.XXXXXXXX 2> /dev/null)

  if [ -z "$tmpfile" ] ; then
    tmpfile="/tmp/rescan-scsi-bus.$$"
    rm -f $tmpfile
  fi

  # Get all of the ID_SERIAL attributes, after finding their sd node
  for hctl in $devs ; do
    if [ -d /sys/class/scsi_device/$hctl/device/block ] ; then
      sddev=`ls /sys/class/scsi_device/$hctl/device/block`
      id_serial_old=`udevadm info -q all -n $sddev | grep "ID_SERIAL=" | cut -d"=" -f2`
      [ -z "$id_serial_old" ] && id_serial_old="none"
      echo "$hctl $sddev $id_serial_old" >> $tmpfile
    fi
  done

  # Trigger udev to update the info
  echo -n "Triggering udev to update device information... "
  /sbin/udevadm trigger
  udevadm_settle 2>&1 /dev/null
  echo "Done"

  # See what changed and reload the respective multipath device if applicable
  while read hctl sddev id_serial_old ; do
    remapped=0
    id_serial=`udevadm info -q all -n $sddev | grep "ID_SERIAL=" | cut -d"=" -f2`
    [ -z "$id_serial" ] && id_serial="none"
    if [ "$id_serial_old" != "$id_serial" ] ; then
      remapped=1
    fi
    # If udev events updated the disks already, but the multipath device isn't update
    # check for old devices to make sure we found remapped luns
    if [ -n "$mp_enable" ] && [ $remapped -eq 0 ]; then
      findmultipath $sddev $id_serial
      if [ $? -eq 1 ] ; then
        remapped=1
      fi
    fi

    # if uuid is 1, it's unmapped, so we don't want to treat it as a remap
    # if remapped flag is 0, just skip the rest of the logic
    if [ "$id_serial" = "1" ] || [ $remapped -eq 0 ] ; then
      continue
    fi
    printf "${yellow}REMAPPED: $norm"
    host=`echo $hctl | cut -d":" -f1`
    channel=`echo $hctl | cut -d":" -f2`
    id=`echo $hctl | cut -d":" -f3`
    lun=`echo $hctl | cut -d":" -f4`
    procscsiscsi
    echo "$SCSISTR"
    incrchgd "$hctl"
  done < $tmpfile
  rm -f $tmpfile

  if test -n "$mp_enable" -a -n "$mpaths" ; then
    echo "Updating multipath device mappings"
    flushmpaths
    $MULTIPATH | grep "create:" 2> /dev/null
  fi
}

incrfound()
{
  local hctl="$1"
  if test -n "$hctl" ; then
    let found+=1
    FOUNDDEVS="$FOUNDDEVS\t[$hctl]\n"
  else
    return
  fi
}

incrchgd()
{
  local hctl="$1"
  if test -n "$hctl" ; then
    if ! echo $CHGDEVS | grep -q "\[$hctl\]"; then
      let updated+=1
      CHGDEVS="$CHGDEVS\t[$hctl]\n"
    fi
  else
    return
  fi

  if test -n "$mp_enable" ; then
    local sdev="`findsddev \"$hctl\"`"
    if test -n "$sdev" ; then
      findmultipath "$sdev"
    fi
  fi
}

incrrmvd()
{
  local hctl="$1"
  if test -n "$hctl" ; then
    let rmvd+=1;
    RMVDDEVS="$RMVDDEVS\t[$hctl]\n"
  else
    return
  fi

  if test -n "$mp_enable" ; then
    local sdev="`findsddev \"$hctl\"`"
    if test -n "$sdev" ; then
      findmultipath "$sdev"
    fi
  fi
}

findsddev()
{
  local hctl="$1"
  local sddev=  

  if test ! -e /sys/class/scsi_device/$hctl/device/block ; then
    return 1
  fi 

  sddev=`ls /sys/class/scsi_device/$hctl/device/block`
  echo $sddev

  return 0
}

addmpathtolist()
{
  local mp="$1"
  local mp2=

  for mp2 in $mpaths ; do
    # The multipath device is already in the list
    if [ "$mp2" = "$mp" ] ; then
      return
    fi
  done
  mpaths="$mpaths $mp"
}

findmultipath()
{
  local dev="$1"
  local find_mismatch="$2"
  local mp=
  local mp2=
  local found_dup=0

  # Need a sdev, and executable multipath and dmsetup command here
  if [ -z "$dev" ] || [ ! -x $DMSETUP ] || [ ! -x "$MULTIPATH" ] ; then
    return 1
  fi

  local maj_min=`cat /sys/block/$dev/dev`
  for mp in $($DMSETUP ls --target=multipath | cut -f 1) ; do
    [ "$mp" = "No" ] && break;
    if $($DMSETUP status $mp | grep -q " $maj_min ") ; then
      # With two arguments, look up current uuid from sysfs
      # if it doesn't match what was passed, this multipath
      # device is not updated, so this is a remapped LUN
      if [ -n "$find_mismatch" ] ; then
        mp2=`$MULTIPATH -l $mp | egrep -o dm-[0-9]+`
        mp2=`cat /sys/block/$mp2/dm/uuid | cut -f2 -d-`
        if [ "$find_mismatch" != "$mp2" ] ; then
          addmpathtolist $mp
          found_dup=1
        fi
        continue
      fi
      # Normal mode: Find the first multipath with the sdev
      # and add it to the list
      addmpathtolist $mp
      return
    fi
  done

  # Return 1 to signal that a duplicate was found to the calling function
  if [ $found_dup -eq 1 ] ; then
    return 1
  else
    return 0
  fi
}

reloadmpaths()
{
  local mpath
  if [ ! -x "$MULTIPATH" ] ; then
    echo "no -x multipath"
    return
  fi

  # Pass 1 as the argument to reload all mpaths
  if [ "$1" = "1" ] ; then
    echo "Reloading all multipath devices"
    $MULTIPATH -r > /dev/null 2>&1
    return
  fi

  # Reload the multipath devices
  for mpath in $mpaths ; do
    echo -n "Reloading multipath device $mpath... "
    $MULTIPATH -r $mpath > /dev/null 2>&1
    if test "$?" = "0" ; then
      echo "Done"
    else
      echo "Fail"
    fi
  done
}

resizempaths()
{
  local mpath

  for mpath in $mpaths ; do
    echo -n "Resizing multipath map $mpath ..."
    multipathd -k"resize map $mpath"
    let updated+=1
  done
}

flushmpaths()
{
  local mpath
  local remove=""
  local i
  local flush_retries=5

  if test -n "$1" ; then
    for mpath in $($DMSETUP ls --target=multipath | cut -f 1) ; do
      [ "$mpath" = "No" ] && break
      num=$($DMSETUP status $mpath | awk 'BEGIN{RS=" ";active=0}/[0-9]+:[0-9]+/{dev=1}/A/{if (dev == 1) active++; dev=0} END{ print active }')
      if [ $num -eq 0 ] ; then
        remove="$remove $mpath"
      fi
    done
  else
    remove="$mpaths"
  fi

  for mpath in $remove ; do
    i=0
    echo -n "Flushing multipath device $mpath... "
    while [ $i -lt $flush_retries ] ; do
      $DMSETUP message $mpath 0 fail_if_no_path > /dev/null 2>&1
      $MULTIPATH -f $mpath > /dev/null 2>&1
      if test "$?" = "0" ; then
        echo "Done ($i retries)"
        break
      elif test $i -eq $flush_retries ; then
        echo "Fail"
      fi
      sleep 0.02
      let i=$i+1
    done
  done
}


# Find resized luns
findresized()
{
  local devs=`ls /sys/class/scsi_device/`
  local size=
  local new_size=
  local sysfs_path=
  local sddev=
  local i=
  local m=
  local mpathsize=
  declare -a mpathsizes

  for hctl in $devs ; do
    sysfs_path="/sys/class/scsi_device/$hctl/device"
    if [ -d "$sysfs_path/block" ] ; then
      sddev=`ls $sysfs_path/block`
      size=`cat $sysfs_path/block/$sddev/size`

      echo 1 > $sysfs_path/rescan
      new_size=`cat $sysfs_path/block/$sddev/size`

      if [ "$size" != "$new_size" ] && [ "$size" != "0" ] && [ "$new_size" != "0" ] ; then
        printf "${yellow}RESIZED: $norm"
        host=`echo $hctl | cut -d":" -f1`
        channel=`echo $hctl | cut -d":" -f2`
        id=`echo $hctl | cut -d":" -f3`
        lun=`echo $hctl | cut -d":" -f4`

        procscsiscsi
        echo "$SCSISTR"
        incrchgd "$hctl"
      fi
    fi
  done

  if test -n "$mp_enable" -a -n "$mpaths" ; then
    i=0
    for m in $mpaths ; do
      mpathsizes[$i]="`$MULTIPATH -l $m | egrep -o [0-9]+.[0-9]+[KMGT]`"
      let i=$i+1
    done
    resizempaths
    i=0
    for m in $mpaths ; do
      mpathsize="`$MULTIPATH -l $m | egrep -o [0-9\.]+[KMGT]`"
      echo "$m ${mpathsizes[$i]} => $mpathsize"
      let i=$i+1
    done
  fi
}

FOUNDDEVS=""
CHGDEVS=""
RMVDDEVS=""

# main
if test @$1 = @--help -o @$1 = @-h -o @$1 = @-?; then
    echo "Usage: rescan-scsi-bus.sh [options] [host [host ...]]"
    echo "Options:"
    echo " -a      scan all targets, not just currently existing [default: disabled]"
    echo " -c      enables scanning of channels 0 1   [default: 0 / all detected ones]"
    echo " -d      enable debug                       [default: 0]"
    echo " -f      flush failed multipath devices     [default: disabled]"
    echo " -h      help: print this usage message then exit"
    echo " -i      issue a FibreChannel LIP reset     [default: disabled]"
    echo " -I SECS issue a FibreChannel LIP reset and wait for SECS seconds [default: disabled]"
    echo " -l      activates scanning for LUNs 0--7   [default: 0]"
    echo " -L NUM  activates scanning for LUNs 0--NUM [default: 0]"
    echo " -m      update multipath devices           [default: disabled]"
    echo " -r      enables removing of devices        [default: disabled]"
    echo " -s      look for resized disks and reload associated multipath devices, if applicable"
    echo " -u      look for existing disks that have been remapped"
    echo " -V      print version date then exit"
    echo " -w      scan for target device IDs 0--15   [default: 0--7]"
    echo "--alltargets:    same as -a"
    echo "--attachpq3:     Tell kernel to attach sg to LUN 0 that reports PQ=3"
    echo "--channels=LIST: Scan only channel(s) in LIST"
    echo "--color:         use coloured prefixes OLD/NEW/DEL"
    echo "--flush:         same as -f"
    echo "--forceremove:   Remove and readd every device (DANGEROUS)"
    echo "--forcerescan:   Rescan existing devices"
    echo "--help:          print this usage message then exit"
    echo "--hosts=LIST:    Scan only host(s) in LIST"
    echo "--ids=LIST:      Scan only target ID(s) in LIST"
    echo "--issue-lip:     same as -i"
    echo "--issue-lip-wait=SECS:     same as -I"
    echo "--largelun:      Tell kernel to support LUNs > 7 even on SCSI2 devs"
    echo "--luns=LIST:     Scan only lun(s) in LIST"  
    echo "--multipath:     same as -m"
    echo "--nooptscan:     don't stop looking for LUNs is 0 is not found"
    echo "--remove:        same as -r"
    echo "--reportlun2:    Tell kernel to try REPORT_LUN even on SCSI2 devices"
    echo "--resize:        same as -s"
    echo "--sparselun:     Tell kernel to support sparse LUN numbering"
    echo "--sync/nosync:   Issue a sync / no sync [default: sync if remove]"
    echo "--update:        same as -u"
    echo "--version:       same as -V"
    echo "--wide:          same as -w"
    echo ""
    echo "Host numbers may thus be specified either directly on cmd line (deprecated)"
    echo "or with the --hosts=LIST parameter (recommended)."
    echo "LIST: A[-B][,C[-D]]... is a comma separated list of single values and ranges"
    echo "(No spaces allowed.)"
    exit 0
fi

if test @$1 = @--version -o @$1 = @-V ; then
    echo ${VERSION}
    exit 0
fi

if test ! -d /sys/class/scsi_host/ -a ! -d /proc/scsi/; then
  echo "Error: SCSI subsystem not active"
  exit 1
fi

# Make sure sg is there
modprobe sg >/dev/null 2>&1

if test -x /usr/bin/sg_inq; then
  sg_version=$(sg_inq -V 2>&1 | cut -d " " -f 3)
  if test -n "$sg_version"; then
    sg_ver_maj=${sg_version:0:1}
    sg_version=${sg_version##?.}
    let sg_version+=$((100*$sg_ver_maj))
  fi
  sg_version=${sg_version##0.}
  #echo "\"$sg_version\""
  if [ -z "$sg_version" -o "$sg_version" -lt 70 ] ; then
    sg_len_arg="-36"
  else
    sg_len_arg="--len=36"
  fi
else
  echo "WARN: /usr/bin/sg_inq not present -- please install sg3_utils"
  echo " or rescan-scsi-bus.sh might not fully work."     
fi    

# defaults
unsetcolor
debug=0
lunsearch=
opt_idsearch=`seq 0 7`
filter_ids=0
opt_channelsearch=
remove=
updated=0
update=0
resize=0
forceremove=
optscan=1
sync=1
existing_targets=1
mp_enable=
lipreset=-1
declare -i scan_flags=0

# Scan options
opt="$1"
while test ! -z "$opt" -a -z "${opt##-*}"; do
  opt=${opt#-}
  case "$opt" in
    a) existing_targets=;;  #Scan ALL targets when specified
    d) debug=1 ;;
    f) flush=1 ;;
    l) lunsearch=`seq 0 7` ;;
    L) lunsearch=`seq 0 $2`; shift ;;
    m) mp_enable=1 ;;
    w) opt_idsearch=`seq 0 15` ;;
    c) opt_channelsearch="0 1" ;;
    r) remove=1 ;;
    s) resize=1; mp_enable=1 ;;
    i) lipreset=0 ;;
    I) shift; lipreset=$opt ;;
    u) update=1 ;;
    -alltargets)  existing_targets=;;
    -flush)       flush=1 ;;
    -remove)      remove=1 ;;
    -forcerescan) remove=1; forcerescan=1 ;;
    -forceremove) remove=1; forceremove=1 ;;
    -hosts=*)     arg=${opt#-hosts=};   hosts=`expandlist $arg` ;;
    -channels=*)  arg=${opt#-channels=};opt_channelsearch=`expandlist $arg` ;; 
    -ids=*)   arg=${opt#-ids=};         opt_idsearch=`expandlist $arg` ; filter_ids=1;;
    -luns=*)  arg=${opt#-luns=};        lunsearch=`expandlist $arg` ;; 
    -color) setcolor ;;
    -nooptscan) optscan=0 ;;
    -issue-lip) lipreset=0 ;;
    -issue-lip-wait) lipreset=${opt#-issue-lip-wait=};;
    -sync) sync=2 ;;
    -nosync) sync=0 ;;
    -multipath) mp_enable=1 ;;
    -attachpq3) scan_flags=$(($scan_flags|0x1000000)) ;;
    -reportlun2) scan_flags=$(($scan_flags|0x20000)) ;;
    -resize) resize=1;;
    -largelun) scan_flags=$(($scan_flags|0x200)) ;;
    -sparselun) scan_flags=$((scan_flags|0x40)) ;;
    -update) update=1;;
    -wide) opt_idsearch=`seq 0 15` ;;
    *) echo "Unknown option -$opt !" ;;
  esac
  shift
  opt="$1"
done    

if [ -z "$hosts" ] ; then
  if test -d /sys/class/scsi_host; then 
    findhosts_26
  else  
    findhosts
  fi  
fi

if [ -d /sys/class/scsi_host -a ! -w /sys/class/scsi_host ]; then
  echo "You need to run scsi-rescan-bus.sh as root"
  exit 2
fi  
if test "$sync" = 1 -a "$remove" = 1; then sync=2; fi
if test "$sync" = 2; then echo "Syncing file systems"; sync; fi
if test -w /sys/module/scsi_mod/parameters/default_dev_flags -a $scan_flags != 0; then
  OLD_SCANFLAGS=`cat /sys/module/scsi_mod/parameters/default_dev_flags`
  NEW_SCANFLAGS=$(($OLD_SCANFLAGS|$scan_flags))
  if test "$OLD_SCANFLAGS" != "$NEW_SCANFLAGS"; then
    echo -n "Temporarily setting kernel scanning flags from "
    printf "0x%08x to 0x%08x\n" $OLD_SCANFLAGS $NEW_SCANFLAGS
    echo $NEW_SCANFLAGS > /sys/module/scsi_mod/parameters/default_dev_flags
  else
    unset OLD_SCANFLAGS
  fi
fi  
DMSETUP=$(which dmsetup)
[ -z "$DMSETUP" ] && flush= && mp_enable=
MULTIPATH=$(which multipath)
[ -z "$MULTIPATH" ] && flush= && mp_enable=

echo -n "Scanning SCSI subsystem for new devices"
test -z "$flush" || echo -n ", flush failed multipath devices,"
test -z "$remove" || echo -n " and remove devices that have disappeared"
echo
declare -i found=0
declare -i updated=0
declare -i rmvd=0

if [ -n "$flush" ] ; then
  if [ -x "$MULTIPATH" ] ; then
    flushmpaths 1
  fi
fi

# Update existing mappings
if [ $update -eq 1 ] ; then
  echo "Searching for remapped LUNs"
  findremapped
  # If you've changed the mapping, there's a chance it's a different size
  mpaths=""
  findresized
# Search for resized LUNs
elif [ $resize -eq 1 ] ; then
  echo "Searching for resized LUNs"
  findresized
# Normal rescan mode
else
  for host in $hosts; do
  echo -n "Scanning host $host "
  if test -e /sys/class/fc_host/host$host ; then
    # It's pointless to do a target scan on FC
    issue_lip=/sys/class/fc_host/host$host/issue_lip
    if test -e $issue_lip -a $lipreset -ge 0 ; then
      echo 1 > $issue_lip 2> /dev/null;
      udevadm_settle
      [ $lipreset -gt 0 ] && sleep $lipreset
    fi
    channelsearch=
    idsearch=
  else
    channelsearch=$opt_channelsearch
    idsearch=$opt_idsearch
  fi
  [ -n "$channelsearch" ] && echo -n "channels $channelsearch "
  echo -n "for "
  if [ -n "$idsearch" ] ; then
    echo -n " SCSI target IDs " $idsearch
  else
    echo -n " all SCSI target IDs"
  fi
  if [ -n "$lunsearch" ] ; then
    echo ", LUNs " $lunsearch
  else
    echo ", all LUNs"
  fi

  if [ -n "$existing_targets" ] ; then
    searchexisting
  else
    dosearch
  fi
  done
  if test -n "$OLD_SCANFLAGS"; then
    echo $OLD_SCANFLAGS > /sys/module/scsi_mod/parameters/default_dev_flags
  fi
fi

let rmvd_found=$rmvd+$found
if test -n "$mp_enable" -a $rmvd_found -gt 0 ; then
  echo "Attempting to update multipath devices..."
  if test $rmvd -gt 0 ; then
    udevadm_settle
    echo "Removing multipath mappings for removed devices if all paths are now failed... "
    flushmpaths 1
  fi
  if test $found -gt 0 ; then
    /sbin/udevadm trigger --sysname-match=sd*
    udevadm_settle
    if [ -x "$MULTIPATH" ] ; then
      echo "Trying to discover new multipath mappings for newly discovered devices... "
      $MULTIPATH | grep "create:" 2> /dev/null
    fi
  fi 
fi

echo "$found new or changed device(s) found.          "
if test ! -z "$FOUNDDEVS" ; then
  printf "$FOUNDDEVS"
fi
echo "$updated remapped or resized device(s) found."
if test ! -z "$CHGDEVS" ; then
  printf "$CHGDEVS"
fi
echo "$rmvd device(s) removed.                 "
if test ! -z "$RMVDDEVS" ; then
  printf "$RMVDDEVS"
fi

# Local Variables:
# sh-basic-offset: 2
# End:


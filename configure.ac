AC_INIT(sg3_utils, 1.45, dgilbert@interlog.com)

AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AM_MAINTAINER_MODE
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
# AC_PROG_CXX
AC_PROG_INSTALL

# AM_PROG_AR is supported and needed since automake v1.12+
ifdef([AM_PROG_AR], [AM_PROG_AR], []) 
		
# Adding libtools to the build seems to bring in C++ environment
AC_PROG_LIBTOOL

# check for headers
AC_HEADER_STDC
AC_CHECK_HEADERS([byteswap.h], [], [], [])

# check for functions
AC_CHECK_FUNCS(getopt_long,
	       GETOPT_O_FILES='',
	       GETOPT_O_FILES='getopt_long.o')
AC_CHECK_FUNCS(posix_fadvise)
AC_CHECK_FUNCS(posix_memalign)
AC_CHECK_FUNCS(gettimeofday)
AC_CHECK_FUNCS(sysconf)
AC_CHECK_FUNCS(lseek64)
SAVED_LIBS=$LIBS
AC_SEARCH_LIBS([pthread_create], [pthread])
# AC_SEARCH_LIBS adds libraries at the start of $LIBS so remove $SAVED_LIBS
# from the end of $LIBS.
pthread_lib=${LIBS%${SAVED_LIBS}}
AC_CHECK_FUNCS([pthread_cancel pthread_kill])
LIBS=$SAVED_LIBS
AC_SUBST(PTHREAD_LIB, [$pthread_lib])

SAVED_LIBS=$LIBS
AC_SEARCH_LIBS([clock_gettime], [rt])
rt_lib=${LIBS%${SAVED_LIBS}}
AC_CHECK_FUNCS(clock_gettime)
LIBS=$SAVED_LIBS
AC_SUBST(RT_LIB, [$rt_lib])

AC_SUBST(GETOPT_O_FILES)


AC_CANONICAL_HOST

AC_DEFINE_UNQUOTED(SG_LIB_BUILD_HOST, "${host}", [sg3_utils Build Host])

check_for_linux_nvme_headers() {
	AC_CHECK_HEADERS([linux/nvme_ioctl.h], [AC_DEFINE_UNQUOTED(HAVE_NVME, 1, [Found NVMe])], [], [])
	AC_CHECK_HEADERS([linux/types.h linux/bsg.h linux/kdev_t.h], [], [],
		     [[#ifdef HAVE_LINUX_TYPES_H
		     # include <linux/types.h>
		     #endif
		     ]])
}

check_for_linux_sg_v4_hdr() {
	AC_EGREP_CPP(found,
		[ # include <scsi/sg.h>
		  #ifdef SG_IOSUBMIT
		   found
		  #endif
		],
		[AC_DEFINE_UNQUOTED(HAVE_LINUX_SG_V4_HDR, 1, [Have Linux sg v4 header]) ])

}

case "${host}" in
	*-*-android*)
		AC_DEFINE_UNQUOTED(SG_LIB_ANDROID, 1, [sg3_utils on android])
		AC_DEFINE_UNQUOTED(SG_LIB_LINUX, 1, [sg3_utils on linux])
		check_for_linux_sg_v4_hdr
		check_for_linux_nvme_headers;;
        *-*-freebsd*|*-*-kfreebsd*-gnu*)
		AC_DEFINE_UNQUOTED(SG_LIB_FREEBSD, 1, [sg3_utils on FreeBSD])
		AC_DEFINE_UNQUOTED(HAVE_NVME, 1, [Found NVMe])
                LIBS="$LIBS -lcam";;
        *-*-solaris*)
		AC_DEFINE_UNQUOTED(SG_LIB_SOLARIS, 1, [sg3_utils on Solaris]);;
        *-*-osf*)
		AC_DEFINE_UNQUOTED(SG_LIB_OSF1, 1, [sg3_utils on Tru64 UNIX]);;
        *-*-cygwin*)
		AC_DEFINE_UNQUOTED(SG_LIB_WIN32, 1, [sg3_utils on Win32])
		# AC_CHECK_HEADERS([nvme.h], [AC_DEFINE_UNQUOTED(HAVE_NVME, 1, [Found NVMe])], [], [])
		AC_DEFINE_UNQUOTED(HAVE_NVME, 1, [Found NVMe])
                CFLAGS="$CFLAGS -Wno-char-subscripts";;
        *-*-mingw*)
		AC_DEFINE_UNQUOTED(SG_LIB_WIN32, 1, [sg3_utils on Win32])
		AC_DEFINE_UNQUOTED(SG_LIB_MINGW, 1, [also MinGW environment])
		# AC_CHECK_HEADERS([nvme.h], [AC_DEFINE_UNQUOTED(HAVE_NVME, 1, [Found NVMe])], [], [])
		AC_DEFINE_UNQUOTED(HAVE_NVME, 1, [Found NVMe])
                CFLAGS="$CFLAGS -D__USE_MINGW_ANSI_STDIO";;
        *-*-linux-gnu* | *-*-linux* | *)
                AC_DEFINE_UNQUOTED(SG_LIB_LINUX, 1, [sg3_utils on linux])
		check_for_linux_sg_v4_hdr
                check_for_linux_nvme_headers;;
esac

# Define platform-specific symbol.
AM_CONDITIONAL(OS_FREEBSD, [echo $host_os | grep 'freebsd' > /dev/null])
AM_CONDITIONAL(OS_LINUX, [echo $host_os | grep '^linux' > /dev/null])
AM_CONDITIONAL(OS_OSF, [echo $host_os | grep '^osf' > /dev/null])
AM_CONDITIONAL(OS_SOLARIS, [echo $host_os | grep '^solaris' > /dev/null])
AM_CONDITIONAL(OS_WIN32_MINGW, [echo $host_os | grep '^mingw' > /dev/null])
AM_CONDITIONAL(OS_WIN32_CYGWIN, [echo $host_os | grep '^cygwin' > /dev/null])
AM_CONDITIONAL(OS_ANDROID, [echo $host_os | grep 'android' > /dev/null])

AC_ARG_ENABLE([debug],
	      [  --enable-debug    Turn on debugging],
	      [case "${enableval}" in
		  yes) debug=true ;;
		  no)  debug=false ;;
		  *) AC_MSG_ERROR([bad value ${enableval} for --enable-debug]) ;;
	       esac],[debug=false])
AM_CONDITIONAL([DEBUG], [test x$debug = xtrue])

AC_ARG_ENABLE([linuxbsg],
  AC_HELP_STRING([--disable-linuxbsg], [option ignored, this is placeholder]),
  [AC_DEFINE_UNQUOTED(IGNORE_LINUX_BSG, 1, [option ignored], )], [])

AC_ARG_ENABLE([win32-spt-direct],
  AC_HELP_STRING([--enable-win32-spt-direct], [enable Win32 SPT Direct]),
  AC_DEFINE_UNQUOTED(WIN32_SPT_DIRECT, 1, [enable Win32 SPT Direct], )
)

AC_ARG_ENABLE([scsistrings],
  [AS_HELP_STRING([--disable-scsistrings],
		  [Disable full SCSI sense strings and NVMe status strings])],
  [], [AC_DEFINE_UNQUOTED(SG_SCSI_STRINGS, 1, [full SCSI sense strings and NVMe status strings], )])

AC_ARG_ENABLE([nvme-supp],
  AC_HELP_STRING([--disable-nvme-supp], [remove all or most NVMe code]),
  [AC_DEFINE_UNQUOTED(IGNORE_NVME, 1, [compile out NVMe support], )], [])

AC_ARG_ENABLE([fast-lebe],
  AC_HELP_STRING([--disable-fast-lebe], [use generic little-endian/big-endian code instead]),
  [AC_DEFINE_UNQUOTED(IGNORE_FAST_LEBE, 1, [use generic little-endian/big-endian instead], )], [])

AC_ARG_ENABLE([linux-sgv4],
  AC_HELP_STRING([--disable-linux-sgv4], [for Linux sg driver avoid v4 interface even if available]),
  [AC_DEFINE_UNQUOTED(IGNORE_LINUX_SGV4, 1, [even if Linux sg v4 available, use v3 instead], )], [])


AC_OUTPUT(Makefile include/Makefile lib/Makefile src/Makefile doc/Makefile scripts/Makefile)


# Borrowed from smartmontools configure.ac
# Note: Use `...` here as some shells do not properly parse '$(... case $x in X) ...)'
info=`
  echo "-----------------------------------------------------------------------------"
  echo "${PACKAGE}-${VERSION} configuration:"
  echo "host operating system:  $host"
  echo "default C compiler:     $CC"

  case "$host_os" in
    mingw*)
      echo "application manifest:   ${os_win32_manifest:-built-in}"
      echo "resource compiler:      $WINDRES"
      echo "message compiler:       $WINDMC"
      echo "NSIS compiler:          $MAKENSIS"
      ;;

    *)
      echo "binary install path:    \`eval eval eval echo $bindir\`"
      echo "scripts install path:   \`eval eval eval echo $bindir\`"
      echo "man page install path:  \`eval eval eval echo $mandir\`"
      ;;
  esac
  echo "-----------------------------------------------------------------------------"
`

AC_MSG_NOTICE([
$info
])


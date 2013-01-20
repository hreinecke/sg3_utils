AC_INIT(sg3_utils, 1.36, dgilbert@interlog.com)

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
# AC_PROG_CXX
AC_PROG_INSTALL
		
# Adding libtools to the build seems to bring in C++ environment
AC_PROG_LIBTOOL

# check for headers
AC_HEADER_STDC
AC_CHECK_HEADERS([linux/types.h linux/bsg.h linux/kdev_t.h], [], [],
     [[#ifdef HAVE_LINUX_TYPES_H
     # include <linux/types.h>
     #endif
     ]])

# check for functions
AC_CHECK_FUNCS(getopt_long,
	       GETOPT_O_FILES='',
	       GETOPT_O_FILES='getopt_long.o')
AC_CHECK_FUNCS(posix_fadvise)
AC_CHECK_FUNCS(lseek64)
AC_SUBST(GETOPT_O_FILES)

AC_CANONICAL_HOST

AC_DEFINE_UNQUOTED(SG_LIB_BUILD_HOST, "${host}", [sg3_utils Build Host])

case "${host}" in
        *-*-linux-gnu*)
		AC_DEFINE_UNQUOTED(SG_LIB_LINUX, 1, [sg3_utils on linux])
                AC_SUBST([os_libs], ['']) ;;
        *-*-linux*)
		AC_DEFINE_UNQUOTED(SG_LIB_LINUX, 1, [sg3_utils on linux])
                AC_SUBST([os_libs], ['']) ;;
        *-*-freebsd*|*-*-kfreebsd*-gnu*)
		AC_DEFINE_UNQUOTED(SG_LIB_FREEBSD, 1, [sg3_utils on FreeBSD])
                AC_SUBST([os_libs], ['-lcam']);;
        *-*-solaris*)
		AC_DEFINE_UNQUOTED(SG_LIB_SOLARIS, 1, [sg3_utils on Solaris])
                AC_SUBST([os_libs], ['']);;
        *-*-osf*)
		AC_DEFINE_UNQUOTED(SG_LIB_OSF1, 1, [sg3_utils on Tru64 UNIX])
                AC_SUBST([os_libs], ['']) ;;
        *-*-cygwin*)
		AC_DEFINE_UNQUOTED(SG_LIB_WIN32, 1, [sg3_utils on Win32])
                AC_SUBST([os_libs], ['']) ;;
        *-*-mingw*)
		AC_DEFINE_UNQUOTED(SG_LIB_WIN32, 1, [sg3_utils on Win32])
		AC_DEFINE_UNQUOTED(SG_LIB_MINGW, 1, [also MinGW environment])
                AC_SUBST([os_libs], ['']) ;;
        *)
		AC_DEFINE_UNQUOTED(SG_LIB_LINUX, 1, [assume sg3_utils on linux])
                AC_SUBST([os_libs], ['']) ;;
esac

# Define platform-specific symbol.
AM_CONDITIONAL(OS_FREEBSD, [echo $host_os | grep 'freebsd' > /dev/null])
AM_CONDITIONAL(OS_LINUX, [echo $host_os | grep '^linux' > /dev/null])
AM_CONDITIONAL(OS_OSF, [echo $host_os | grep '^osf' > /dev/null])
AM_CONDITIONAL(OS_SOLARIS, [echo $host_os | grep '^solaris' > /dev/null])
AM_CONDITIONAL(OS_WIN32_MINGW, [echo $host_os | grep '^mingw' > /dev/null])
AM_CONDITIONAL(OS_WIN32_CYGWIN, [echo $host_os | grep '^cygwin' > /dev/null])

AC_ARG_ENABLE([linuxbsg],
  AC_HELP_STRING([--disable-linuxbsg], [ignore linux bsg (sgv4) if present]),
  [AC_DEFINE_UNQUOTED(IGNORE_LINUX_BSG, 1, [ignore linux bsg], )], [])

AC_ARG_ENABLE([win32-spt-direct],
  AC_HELP_STRING([--enable-win32-spt-direct], [enable Win32 SPT Direct]),
  AC_DEFINE_UNQUOTED(WIN32_SPT_DIRECT, 1, [enable Win32 SPT Direct], )
)

AC_ARG_ENABLE([scsistrings],
  [AS_HELP_STRING([--disable-scsistrings],
		  [Disable full SCSI sense strings])],
  [], [AC_DEFINE_UNQUOTED(SG_SCSI_STRINGS, 1, [full SCSI sense strings], )])

AC_OUTPUT(Makefile include/Makefile lib/Makefile src/Makefile doc/Makefile)

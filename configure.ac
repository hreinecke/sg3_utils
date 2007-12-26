AC_INIT(sg3_utils, 1.26, dgilbert@interlog.com)

AM_INIT_AUTOMAKE
AM_CONFIG_HEADER(config.h)

AC_PROG_CC
# AC_PROG_CXX
AC_PROG_INSTALL
		
AC_PROG_LIBTOOL

# check for headers
AC_HEADER_STDC
AC_CHECK_FUNCS(getopt_long,
	       GETOPT_O_FILES='',
	       GETOPT_O_FILES='getopt_long.o')
AC_SUBST(GETOPT_O_FILES)

AC_CANONICAL_HOST

AC_DEFINE_UNQUOTED(SG3_UTILS_BUILD_HOST, "${host}", [sg3_utils Build Host])

case "${host}" in
        *-*-linux-gnu*)
		AC_DEFINE_UNQUOTED(SG3_UTILS_LINUX, 1, [sg3_utils on linux])
                AC_SUBST([os_libs], ['']) ;;
        *-*-linux*)
		AC_DEFINE_UNQUOTED(SG3_UTILS_LINUX, 1, [sg3_utils on linux])
                AC_SUBST([os_libs], ['']) ;;
        *-*-freebsd*)
		AC_DEFINE_UNQUOTED(SG3_UTILS_FREEBSD, 1, [sg3_utils on FreeBSD])
                AC_SUBST([os_libs], ['-lcam']);;
        *-*-solaris*)
		AC_DEFINE_UNQUOTED(SG3_UTILS_SOLARIS, 1, [sg3_utils on Solaris])
                AC_SUBST([os_libs], ['']);;
        *-*-osf*)
		AC_DEFINE_UNQUOTED(SG3_UTILS_OSF1, 1, [sg3_utils on Tru64 UNIX])
                AC_SUBST([os_libs], ['']) ;;
        *-*-cygwin*)
		AC_DEFINE_UNQUOTED(SG3_UTILS_WIN32, 1, [sg3_utils on Win32])
                AC_SUBST([os_libs], ['']) ;;
        *-*-mingw*)
		AC_DEFINE_UNQUOTED(SG3_UTILS_WIN32, 1, [sg3_utils on Win32])
		AC_DEFINE_UNQUOTED(SG3_UTILS_MINGW, 1, [also MinGW environment])
                AC_SUBST([os_libs], ['']) ;;
        *)
		AC_DEFINE_UNQUOTED(SG3_UTILS_LINUX, 1, [assume sg3_utils on linux])
                AC_SUBST([os_libs], ['']) ;;
esac

# Define platform-specific symbol.
AM_CONDITIONAL(OS_FREEBSD, [echo $host_os | grep '^freebsd' > /dev/null])
AM_CONDITIONAL(OS_LINUX, [echo $host_os | grep '^linux' > /dev/null])
AM_CONDITIONAL(OS_OSF, [echo $host_os | grep '^osf' > /dev/null])
AM_CONDITIONAL(OS_SOLARIS, [echo $host_os | grep '^solaris' > /dev/null])
AM_CONDITIONAL(OS_WIN32_MINGW, [echo $host_os | grep '^mingw' > /dev/null])
AM_CONDITIONAL(OS_WIN32_CYGWIN, [echo $host_os | grep '^cygwin' > /dev/null])


AC_OUTPUT(Makefile include/Makefile lib/Makefile src/Makefile doc/Makefile)

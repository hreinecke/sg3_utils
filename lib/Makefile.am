libsgutils2_la_SOURCES = \
	sg_lib.c \
	sg_lib_data.c \
	sg_cmds_basic.c \
	sg_cmds_basic2.c \
	sg_cmds_extra.c \
	sg_cmds_mmc.c \
	sg_pt_common.c 

if OS_LINUX
libsgutils2_la_SOURCES += \
	sg_pt_linux.c \
	sg_io_linux.c
endif

if OS_WIN32_MINGW
libsgutils2_la_SOURCES += sg_pt_win32.c
endif

if OS_WIN32_CYGWIN
libsgutils2_la_SOURCES += sg_pt_win32.c
endif

if OS_FREEBSD
libsgutils2_la_SOURCES += sg_pt_freebsd.c
endif

if OS_SOLARIS
libsgutils2_la_SOURCES += sg_pt_solaris.c
endif

if OS_OSF
libsgutils2_la_SOURCES += sg_pt_osf1.c
endif

# For C++/clang testing
## CC = gcc
## CC = g++
## CC = clang
## CC = clang++

# -std=<s> can be c99, c11, gnu11, etc. Default is gnu89 (gnu90 is the same)
# -Wall is no longer all warnings. Add -W (since renamed to -Wextra) for more
AM_CPPFLAGS = -iquote ${top_srcdir}/include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
AM_CFLAGS = -Wall -W
# AM_CFLAGS = -Wall -W -pedantic -std=c11
# AM_CFLAGS = -Wall -W -pedantic -std=c11 --analyze
# AM_CFLAGS = -Wall -W -pedantic -std=c++14

lib_LTLIBRARIES = libsgutils2.la

libsgutils2_la_LDFLAGS = -version-info 2:0:0 -no-undefined

libsgutils2_la_LIBADD = @GETOPT_O_FILES@ @os_libs@
libsgutils2_la_DEPENDENCIES = @GETOPT_O_FILES@



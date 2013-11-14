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
## CC = g++ -std=c++11
## CC = g++
## CC = clang
## CC = clang++

# -std=<s> can be c99, c11, gnu11, etc. Default is gnu89 (gnu90 is the same)
AM_CFLAGS = -I ../include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -W
# AM_CFLAGS = -I ../include -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -Wall -W -pedantic -std=c11

lib_LTLIBRARIES = libsgutils2.la

libsgutils2_la_LDFLAGS = -version-info 2:0:0

libsgutils2_la_LIBADD = @GETOPT_O_FILES@ @os_libs@
libsgutils2_la_DEPENDENCIES = @GETOPT_O_FILES@



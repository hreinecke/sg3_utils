SHELL = /bin/sh

PREFIX=/usr/local
INSTDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/man

EXECS = sg_iovec_tst sg_sense_test sg_queue_tst bsg_queue_tst sg_chk_asc \
	sg_tst_nvme sg_tst_ioctl sg_tst_bidi tst_sg_lib sgs_dd sg_tst_excl \
	sg_tst_excl2 sg_tst_excl3 sg_tst_context sg_tst_async sgh_dd
	
EXTRAS =

BSG_EXTRAS =


MAN_PGS = 
MAN_PREF = man8

LARGE_FILE_FLAGS = -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

# For C++/clang testing
## CC = gcc
## CXX = g++
## CC = clang
## CXX = clang++

LD = $(CXX)
CXXLD = $(CXX)

CPPFLAGS = -iquote ../include -iquote .. -D_REENTRANT $(LARGE_FILE_FLAGS) -DHAVE_CONFIG_H -DHAVE_NVME
CXXFLAGS = -std=c++17 -pthread -ggdb -O2 -W -Wall -iquote ../include -D_REENTRANT $(LARGE_FILE_FLAGS)
# CPPFLAGS = -iquote ../include -iquote .. -D_REENTRANT $(LARGE_FILE_FLAGS) -DHAVE_CONFIG_H -DHAVE_NVME -DDEBUG
# CFLAGS = -g -O2 -W -Wall 
CFLAGS = -ggdb -O2 -W -Wall -DDEBUG
# CFLAGS = -g -O2 -Wall -DSG_KERNEL_INCLUDES
# CFLAGS = -g -O2 -Wall -pedantic 
# CFLAGS = -Wall -W -pedantic -std=c11 --analyze
# CFLAGS = -Wall -W -pedantic -std=c++14 -fPIC

LDFLAGS =

LIBFILESOLD = ../lib/sg_lib.o ../lib/sg_lib_data.o ../lib/sg_io_linux.o
LIBFILESNEW = ../lib/sg_pt_linux_nvme.o ../lib/sg_lib.o ../lib/sg_lib_data.o \
		../lib/sg_pt_linux.o ../lib/sg_io_linux.o \
		../lib/sg_pt_common.o  ../lib/sg_cmds_basic.o \
		../lib/sg_cmds_basic2.o

all: $(EXECS)

extras: $(EXTRAS)

bsg: $(BSG_EXTRAS)


depend dep:
	for i in *.c; do $(CC) $(CPPFLAGS) $(INCLUDES) $(CFLAGS) -M $$i; \
	done > .depend

clean:
	/bin/rm -f *.o $(EXECS) $(EXTRAS) $(BSG_EXTRAS) core .depend

sg_iovec_tst: sg_iovec_tst.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg_sense_test: sg_sense_test.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg_queue_tst: sg_queue_tst.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^ 

bsg_queue_tst: bsg_queue_tst.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^ 

sg_tst_ioctl: sg_tst_ioctl.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^ 

# building sg_chk_asc depends on a prior successful make in ../lib
sg_chk_asc: sg_chk_asc.o ../lib/sg_lib.o ../lib/sg_lib_data.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_tst_nvme: sg_tst_nvme.o $(LIBFILESNEW)
	$(LD) -o $@ $(LDFLAGS) $^ 

tst_sg_lib: tst_sg_lib.o ../lib/sg_lib.o ../lib/sg_lib_data.o
	$(LD) -o $@ $(LDFLAGS) $^

sgs_dd: sgs_dd.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^ 

sg_tst_bidi: sg_tst_bidi.o $(LIBFILESNEW)
	$(LD) -o $@ $(LDFLAGS) $^ 

sg_tst_excl: sg_tst_excl.o $(LIBFILESNEW)
	$(CXXLD) -o $@ $(LDFLAGS) -pthread $^

sg_tst_excl2: sg_tst_excl2.o $(LIBFILESNEW)
	$(CXXLD) -o $@ $(LDFLAGS) -pthread $^

sg_tst_excl3: sg_tst_excl3.o $(LIBFILESNEW)
	$(CXXLD) -o $@ $(LDFLAGS) -pthread $^

sg_tst_context: sg_tst_context.o $(LIBFILESNEW)
	$(CXXLD) -o $@ $(LDFLAGS) -pthread $^

sg_tst_async: sg_tst_async.o $(LIBFILESNEW)
	$(CXXLD) -o $@ $(LDFLAGS) -pthread $^

sgh_dd: sgh_dd.o $(LIBFILESNEW)
	$(CXXLD) -o $@ $(LDFLAGS) -pthread -latomic $^


install: $(EXECS)
	install -d $(INSTDIR)
	for name in $^; \
	 do install -s -o root -g root -m 755 $$name $(INSTDIR); \
	done
	install -d $(MANDIR)/$(MAN_PREF)
	for mp in $(MAN_PGS); \
	 do install -o root -g root -m 644 $$mp $(MANDIR)/$(MAN_PREF); \
	 gzip -9f $(MANDIR)/$(MAN_PREF)/$$mp; \
	done

uninstall:
	dists="$(EXECS)"; \
	for name in $$dists; do \
	 rm -f $(INSTDIR)/$$name; \
	done
	for mp in $(MAN_PGS); do \
	 rm -f $(MANDIR)/$(MAN_PREF)/$$mp.gz; \
	done

# Linux uses GNU make and FreeBSD uses Berkely make. The following lines
# only work in Linux. Possible solutions in FreeBSD:
#    a) use 'gmake'; b) comment out the next 3 lines, starting with 'ifeq'
#        c) build with 'make -f Makefile.freebsd'
# In Linux one can install bmake (but that won't help here).
ifeq (.depend,$(wildcard .depend))
include .depend
endif

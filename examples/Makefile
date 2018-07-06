SHELL = /bin/sh

PREFIX=/usr/local
INSTDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/man

# In Linux the default C compiler is GCC while in FreeBSD (since release 10 ?)
# the default C compiler is clang. Swap the comment marks (lines starting
# with '#') on the next 4 (non-blank) lines.
CC = gcc
# CC = clang

LD = gcc
# LD = clang


EXECS = sg_simple1 sg_simple2 sg_simple3 sg_simple4 sg_simple16 \
	scsi_inquiry sg_excl sg_simple5 sg__sat_identify \
	sg__sat_phy_event sg__sat_set_features sg_sat_chk_power \
	sg_sat_smart_rd_data

EXTRAS = sgq_dd

BSG_EXTRAS =


MAN_PGS = 
MAN_PREF = man8

LARGE_FILE_FLAGS = -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

CPPFLAGS = -iquote ../include -D_REENTRANT $(LARGE_FILE_FLAGS)
# CPPFLAGS = -iquote ../include -D_REENTRANT $(LARGE_FILE_FLAGS) -DDEBUG

CFLAGS = -g -O2 -W -Wall
# CFLAGS = -g -O2 -Wall -DSG_KERNEL_INCLUDES
# CFLAGS = -g -O2 -Wall -pedantic

LDFLAGS =

LIBFILESOLD = ../lib/sg_lib.o ../lib/sg_lib_data.o ../lib/sg_io_linux.o
LIBFILESNEW = ../lib/sg_lib.o ../lib/sg_lib_data.o ../lib/sg_pt_common.o ../lib/sg_pt_linux.o ../lib/sg_pt_linux_nvme.o

all: $(EXECS)

extras: $(EXTRAS)

bsg: $(BSG_EXTRAS)


depend dep:
	for i in *.c; do $(CC) $(INCLUDES) $(CFLAGS) -M $$i; \
	done > .depend

clean:
	/bin/rm -f *.o $(EXECS) $(EXTRAS) $(BSG_EXTRAS) core .depend

sg_simple1: sg_simple1.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple2: sg_simple2.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple3: sg_simple3.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple4: sg_simple4.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple16: sg_simple16.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

scsi_inquiry: scsi_inquiry.o
	$(LD) -o $@ $(LDFLAGS) $^ 

sg_excl: sg_excl.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple5: sg_simple5.o $(LIBFILESNEW)
	$(LD) -o $@ $(LDFLAGS) $^

sg__sat_identify: sg__sat_identify.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg__sat_phy_event: sg__sat_phy_event.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg__sat_set_features: sg__sat_set_features.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg_sat_chk_power: sg_sat_chk_power.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg_sat_smart_rd_data: sg_sat_smart_rd_data.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sgq_dd: sgq_dd.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^ 

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

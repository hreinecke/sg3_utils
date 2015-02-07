SHELL = /bin/sh

PREFIX=/usr/local
INSTDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/man

CC = gcc
LD = gcc

EXECS = sg_simple1 sg_simple2 sg_simple3 sg_simple4 sg_simple16 \
	sg_iovec_tst scsi_inquiry sg_excl sg_sense_test sg_simple5 \
	sg__sat_identify sg__sat_phy_event sg__sat_set_features \
	sg_sat_chk_power sg_sat_smart_rd_data

EXTRAS = sg_queue_tst sgq_dd

BSG_EXTRAS = bsg_queue_tst


MAN_PGS = 
MAN_PREF = man8

LARGE_FILE_FLAGS = -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

CFLAGS = -g -O2 -W -Wall -iquote ../include -D_REENTRANT $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -Wall -iquote ../include -D_REENTRANT -DSG_KERNEL_INCLUDES $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -Wall -pedantic -iquote ../include -D_REENTRANT $(LARGE_FILE_FLAGS)

LDFLAGS =

LIBFILESOLD = ../lib/sg_lib.o ../lib/sg_lib_data.o ../lib/sg_io_linux.o
LIBFILESNEW = ../lib/sg_lib.o ../lib/sg_lib_data.o ../lib/sg_pt_linux.o

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

sg_iovec_tst: sg_iovec_tst.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

scsi_inquiry: scsi_inquiry.o
	$(LD) -o $@ $(LDFLAGS) $^ 

sg_excl: sg_excl.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^

sg_sense_test: sg_sense_test.o $(LIBFILESOLD)
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

sg_queue_tst: sg_queue_tst.o $(LIBFILESOLD)
	$(LD) -o $@ $(LDFLAGS) $^ 

bsg_queue_tst: bsg_queue_tst.o $(LIBFILESOLD)
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

ifeq (.depend,$(wildcard .depend))
include .depend
endif

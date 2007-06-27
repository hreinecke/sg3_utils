SHELL = /bin/sh

PREFIX=/usr/local
INSTDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/man

CC = gcc
LD = gcc

EXECS = sg_simple1 sg_simple2 sg_simple3 sg_simple4 sg_simple16 \
	sg_iovec_tst scsi_inquiry sg_excl sg_sense_test sg_simple5 \
	sg__sat_identify sg_sat_chk_power sg_sat_smart_rd_data \
	sg_sat_set_features sg_sat_phy_event

# EXECS = sg_simple1 sg_simple2 sg_simple3 sg_simple4 sg_simple16 \
# 	  sg_simple_aio sg_iovec_tst scsi_inquiry sg_excl

MAN_PGS = 
MAN_PREF = man8

LARGE_FILE_FLAGS = -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

CFLAGS = -g -O2 -W -Wall -D_REENTRANT $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -Wall -D_REENTRANT -DSG_KERNEL_INCLUDES $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -Wall -pedantic -D_REENTRANT $(LARGE_FILE_FLAGS)

LDFLAGS =

all: $(EXECS)

depend dep:
	for i in *.c; do $(CC) $(INCLUDES) $(CFLAGS) -M $$i; \
	done > .depend

clean:
	/bin/rm -f *.o $(EXECS) core .depend

sg_simple1: sg_simple1.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple2: sg_simple2.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple3: sg_simple3.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple4: sg_simple4.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple16: sg_simple16.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple_aio: sg_simple_aio.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^ -l aio

sg_iovec_tst: sg_iovec_tst.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

scsi_inquiry: scsi_inquiry.o
	$(LD) -o $@ $(LDFLAGS) $^ 

sg_excl: sg_excl.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_sense_test: sg_sense_test.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple5: sg_simple5.o ../sg_lib.o ../sg_pt_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg__sat_identify: sg__sat_identify.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_sat_chk_power: sg_sat_chk_power.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_sat_smart_rd_data: sg_sat_smart_rd_data.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_sat_set_features: sg_sat_set_features.o ../sg_lib.o ../sg_io_linux.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_sat_phy_event: sg_sat_phy_event.o ../sg_lib.o ../sg_io_linux.o
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

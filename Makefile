SHELL = /bin/sh

PREFIX=/usr/local
INSTDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/man

CC = gcc
LD = gcc

EXECS = sg_simple1 sg_simple2 sg_simple3 sg_dd sg_debug \
	sg_scan scsi_inquiry sg_rbuf sginfo sg_readcap \
	sgp_dd sg_map sg_turs isosize sg_inq sg_test_rwbuf \
	scsi_devfs_scan sg_start

COMMON = sg_scan scsi_inquiry sginfo sg_readcap isosize sg_start

MAN_PGS = sg_dd.8 sgp_dd.8 sg_map.8 sg_rbuf.8 isosize.8
MAN_PREF = man8

CFLAGS = -g -O2 -Wall -D_REENTRANT
# CFLAGS = -g -O2 -Wall -D_REENTRANT -DSG_KERNEL_INCLUDES
# CFLAGS = -g -O2 -Wall -pedantic -D_REENTRANT

LDFLAGS =

all: $(EXECS)

common: $(COMMON)

depend dep:
	for i in *.c; do $(CC) $(INCLUDES) $(CFLAGS) -M $$i; \
	done > .depend

clean:
	/bin/rm -f *.o $(EXECS) core .depend

sg_simple1: sg_simple1.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple2: sg_simple2.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_simple3: sg_simple3.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_dd: sg_dd.o sg_err.o llseek.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_debug: sg_debug.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_scan: sg_scan.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^ 

scsi_inquiry: scsi_inquiry.o
	$(LD) -o $@ $(LDFLAGS) $^ 

sginfo: sginfo.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_start: sg_start.o
	$(LD) -o $@ $(LDFLAGS) $^ 

sg_rbuf: sg_rbuf.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_readcap: sg_readcap.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sgp_dd: sgp_dd.o sg_err.o llseek.o
	$(LD) -o $@ $(LDFLAGS) $^ -lpthread

sg_map: sg_map.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_turs: sg_turs.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_test_rwbuf: sg_test_rwbuf.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

isosize: isosize.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_inq: sg_inq.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

scsi_devfs_scan: scsi_devfs_scan.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

install: $(EXECS) $(COMMON)
	install -d $(INSTDIR)
	for name in $^; \
	 do install -s -o root -g root -m 755 $$name $(INSTDIR); \
	done
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

SHELL = /bin/sh

PREFIX=/usr/local
INSTDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/man

CC = gcc
LD = gcc

EXECS = sg_dd sgp_dd sgm_dd sg_read sg_map sg_scan sg_rbuf \
	sginfo sg_readcap sg_turs sg_inq sg_test_rwbuf \
	sg_start sg_reset sg_modes sg_logs sg_senddiag sg_opcodes \
	sg_persist sg_write_long sg_read_long

MAN_PGS = sg_dd.8 sgp_dd.8 sgm_dd.8 sg_read.8 sg_map.8 sg_scan.8 sg_rbuf.8 \
	sginfo.8 sg_readcap.8 sg_turs.8 sg_inq.8 sg_test_rwbuf.8 \
	sg_start.8 sg_reset.8 sg_modes.8 sg_logs.8 sg_senddiag.8 \
	sg_opcodes.8 sg_persist.8 sg_write_long.8 sg_read_long.8
MAN_PREF = man8

LARGE_FILE_FLAGS = -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

CFLAGS = -g -O2 -Wall -W -D_REENTRANT $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -W -D_REENTRANT -DSG_KERNEL_INCLUDES $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -Wall -pedantic -std=c99 -D_REENTRANT $(LARGE_FILE_FLAGS)

LDFLAGS =

all: $(EXECS)

depend dep:
	for i in *.c; do $(CC) $(INCLUDES) $(CFLAGS) -M $$i; \
	done > .depend

clean:
	/bin/rm -f *.o $(EXECS) core* .depend

sg_dd: sg_dd.o sg_err.o llseek.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_scan: sg_scan.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^ 

sginfo: sginfo.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_start: sg_start.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^ 

sg_rbuf: sg_rbuf.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_readcap: sg_readcap.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sgp_dd: sgp_dd.o sg_err.o llseek.o
	$(LD) -o $@ $(LDFLAGS) $^ -lpthread

sgm_dd: sgm_dd.o sg_err.o llseek.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_map: sg_map.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_turs: sg_turs.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_test_rwbuf: sg_test_rwbuf.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_inq: sg_inq.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_read: sg_read.o sg_err.o llseek.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_reset: sg_reset.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_modes: sg_modes.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_logs: sg_logs.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_senddiag: sg_senddiag.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_opcodes: sg_opcodes.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_persist: sg_persist.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_write_long: sg_write_long.o sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_read_long: sg_read_long.o sg_err.o
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

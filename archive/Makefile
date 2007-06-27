SHELL = /bin/sh

INSTDIR=/usr/local/bin
MANDIR=/usr/local/man

CC = gcc
LD = gcc

EXECS = sgq_dd sg_poll sg_reset sg_bus_xfer sg_hold isosize

COMMON = isosize

MAN_PGS = isosize.8
MAN_PREF = man8

CFLAGS = -g -O2 -Wall -D_REENTRANT
# CFLAGS = -g -O2 -Wall -pedantic -D_REENTRANT

LDFLAGS =

all: $(EXECS)

common: $(COMMON)

depend dep:
	for i in *.c; do $(CC) $(INCLUDES) $(CFLAGS) -M $$i; \
	done > .depend

clean:
	/bin/rm -f *.o $(EXECS) core .depend

sg_poll: sg_poll.o ../sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sgq_dd: sgq_dd.o ../sg_err.o ../llseek.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_reset: sg_reset.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_bus_xfer: sg_bus_xfer.o ../sg_err.o
	$(LD) -o $@ $(LDFLAGS) $^

sg_hold: sg_hold.o
	$(LD) -o $@ $(LDFLAGS) $^

isosize: isosize.o
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

SHELL = /bin/sh

PREFIX=/usr
INSTDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/share/man

CC = gcc
LD = gcc

EXECS = hxascdmp
EXTRA_EXECS = hxascdmp sg_chk_asc tst_sg_lib

MAN_PGS = hxascdmp.1
MAN_PREF = man1

CFLAGS = -g -O2 -W -Wall -I ../include
# CFLAGS = -g -O2 -W -I ../include -pedantic -std=c99

LDFLAGS =

all: $(EXECS)

depend dep:
	for i in *.c; do $(CC) $(INCLUDES) $(CFLAGS) -M $$i; \
	done > .depend

clean:
	/bin/rm -f *.o $(EXTRA_EXECS) core .depend

hxascdmp: hxascdmp.o
	$(LD) -o $@ $(LDFLAGS) $^

# building sg_chk_asc depends on a prior successful make in ../lib
sg_chk_asc: sg_chk_asc.o ../lib/sg_lib.o ../lib/sg_lib_data.o
	$(LD) -o $@ $(LDFLAGS) $^

tst_sg_lib: tst_sg_lib.o ../lib/sg_lib.o ../lib/sg_lib_data.o
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

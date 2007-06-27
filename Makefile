SHELL = /bin/sh

PREFIX=/usr/local
LIBDIR=$(DESTDIR)/$(PREFIX)/lib
INSTDIR=$(DESTDIR)/$(PREFIX)/bin
MANDIR=$(DESTDIR)/$(PREFIX)/share/man
INCLUDEDIR=$(DESTDIR)/$(PREFIX)/include

CC = gcc
LD = gcc

EXECS = sg_dd sgp_dd sgm_dd sg_read sg_map sg_scan sg_rbuf \
  	sginfo sg_readcap sg_turs sg_inq sg_test_rwbuf \
 	sg_start sg_reset sg_modes sg_logs sg_senddiag sg_opcodes \
 	sg_persist sg_write_long sg_read_long sg_requests sg_ses \
	sg_verify sg_emc_trespass sg_luns sg_sync sg_prevent \
	sg_get_config sg_wr_mode sg_rtpg sg_reassign sg_format \
	sg_rmsn sg_ident sg_map26

MAN_PGS = sg_dd.8 sgp_dd.8 sgm_dd.8 sg_read.8 sg_map.8 sg_scan.8 sg_rbuf.8 \
	sginfo.8 sg_readcap.8 sg_turs.8 sg_inq.8 sg_test_rwbuf.8 \
	sg_start.8 sg_reset.8 sg_modes.8 sg_logs.8 sg_senddiag.8 \
	sg_opcodes.8 sg_persist.8 sg_write_long.8 sg_read_long.8 \
	sg_requests.8 sg_ses.8 sg_verify.8 sg_emc_trespass.8 \
	sg_luns.8 sg_sync.8 sg_prevent.8 sg_get_config.8 sg_wr_mode.8 \
	sg_rtpg.8 sg_reassign.8 sg_format.8 sg_rmsn.8 sg_ident.8 \
	sg_map26.8
MAN_PREF = man8

HEADERS = sg_lib.h sg_cmds.h


LARGE_FILE_FLAGS = -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64

# CFLAGS = -O2 -Wall -W $(LARGE_FILE_FLAGS)
CFLAGS = -g -O2 -Wall -W $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -W -DSG_KERNEL_INCLUDES $(LARGE_FILE_FLAGS)
# CFLAGS = -g -O2 -Wall -W -pedantic -std=c99 $(LARGE_FILE_FLAGS)

CFLAGS_PTHREADS = -D_REENTRANT

LDFLAGS = 
# LDFLAGS = -v -lm

LIB_VINFO = 1:0:0
# Perhaps should use "-release RELEASE" instead
# RELEASE = 1.1

all: $(EXECS)

depend dep:
	for i in *.c; do $(CC) $(INCLUDES) $(CFLAGS) -M $$i; \
	done > .depend

clean:
	/bin/rm -f *.o $(EXECS) core* .depend *.a *.la *.lo
	/bin/rm -rf .libs


sg_lib.lo: sg_lib.o
	libtool --mode=compile $(CC) -c sg_lib.c

sg_cmds.lo: sg_cmds.o
	libtool --mode=compile $(CC) -c sg_cmds.c

libsgutils.la: sg_lib.lo sg_cmds.lo
	libtool --mode=link $(LD) -o libsgutils.la sg_lib.lo sg_cmds.lo \
	-rpath $(LIBDIR) -version-info $(LIB_VINFO)

# libsgutils.la: sg_lib.lo sg_cmds.lo
#	libtool --mode=link $(LD) -o libsgutils.la sg_lib.lo sg_cmds.lo \
#	-rpath $(LIBDIR) -release $(RELEASE)

sg_inq: sg_inq.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^ 

sg_dd: sg_dd.o llseek.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_scan: sg_scan.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^ 

sginfo: sginfo.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_start: sg_start.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^ 

sg_rbuf: sg_rbuf.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_readcap: sg_readcap.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sgp_dd.o: sgp_dd.c
	$(CC) $(INCLUDES) $(CFLAGS) $(CFLAGS_PTHREADS) -c $<

sgp_dd: sgp_dd.o llseek.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^ -lpthread

sgm_dd: sgm_dd.o llseek.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_map: sg_map.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_turs: sg_turs.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_test_rwbuf: sg_test_rwbuf.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_read: sg_read.o llseek.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_reset: sg_reset.o
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_modes: sg_modes.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_logs: sg_logs.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_senddiag: sg_senddiag.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_opcodes: sg_opcodes.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_persist: sg_persist.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_write_long: sg_write_long.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_read_long: sg_read_long.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_requests: sg_requests.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_ses: sg_ses.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_verify: sg_verify.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_emc_trespass: sg_emc_trespass.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_luns: sg_luns.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_sync: sg_sync.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_prevent: sg_prevent.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_get_config: sg_get_config.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_wr_mode: sg_wr_mode.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_rtpg: sg_rtpg.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_reassign: sg_reassign.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_format: sg_format.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_rmsn: sg_rmsn.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_ident: sg_ident.o libsgutils.la
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

sg_map26: sg_map26.o
	libtool --mode=link $(LD) -o $@ $(LDFLAGS) $^

install: $(EXECS)
	install -d $(INSTDIR)
	install -d $(LIBDIR)
	libtool --mode=install install -c libsgutils.la $(LIBDIR)/libsgutils.la
	libtool --finish $(LIBDIR)
	for name in $^; \
	 do libtool --mode=install install -m 755 \
		$$name $(INSTDIR); \
	done
	install -d $(MANDIR)/$(MAN_PREF)
	for mp in $(MAN_PGS); \
	 do install -m 644 $$mp $(MANDIR)/$(MAN_PREF); \
	 gzip -9f $(MANDIR)/$(MAN_PREF)/$$mp; \
	done
	install -d $(INCLUDEDIR)/scsi
	for hdr in $(HEADERS); \
	 do install -m 644 $$hdr $(INCLUDEDIR)/scsi ; \
	done

uninstall:
	libtool --mode=uninstall rm -f $(LIBDIR)/libsgutils.la
	dists="$(EXECS)"; \
	for name in $$dists; do \
	 rm -f $(INSTDIR)/$$name; \
	done
	for mp in $(MAN_PGS); do \
	 rm -f $(MANDIR)/$(MAN_PREF)/$$mp.gz; \
	done
	for hdr in $(HEADERS); do \
	 rm -f $(INCLUDEDIR)/scsi/$$hdr ; \
	done

ifeq (.depend,$(wildcard .depend))
include .depend
endif

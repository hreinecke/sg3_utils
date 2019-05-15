
SUBDIRS = include \
	  lib \
	  src \
	  doc \
	  scripts

EXTRA_DIST=autogen.sh COVERAGE CREDITS

distclean-local:
	rm -rf autom4te.cache
	rm -f build-stamp configure-stamp
	rm -rf lib/.deps
	rm -rf src/.deps


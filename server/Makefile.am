# Makefile.am - SharedSecret project.
# Copyright (C) 2004 - Arvydas Juskaitis <arvydasj@users.sourceforge.net>

AM_CFLAGS = -DLOCALSTATEDIR=\"@localstatedir@\" \
-DSYSCONFDIR=\"@sysconfdir@\"

sbin_PROGRAMS = shsecd
man_MANS = shsecd.8 shsecd.conf.5

BUILT_SOURCES = conf_pars.h
AM_YFLAGS = -d

noinst_HEADERS = conf_defs.h shsecd.h 

shsecd_SOURCES = shsecd.c keydb.c dh.c peer.c sig.c asn1.c utils.c \
	conf_pars.y conf_scan.l 

shsecd_DEPENDENCIES = conf_defs.h shsecd.h 

sysconf_DATA = shsecd.conf

shsecd.conf: shsecd.conf.in
	sed -e 's,LOCALSTATEDIR,@localstatedir@,g' \
	    -e 's,SHSEC_GID,@SHSEC_GID@,g' \
	    -e 's,HOSTNAME_FQDN,@HOSTNAME_FQDN@,g' \
		shsecd.conf.in > shsecd.conf

EXTRA_DIST = ${MANS} shsecd.conf.in

CLEANFILES = shsecd.conf conf_pars.c conf_pars.h conf_scan.c *~ \#.\#


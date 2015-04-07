# Makefile.am - SharedSecret project.
# Copyright (C) 2004 - Arvydas Juskaitis <arvydasj@users.sourceforge.net>

AUTOMAKE_OPTIONS = foreign

SUBDIRS = server client include htdocs

EXTRA_DIST = AUTHORS BUGS COPYING ChangeLog INSTALL README TODO shsec.txt \
	cvs-make-dbg cvs-make-rel configure configure.in aclocal.m4 \
	config.guess config.sub missing mkinstalldirs depcomp install-sh

CLEANFILES = *~ \#.\#

install-data-hook:
	mkdir -p $(DESTDIR)@datadir@/doc/@PACKAGE@-@VERSION@
	cp AUTHORS BUGS COPYING ChangeLog INSTALL README TODO shsec.txt \
		$(DESTDIR)@datadir@/doc/@PACKAGE@-@VERSION@
	mkdir -p $(DESTDIR)@localstatedir@/run/@PACKAGE@
	chmod 0770 $(DESTDIR)@localstatedir@/run/@PACKAGE@
	-test `id -u` -eq 0 && \
		chgrp @SHSEC_GID@ $(DESTDIR)/@localstatedir@/run/@PACKAGE@

uninstall-hook:
	(cd @datadir@/doc/@PACKAGE@-@VERSION@; test $$? -eq 0 && rm -f *)
	-rmdir @datadir@/doc/@PACKAGE@-@VERSION@
	-rmdir @datadir@/doc
	-rmdir @datadir@
	(cd @localstatedir@/run/@PACKAGE@; test $$? -eq 0 && rm -f *)
	-rmdir @localstatedir@/run/@PACKAGE@
	-rmdir @localstatedir@/run
	-rmdir @localstatedir@
	-rmdir @mandir@/man1
	-rmdir @mandir@/man5
	-rmdir @mandir@/man8
	-rmdir @mandir@
	-rmdir @sysconfdir@
	-rmdir @bindir@
	-rmdir @sbindir@


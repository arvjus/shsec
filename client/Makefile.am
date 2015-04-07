# Makefile.am - SharedSecret project.
# Copyright (C) 2004 - Arvydas Juskaitis <arvydasj@users.sourceforge.net>

AM_CFLAGS = -DLOCALSTATEDIR=\"@localstatedir@\" 

bin_PROGRAMS = shsec 
man_MANS = shsec.1

noinst_HEADERS = shsec.h
shsec_SOURCES = shsec.c utils.c base64.c 

EXTRA_DIST = ${MANS} 

CLEANFILES = *~ \#.\#


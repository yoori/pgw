#  Check to see if we have our internal library libfreeradius-json
#  which in turn depends on json-c.
TARGETNAME	:=
-include $(top_builddir)/src/lib/json/all.mk
TARGET		:=

#  Add libfreeradius-json to the prereqs (so rlm_rest links to it)
ifneq "$(TARGETNAME)" ""
TGT_PREREQS	:= libfreeradius-json$(L)
endif

#  Check to see if we libfreeradius-curl, as that's a hard dependency
#  which in turn depends on json-c.
TARGETNAME	:=
-include $(top_builddir)/src/lib/curl/all.mk
TARGET		:=

ifneq "$(TARGETNAME)" ""
TARGETNAME	:= rlm_rest
TARGET		:= $(TARGETNAME)$(L)
TGT_PREREQS	+= libfreeradius-curl$(L)
endif

SOURCES		:= $(TARGETNAME).c rest.c io.c
LOG_ID_LIB	= 44

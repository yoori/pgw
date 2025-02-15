TARGETNAME	:= rlm_sber

TARGET		:= $(TARGETNAME)$(L)
SOURCES		:= $(TARGETNAME).c

SRC_INCDIRS	:= . lib/base ${top_srcdir}/src/ ${top_srcdir}/../radius_module/
TGT_LDLIBS      := -lradius_module

LOG_ID_LIB	= 1000

TARGETNAME	:= rlm_sber

TARGET		:= $(TARGETNAME)$(L)
SOURCES		:= $(TARGETNAME).c impl.cpp

SRC_INCDIRS	:= . lib/base ${top_srcdir}/src/

LOG_ID_LIB	= 1000

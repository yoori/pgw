AC_PREREQ([2.71])
AC_INIT
AC_CONFIG_SRCDIR([rlm_sber.c], [impl.cpp])
AC_REVISION($Revision$)
FR_INIT_MODULE([rlm_sber], [SBER functionality])

SMART_LIBS=-lradius_process_module
SMART_CLFAGS=
sbersubdirs=

FR_MODULE_START_TESTS

AC_PROG_CC

for foo in `find ./types -name configure -print`; do
  bar=`echo $foo | sed 's%/configure$%%g'`
  sbersubdirs="$sbersubdirs $bar"
done

dnl # don't ask... this is done to avoid autoconf stupidities.
ln -s ../../../install-sh install-sh

AC_CONFIG_SUBDIRS($sbersubdirs)
rm install-sh

FR_MODULE_END_TESTS

FR_MODULE_TEST_FAIL_DO([sbersubdirs=""])

sbertypes=types
if test x"$sbersubdirs" = x""; then
	sbertypes=""
fi

mod_ldflags="$SMART_LIBS"
mod_cflags="$SMART_CPPFLAGS"

AC_SUBST(sbertypes)
AC_SUBST(mod_ldflags)
AC_SUBST(mod_cflags)

AC_OUTPUT

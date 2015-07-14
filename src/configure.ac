AC_INIT([uwt_random], [0.0.1],[andreashauptmann@t-online.de],[uwt])

AC_PROG_CC

AC_CONFIG_HEADERS([config.h])
AC_USE_SYSTEM_EXTENSIONS

AC_CHECK_HEADERS(sys/ioctl.h sys/types.h sys/stat.h errno.h fcntl.h sys/rnd.h sys/syscall.h linux/types.h linux/random.h linux/sysctl.h sys/sysctl.h stddef.h unistd.h)
AC_CHECK_FUNCS(getentropy)


AC_MSG_CHECKING([_Static_assert])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM([_Static_assert (1, "");],
                                   [(void) 0])],
                  [AC_DEFINE([HAVE_STATIC_ASSERT], [1],
                             [Whether _Static_assert can be used or not])
                              AC_MSG_RESULT([yes])],
                               [AC_MSG_RESULT([no])])

AC_MSG_CHECKING([attribute "unused"])
AC_COMPILE_IFELSE(
    [AC_LANG_SOURCE([[
int x __attribute__((unused));

int
bar(int y __attribute__((unused)))
{
	return (0);
}
]])],
    [AC_MSG_RESULT([yes]); AC_DEFINE(ATTR_UNUSED,
	[__attribute__ ((unused))], ["unused" attribute.])],
    [AC_MSG_RESULT([no]);  AC_DEFINE(ATTR_UNUSED,
	[], ["unused" attribute.])])

AC_MSG_CHECKING(for __func__)
AH_TEMPLATE(__func__, [C99-specified function identifier])
AC_TRY_COMPILE([
#include <stdio.h>
],[printf ("%s", __func__);],
have_func=yes, have_func=no)
if test "x$have_func" = "xyes"; then
   AC_MSG_RESULT(yes)
else
   AC_MSG_RESULT(no)
   AC_MSG_CHECKING(for __FUNCTION__)
   AC_TRY_COMPILE([
#include <stdio.h>
],[printf ("%s", __FUNCTION__);],
have_function=yes, have_function=no)
   if test "x$have_function" = "xyes"; then
      AC_MSG_RESULT(yes)
      AC_DEFINE(__func__, __FUNCTION__)
   else
      AC_MSG_RESULT(no)
      AC_DEFINE(__func__, __FILE__)
   fi
fi

AC_MSG_CHECKING([for getrandom linux syscall interface])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <linux/random.h>
]],
[[
int x = GRND_NONBLOCK;
]])],
  [have_getrandom_interface=yes
   AC_DEFINE([HAVE_GETRANDOM_INTERFACE], [1], [Define to 1 if getrandom linux syscall interface is available.])],
  [have_getrandom_interface=no])
AC_MSG_RESULT([$have_getrandom_interface])
AM_CONDITIONAL([HAVE_GETRANDOM_INTERFACE], [test "x$have_getrandom_interface" = "xyes"])


AC_MSG_CHECKING([for getrandom linux syscall])
AC_LINK_IFELSE([AC_LANG_PROGRAM([[
#include <sys/syscall.h>
]],
[[
    int main() {
        const int flags = 0;
        char buffer[1];
        int n;
        (void)syscall(SYS_getrandom, buffer, sizeof(buffer), flags);
        return 0;
    }
]])],
  [have_getrandom_syscall=yes
   AC_DEFINE([HAVE_GETRANDOM_SYSCALL], [1], [Define to 1 if getrandom linux syscall syscall is available.])],
  [have_getrandom_syscall=no])
AC_MSG_RESULT([$have_getrandom_syscall])
AM_CONDITIONAL([HAVE_GETRANDOM_SYSCALL], [test "x$have_getrandom_syscall" = "xyes"])


AC_OUTPUT

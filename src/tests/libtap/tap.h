#ifndef __TAP_H__
#define __TAP_H__

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#define NO_PLAN          -1
#define ok(...)          ok_at_loc(__FILE__, __LINE__, __VA_ARGS__, NULL)
#define pass(...)        ok(1, ## __VA_ARGS__)
#define fail(...)        ok(0, ## __VA_ARGS__)
#define is(...)          is_at_loc(__FILE__, __LINE__, __VA_ARGS__, NULL)
#define isnt(...)        isnt_at_loc(__FILE__, __LINE__, __VA_ARGS__, NULL)
#define cmp_ok(...)      cmp_ok_at_loc(__FILE__, __LINE__, __VA_ARGS__, NULL)

int     vok_at_loc      (const char *file, int line, int test, const char *fmt,
                         va_list args);
void    plan            (int tests);
int     ok_at_loc       (const char *file, int line, int test, const char *fmt,
                         ...);
int     diag            (const char *fmt, ...);
int     note            (const char *fmt, ...);
int     exit_status     (void);
void    skippy          (int n, const char *fmt, ...);
void    ctodo           (int ignore, const char *fmt, ...);
void    cendtodo        (void);
int     is_at_loc       (const char *file, int line, const char *got,
                         const char *expected, const char *fmt, ...);
int     isnt_at_loc     (const char *file, int line, const char *got,
                         const char *expected, const char *fmt, ...);
int     cmp_ok_at_loc   (const char *file, int line, int a, const char *op,
                         int b, const char *fmt, ...);

#ifdef _WIN32
#define like(...)   skippy(1, "like is not implemented on MSWin32")
#define unlike(...) like()
#else
#define like(...)   like_at_loc(1, __FILE__, __LINE__, __VA_ARGS__, NULL)
#define unlike(...) like_at_loc(0, __FILE__, __LINE__, __VA_ARGS__, NULL)
int     like_at_loc     (int for_match, const char *file, int line,
                         const char *got, const char *expected,
                         const char *fmt, ...);
#endif

#define skip(test, ...)  do {if (test) {skippy(__VA_ARGS__, NULL); break;}
#define endskip          } while (0)

#define todo(...)        ctodo(0, ## __VA_ARGS__, NULL)
#define endtodo          cendtodo()

#define dies_ok(code, ...)  dies_ok_common(code, 1, ## __VA_ARGS__)
#define lives_ok(code, ...) dies_ok_common(code, 0, ## __VA_ARGS__)

#ifdef _WIN32
#define dies_ok_common(...) \
    skippy(1, "Death detection is not supported on MSWin32")
#else
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
int tap_test_died (int status);
#define dies_ok_common(code, for_death, ...)                \
    do {                                                    \
        tap_test_died(1);                                   \
        int cpid = fork();                                  \
        switch (cpid) {                                     \
        case -1:                                            \
            perror("fork error");                           \
            exit(EXIT_FAILURE);                             \
        case 0: /* child  */                                \
            close(1); close(2);                             \
            code                                            \
            tap_test_died(0);                               \
            exit(EXIT_SUCCESS);                             \
        }                                                   \
        if (waitpid(cpid, NULL, 0) < 0) {                   \
            perror("waitpid error");                        \
            exit(EXIT_FAILURE);                             \
        }                                                   \
        int it_died = tap_test_died(0);                     \
        if (!it_died) {code}                                \
        ok(for_death ? it_died : !it_died, ## __VA_ARGS__); \
    } while (0)
#endif
#endif

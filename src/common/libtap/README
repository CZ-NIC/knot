NAME
====

libtap - Write tests in C

SYNOPSIS
========

    #include <tap.h>
    
    int   foo () {return 3;}
    char *bar () {return "fnord";}

    int main () {
        plan(5);
        ok(foo() == 3);
        is(bar(), "eek");
        ok(foo() <= 8732, "foo <= %d", 8732);
        like(bar(), "f(yes|no)r*[a-f]$", "is like");
        cmp_ok(foo(), ">=", 10, "foo is greater than ten");
        return exit_status();
    }

results in:

    1..5
    ok 1
    not ok 2
    #   Failed test at synopsis.c line 9.
    #          got: 'fnord'
    #     expected: 'eek'
    ok 3 - foo <= 8732
    ok 4 - is like
    not ok 5 - foo is greater than ten
    #   Failed test 'foo is greater than ten'
    #   at synopsis.c line 12.
    #     3
    #         >=
    #     10
    # Looks like you failed 2 tests of 5 run.

DESCRIPTION
===========

tap is an easy to read and easy to write way of creating tests for your
software. This library creates functions that can be used to generate it for
your C programs. It is mostly based on the Test::More Perl module.

FUNCTIONS
=========

-   plan(tests)
-   plan(NO_PLAN)
    
    Use this to start a series of tests. When you know how many tests there 
    will be, you can put a number as a number of tests you expect to run. If 
    you do not know how many tests there will be, you can use plan(NO_PLAN)
    or not call this function. When you pass it a number of tests to run, a
    message similar to the following will appear in the output:
    
        1..5

-   ok(test)
-   ok(test, fmt, ...)

    Specify a test. the test can be any statement returning a true or false
    value. You may optionally pass a format string describing the test.
    
        ok(r = reader_new("Of Mice and Men"), "create a new reader");
        ok(reader_go_to_page(r, 55), "can turn the page");
        ok(r->page == 55, "page turned to the right one");
    
    Should print out:
    
        ok 1 - create a new reader
        ok 2 - can turn the page
        ok 3 - page turned to the right one
    
    On failure, a diagnostic message will be printed out.

        not ok 3 - page turned to the right one
        #   Failed test 'page turned to the right one'
        #   at reader.c line 13.

-   is(got, expected)
-   is(got, expected, fmt, ...)
-   isnt(got, expected)
-   isnt(got, expected, fmt, ...)

    Tests that the string you got is what you expected. with isnt, it is the
    reverse.
    
        is("this", "that", "this is that");

    prints:
    
        not ok 1 - this is that
        #   Failed test 'this is that'
        #   at is.c line 6.
        #          got: 'this'
        #     expected: 'that'

-   cmp_ok(a, op, b)
-   cmp_ok(a, op, b, fmt, ...)

    Compares two ints with any binary operator that doesn't require an lvalue.
    This is nice to use since it provides a better error message than an
    equivalent ok.
    
        cmp_ok(420, ">", 666);
    
    prints:
    
        not ok 1
        #   Failed test at cmpok.c line 5.
        #     420
        #         >
        #     666

-   like(got, expected)
-   like(got, expected, fmt, ...)
-   unlike(got, expected)
-   unlike(got, expected, fmt, ...)

    Tests that the string you got matches the expected extended POSIX regex.
    unlike is the reverse. These macros are the equivalent of a skip on
    Windows.
    
        like("stranger", "^s.(r).*\\1$", "matches the regex");
        
    prints:
    
        ok 1 - matches the regex

-   pass()
-   pass(fmt, ...)
-   fail()
-   fail(fmt, ...)

    Speciy that a test succeeded or failed. Use these when the statement is
    longer than you can fit into the argument given to an ok() test.

-   dies_ok(code)
-   dies_ok(code, fmt, ...)
-   lives_ok(code)
-   lives_ok(code, fmt, ...)

    Tests whether the given code causes your program to exit. The code gets
    passed to a macro that will test it in a forked process. If the code
    succeeds it will be executed in the parent process. You can test things 
    like passing a function a null pointer and make sure it doesnt 
    dereference it and crash.
    
        dies_ok({abort();}, "abort does close your program");
        dies_ok({int x = 0/0;}, "divide by zero crash");
        lives ok({pow(3.0, 5.0)}, "nothing wrong with taking 3**5");
    
    On Windows, these macros are the equivalent of a skip.

-   exit_status()

    Summarizes the tests that occurred. If there was no plan, it will print
    out the number of tests as.
    
        1..5
    
    It will also print a diagnostic message about how many
    failures there were.
    
        # Looks like you failed 2 tests of 3 run.
    
    If all planned tests were successful, it will return 0. If any test fails,
    it will return the number of failed tests (including ones that were
    missing). If they all passed, but there were missing tests, it will return
    255.

-   note(fmt, ...)
-   diag(fmt, ...)

    print out a message to the tap output. note prints to stdout and diag
    prints to stderr. Each line is preceeded by a "# " so that you know its a 
    diagnostic message.
    
        note("This is\na note\nto describe\nsomething.");
    
    prints:
    
        # This is
        # a note
        # to describe
        # something
    
    ok() and these functions return ints so you can use them like:
    
        ok(1) && note("yo!");
        ok(0) || diag("I have no idea what just happened");

-   skip(test, n)
-   skip(test, n, fmt, ...)
-   endskip

    Skip a series of n tests if test is true. You may give a reason why you are
    skipping them or not. The (possibly) skipped tests must occur between the
    skip and endskip macros.
    
        skip(TRUE, 2);
        ok(1);
        ok(0);
        endskip;

    prints:
    
        ok 1 # skip
        ok 2 # skip

-   todo()
-   todo(fmt, ...)
-   endtodo

    Specifies a series of tests that you expect to fail because they are not
    yet implemented.

        todo()
        ok(0);
        endtodo;
    
    prints:
    
        not ok 1 # TODO
        #   Failed (TODO) test at todo.c line 7


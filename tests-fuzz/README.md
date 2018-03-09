# Fuzzing stdio-wrapped knotd with [AFL](http://lcamtuf.coredump.cx/afl/)

1. Ensure [Clang](https://clang.llvm.org)
1. Ensure AFL 1.83b+ or install fresh one
 2. `curl -O -L http://lcamtuf.coredump.cx/afl/releases/afl-latest.tgz`
 2. `tar -xzf afl-latest.tgz`
 2. `cd afl-*/`
 2. `make`
 2. `make -C llvm_mode`
 2. `sudo make install`
1. Compile Knot DNS with `afl-clang` compiler
 2. `CC=afl-clang-fast ./configure --disable-shared --disable-utilities --disable-documentation`
 2. (Add `--with-sanitizer=address` for [ASAN](http://clang.llvm.org/docs/AddressSanitizer.html))
 2. `make`
1. Try running `knotd_stdio`
 2. `cd tests-fuzz`
 2. `make check-compile`
 2. `mkdir -p /tmp/knotd-fuzz/rundir /tmp/knotd-fuzz/storage`
 2. `./knotd_stdio -c ./knotd_wrap/knot_stdio.conf`
 2. (Consider adding zones or modules to the configuration)
1. Prepare an initial corpus
 2. Checkout the dns-fuzzing repository `git clone https://github.com/CZ-NIC/dns-fuzzing in`
 2. (Add more custom test cases to `in/packet/`)
1. Minimize the tested corpus with `afl-cmin` and simple packet parser (doesn't work with ASAN!)
  2. `afl-cmin -i in/packet/ -o min -- ./fuzz_packet`
1. Run the fuzzer
  2. `AFL_PERSISTENT=1 afl-fuzz -m 1000M -i min -o out -- ./knotd_stdio -c knotd_wrap/knot_stdio.conf`
  2. (Add `AFL_USE_ASAN=1` and use `-m none` if compiled with ASAN)
  2. (Consider parallel fuzzing, see `afl-fuzz -h`)

**NOTE:** Sanitizer utilization is a bit problematical with AFL, see [notes_for_asan.txt]
(https://github.com/mirrorer/afl/blob/master/docs/notes_for_asan.txt).

# Fuzzing with [libFuzzer](https://llvm.org/docs/LibFuzzer.html) (requires Clang 6.0+)

1. Ensure [Clang](https://clang.llvm.org) with `-fsanitize=fuzzer` support (e.g. [LLVM](https://apt.llvm.org))
1. Configure with
 2. `./configure --with-fuzzer --disable-shared --disable-documentation`
 2. (You should also add `--with-sanitizer=`
    `address` for [ASAN](http://clang.llvm.org/docs/AddressSanitizer.html) or
    `undefined` for [UBSAN](http://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html))
 2. (Add proper `CC=clang-6.0` if necessary)
1. Compile Knot DNS:
 2. `make`
1. Create and check the fuzzing binaries 
 2. `cd tests-fuzz`
 2. `make check`
1. Download the corpora
 2. `git submodule init`
 2. `git submodule update --recursive --remote`
1. (Optional) add more test cases
 2. `./fuzz_packet -merge=1 fuzz_packet.in <DIR_WITH_NEW_PACKET_TEST_CASES>`
 2. `./fuzz_zscanner -merge=1 fuzz_zscanner.in <DIR_WITH_NEW_ZSCANNER_TEST_CASES>`
1. Run the fuzzer
 2. (Set proper symbolizer if necessary
    ``export ASAN_SYMBOLIZER_PATH=$(readlink -f `which llvm-symbolizer-6.0`)`` for ASAN or
    ``export UBSAN_SYMBOLIZER_PATH=$(readlink -f `which llvm-symbolizer-6.0`)`` for UBSAN)
 2. `./fuzz_packet fuzz_packet.in` or `./fuzz_zscanner fuzz_zscanner.in`
 2. (Add parallel fuzzing `-jobs=<CPUS>`

# Fuzzing with [libFuzzer](https://llvm.org/docs/LibFuzzer.html) (requires Clang 6.0+)

1. Ensure [Clang](https://clang.llvm.org) with `-fsanitize=fuzzer` support (e.g. [LLVM](https://apt.llvm.org))
1. Configure with
   1. `./configure --with-fuzzer --disable-shared --disable-documentation`
   1. (You should also add `--with-sanitizer=`
      `address` for [ASAN](http://clang.llvm.org/docs/AddressSanitizer.html) or
      `undefined` for [UBSAN](http://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html))
   1. (Add proper `CC=clang-6.0` if necessary)
1. Compile Knot DNS:
   1. `make`
1. Create and check the fuzzing binaries 
   1. `cd tests-fuzz`
   1. `make check`
1. Download the corpora
   1. `git submodule init`
   1. `git submodule update --recursive --remote`
1. (Optional) add more test cases
   1. `./fuzz_packet -merge=1 fuzz_packet.in <DIR_WITH_NEW_PACKET_TEST_CASES>`
   1. `./fuzz_zscanner -merge=1 fuzz_zscanner.in <DIR_WITH_NEW_ZSCANNER_TEST_CASES>`
1. Run the fuzzer
   1. (Set proper symbolizer if necessary
      ``export ASAN_SYMBOLIZER_PATH=$(readlink -f `which llvm-symbolizer-6.0`)`` for ASAN or
      ``export UBSAN_SYMBOLIZER_PATH=$(readlink -f `which llvm-symbolizer-6.0`)`` for UBSAN)
   1. `./fuzz_packet fuzz_packet.in` or `./fuzz_zscanner fuzz_zscanner.in`
   1. (Add parallel fuzzing `-jobs=<CPUS>`

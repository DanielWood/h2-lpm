#!/bin/bash
# No coverage
#auto/configure --with-cc-opt='-DNGX_DEBUG_PALLOC=1 -O0' --with-http_v2_module --with-cc=clang --with-cpp=clang++
#CXX=clang++ CFLAGS="-fsanitize=fuzzer,address -O0" make -f objs/Makefile fuzzer

# With coverage
auto/configure --with-cc-opt='-DNGX_DEBUG_PALLOC=1 -O0 -fprofile-arcs -ftest-coverage' --with-http_v2_module --with-cc=clang --with-cpp=clang++
CXX=clang++ CFLAGS="-fsanitize=fuzzer,address -g -O0 -fprofile-arcs -ftest-coverage" make -f objs/Makefile fuzzer

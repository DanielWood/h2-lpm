#!/bin/bash

rm lcov_test.info
lcov --gcov-tool=/home/ufo/personal/research/fuzzing/nginx/gcov -c -d objs/ -o lcov_test.info

# TODO REPORT
lcov --add-tracefile lcov_base.info --add-tracefile lcov_test.info --output-file lcov_total.info

rm -rf lcov-report/
mkdir lcov-report

genhtml --prefix=/home/ufo/personal/research/fuzzing/nginx lcov_total.info --output-directory=lcov-report/


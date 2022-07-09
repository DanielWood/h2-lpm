#!/bin/bash

rm *.gcda
rm **/*.gcda
lcov --gcov-tool=/home/ufo/personal/research/fuzzing/nginx/gcov -c -i -d objs/ -o lcov_base.info

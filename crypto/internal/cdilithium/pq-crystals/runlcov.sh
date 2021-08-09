#!/bin/sh -e

cd ref

for alg in 2 2aes 3 3aes 5 5aes; do
  make -B test/test_dilithium$alg CFLAGS="-O0 -g --coverage"
  ./test/test_dilithium$alg
  lcov -c -d . -o dilithium$alg.lcov
  lcov -z -d .
  rm test/test_dilithium$alg
done

lcov -o dilithium.lcov \
  -a dilithium2.lcov \
  -a dilithium2aes.lcov \
  -a dilithium3.lcov \
  -a dilithium3aes.lcov \
  -a dilithium5.lcov \
  -a dilithium5aes.lcov

lcov -r dilithium.lcov -o dilithium.lcov \
  '*/test/test_dilithium.c'

exit 0

#! /bin/sh

rm -f test_run
gcc -o test_run openssl_cipher_test.c -I/home/abbas/path/include && ./test_run $1
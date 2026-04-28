# Makefile for DNSSEC signing tool
# Author: Steve
# make different names for different records, 
# like make A for A files, make NS for NS files, etc.
run:
	gcc -Wall dnssec_sign.c -o dnssec_sign -lcrypto


clean:
	rm -f dnssec_sign
run:
	gcc -Wall dnssec_sign.c -o dnssec_sign -lcrypto


clean:
	rm -f dnssec_sign
# Makefile for DNSSEC signing tool
# Author: Steve
# make different names for different records, 
# like make A for A files, make NS for NS files, etc.
compile:
	gcc -Wall dnssec_sign.c -o dnssec_sign -lcrypto

a:
	./dnssec_sign ~/keys/jmu_zsk_private.pem ./keys/jmu-lab/jmu_zsk_public.pem ./hex_in/a.hex ./signatures/new/quad_a_sig.b64

dnskey:
	./dnssec_sign ~/keys/jmu_ksk_private.pem ./keys/jmu-lab/jmu_ksk_public.pem ./hex_in/new_dnskey.hex ./signatures/new/dnskey_jmu.b64
ns:
	dnskey:
	./dnssec_sign ~/keys/jmu_zsk_private.pem ./keys/jmu-lab/jmu_zsk_public.pem ./hex_in/new_ns.hex ./signatures/new/quad_ns_sig.b64
clean:
	rm -f dnssec_sign
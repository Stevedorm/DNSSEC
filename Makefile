# Makefile for DNSSEC signing tool
# Author: Steve
# See different headers for different commands to run for
# compiling, cleaning, and signing different records.

# Run make compile to compile the code for the other commands below
compile:
	gcc -Wall dnssec_sign.c -o dnssec_sign -lcrypto
	@echo
	@echo Code Compiled!!
	@echo
	@echo Run make \(a, ns, or dnskey\) to sign those records!
	@echo

# Run make clean to make a fresh executable
clean:
	rm -f dnssec_sign
	@echo
	@echo Executable Removed!!
	@echo

# Run make a after executable is compilied to generate 
# and validate an A record signature
a:
	./dnssec_sign ~/keys/jmu_zsk_private.pem ./keys/jmu-lab/jmu_zsk_public.pem ./hex_in/a.hex ./signatures/new/quad_a_sig.b64

# Run make dnskey after executable is compilied to generate 
# and validate an DNSKEY record signature
dnskey:
	./dnssec_sign ~/keys/jmu_ksk_private.pem ./keys/jmu-lab/jmu_ksk_public.pem ./hex_in/new_dnskey.hex ./signatures/new/dnskey_jmu.b64

# Run make ns after executable is compilied to generate 
# and validate an NS record signature
ns:
	./dnssec_sign ~/keys/jmu_zsk_private.pem ./keys/jmu-lab/jmu_zsk_public.pem ./hex_in/new_ns.hex ./signatures/new/quad_ns_sig.b64
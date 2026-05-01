# Makefile for DNSSEC signing tool
# Author: Steve
# See different headers for different commands to run for
# compiling, cleaning, and signing different records.

# Run make compile to compile the code for the other commands below
compile:
	@echo
	gcc -Wall dnssec_sign.c -o dnssec_sign -lcrypto
	@echo
	@echo Code Compiled!!
	@echo
	@echo Run make \(a, ns, or dnskey\) to sign those records!
	@echo

# Run make clean to make a fresh executable
clean:
	@echo
	rm -f dnssec_sign
	@echo
	@echo Executable Removed!!
	@echo

# Run make a after executable is compilied to generate 
# and validate an A record signature
a:
	@echo
	@echo Command that was run is seen below
	./dnssec_sign ~/keys/jmu_zsk_private.pem ./keys/jmu-lab/jmu_zsk_public.pem ./hex_in/a.hex ./signatures/quad_a_sig.b64
	@echo

# Run make dnskey after executable is compilied to generate 
# and validate an DNSKEY record signature
dnskey:
	@echo
	@echo Command that was run is seen below
	./dnssec_sign ~/keys/jmu_ksk_private.pem ./keys/jmu-lab/jmu_ksk_public.pem ./hex_in/dnskey.hex ./signatures/dnskey_jmu.b64
	@echo

# Run make ns after executable is compilied to generate 
# and validate an NS record signature
ns:
	@echo
	@echo Command that was run is seen below
	./dnssec_sign ~/keys/jmu_zsk_private.pem ./keys/jmu-lab/jmu_zsk_public.pem ./hex_in/ns.hex ./signatures/quad_ns_sig.b64
	@echo

# Run make keys to generate all of the key files to .pem files
keys:
	@echo
	@echo Commands to generate the public keys is below
	@echo
	cd keys
	gcc -Wall bind2pem.c -o bind2pem
	./bind2pem ../Kjmu.lab.+008+34939.key /jmu-lab/jmu_ksk_public.pem
	./bind2pem ../Kjmu.lab.+008+49498.key /jmu-lab/jmu_zsk_public.pem
	./bind2pem ../Kjmu.lab.+008+05852.key /lab/lab_ksk_public.pem
	./bind2pem ../Kjmu.lab.+008+12978.key /lab/lab_zsk_public.pem
	@echo
	@echo Commands to generate the private keys is below
	@echo
# Directory that holds my private key files, as well as another copy of bind2pem
# check keyIds, make sure these directories are good
	cd ~/keys
	gcc -Wall bind2pem.c -o bind2pem
	./bind2pem ../Kjmu.lab.+008+34939.private jmu_ksk_private.pem
	./bind2pem ../Kjmu.lab.+008+49498.private jmu_zsk_private.pem
	./bind2pem ../Kjmu.lab.+008+05852.private lab_ksk_private.pem
	./bind2pem ../Kjmu.lab.+008+12978.private lab_zsk_private.pem
	@echo
	@echo All keys were generated successfully!
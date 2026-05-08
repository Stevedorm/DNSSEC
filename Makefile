# Makefile for DNSSEC signing tool
# Author: Steven Dormady
# See different headers for different commands to run for
# compiling, cleaning, and signing different records.

#  Define the command names
.PHONY: compile compile-keys a ns dnskey soa keys clean-keys clean

# Run make compile to compile the code for the other commands below
compile:
	@echo
	gcc -Wall dnssec_sign.c -o dnssec_sign -lcrypto
	@echo
	@echo Code Compiled!! Executable is in the current directory with the name dnssec_sign.
	@echo
	@echo Run make \(a, ns, or dnskey\) to sign those records!
	@echo

# Run make compile-keys to compile the bind2pem executable that is used in key conversion
compile-keys:
	@echo
	gcc -o bind2pem bind2pem.c -lssl -lcrypto
	@echo
	@echo Key Conversion Script Compiled!!
	@echo
	@echo Run make keys to convert the keys to .pem files!
	@echo
	@echo These keys will be stored in their respective public/private key directory!
	@echo

# Run make a after executable is compiled to generate 
# and validate an A record signature
a:
	@echo
	@echo Command that was run is seen below
	@echo
	./dnssec_sign ~/keys/jmu_zsk_private.pem ./keys/jmu-lab/jmu_zsk_public.pem ./hex_in/a.hex ./signatures/quad_a_sig.b64
	@echo
	@echo Below is the output of the signature validation for the A record
	@echo

# Run make dnskey after executable is compiled to generate 
# and validate an DNSKEY record signature
dnskey:
	@echo
	@echo Command that was run is seen below
	@echo
	./dnssec_sign ~/keys/jmu_ksk_private.pem ./keys/jmu-lab/jmu_ksk_public.pem ./hex_in/dnskey.hex ./signatures/dnskey_jmu.b64
	@echo
	@echo Below is the output of the signature validation for the DNSKEY record
	@echo

# Run make ns after executable is compiled to generate 
# and validate an NS record signature
ns:
	@echo
	@echo Command that was run is seen below
	@echo
	./dnssec_sign ~/keys/jmu_zsk_private.pem ./keys/jmu-lab/jmu_zsk_public.pem ./hex_in/ns.hex ./signatures/quad_ns_sig.b64
	@echo
	@echo Below is the output of the signature validation for the NS record
	@echo

# Run make soa after executable is compiled to generate 
# and validate an SOA record signature
soa:
	@echo
	@echo Command that was run is seen below
	@echo
	./dnssec_sign ~/keys/jmu_zsk_private.pem ./keys/jmu-lab/jmu_zsk_public.pem ./hex_in/new_soa.hex ./signatures/soa.b64
	@echo
	@echo Below is the output of the signature validation for the SOA record
	@echo

# Run make keys to generate all of the key files to .pem files
# This script requires the keys from the dns servers to be in 
# the respective keys directory
keys:
#  If needed, command to recompile the bind2pem: gcc -Wall bind2pem.c -o bind2pem
	@echo
	@echo Commands to generate the public keys is below
	@echo
	cd keys && \
		./bind2pem ../vm_files/Kjmu.lab.+008+34939.key jmu-lab/jmu_ksk_public.pem && \
		./bind2pem ../vm_files/Kjmu.lab.+008+49498.key jmu-lab/jmu_zsk_public.pem && \
		./bind2pem ../vm_files/Klab.+008+05852.key lab/lab_ksk_public.pem && \
		./bind2pem ../vm_files/Klab.+008+12978.key lab/lab_zsk_public.pem
	@echo
	@echo Commands to generate the private keys is below
	@echo
	cd ~/keys && \
		./bind2pem Kjmu.lab.+008+34939.private jmu_ksk_private.pem && \
		./bind2pem Kjmu.lab.+008+49498.private jmu_zsk_private.pem && \
		./bind2pem Klab.+008+05852.private lab_ksk_private.pem && \
		./bind2pem Klab.+008+12978.private lab_zsk_private.pem
	@echo
	@echo All keys were generated successfully!

# Run make clean-keys to remove old key files.
clean-keys:
	rm -f keys/jmu-lab/jmu_zsk_public.pem \
	      keys/jmu-lab/jmu_ksk_public.pem \
	      keys/lab/lab_zsk_public.pem \
	      keys/lab/lab_ksk_public.pem
	rm -f ~/keys/jmu_zsk_private.pem \
	      ~/keys/jmu_ksk_private.pem \
	      ~/keys/lab_ksk_private.pem \
	      ~/keys/lab_zsk_private.pem
	@echo
	@echo All keys removed!

# Run make clean remove the old executable and make room for a new one!
clean:
	@echo
	rm -f dnssec_sign
	@echo
	@echo Executable Removed!!
	@echo
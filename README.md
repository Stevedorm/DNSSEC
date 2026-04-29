
# DNSSEC

This repository contains the code that I wrote completing an Indpendent Study on DNSSEC. Over the course of this project, I have learned about DNS and it's vulnerablities, and how an unsecure DNS system can be attacked.

The Make file contains comments and commands to compile, clean, and run the executable for the signature process for different records.

The keys directory contains two subdirectories for each respective zone, .lab and .jmu.lab. These are the public KSK and ZSK for each zone. There is also a c file for converting the DNSSEC keys into RSA .pem keys, which I used Claude to help me write as well.

The captures directory holds some pcap files that I used to pull hex data from to then hash and sign.

The signatures directory hold the base64 signature for different records.

The hex_in directory holds the manually built hex files that are passed to dnssec_sign.c, then used to generate and validate the existing signature.

The main driver file is dnssec_sign.c, where records are loaded in, like the private key, public key, hex of the record to be generated and signed, and the recieved signature from a DNSSEC query.

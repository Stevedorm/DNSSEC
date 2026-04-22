
# DNSSEC

This repository contains the code that I wrote completing an Indpendent Study on DNSSEC. Over the course of this project, I have learned about DNS and it's vulnerablities, and how an unsecure DNS system can be attacked.


basetobin.c contains code from Claude that converts the base64 signature to binary. This same function is in dnssec_sign.c, which is the main driver.

The keys directory contains two subdirectories for each respective zone, .lab and .jmu.lab. These are the public KSK and ZSK for each zone. There is also a c file for converting the DNSSEC keys into RSA .pem keys, which I used Claude to help me write as well.

The captures directory holds some pcap files that I used to pull hex data from to then hash and sign.

The signatures directory hold the base64 signature for different records.

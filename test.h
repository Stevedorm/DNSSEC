#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <time.h>

#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>


struct a_rec {

} a_rec_t;

// This signature is 256 bytes long, it is a ksk signature from the child.
// 0f4b34bd59c7a7a5985a6ac1d3651cc223a65ad0ca4961ac3f16d702282cf8ad1284dafa469ac0ed59beb918b90f99a0a0992328305bc9e661cefc8ae47564f92c9c0d66570ab3b1a93998535185094519007d0c6ac7b3de09400576217ecbc187834dc05b14e7562315784b4a00da0f3da750bce88086643bccbe466d291fd19d759689af695e4c2dd58b314c9b2a38fcac53f1d15d7de7cf954163f037ef3a3eeaac6f2c0952e54c03fc9e574cb33256ca431239d878de3c97f143a3928c71a2b92eb07f085c72964593a797efb623d0660b0fcbee01464ee665a4a731d858ea0bed4639c2989800b8409b68eb853155a6caeb5ca2ad379cc8cc61f9b95ba2 A SIG
typedef struct {
    uint16_t type; // type of record. should be 48 for DNSKEY, 1 for A
    uint8_t algo; // algorithm used. should be 8 for RSASHA256
    uint8_t labels; // number of labels, normally 2 or 3 in my case. 3 for A record on child.
    uint32_t ttl; // Time to live
    uint32_t expiration; // expiration time in seconds since epoch
    uint32_t inception; // inception time in seconds since epoch
    uint16_t key_tag; // tag of the key used for signature.
    char signer_name[16]; // length of signer name, make an array? jmu.lab is 9 bytes long, but I will make it 16 to be safe.
} r_data_t;





// typedef struct {
//     uint16_t type; // type of record. 48 for DNSKEY, 1 for A
//     uint8_t algo; // algorithm used. 8 for RSASHA256
//     uint8_t labels; // number of labels. quad.jmu.lab is 3.
//     uint32_t ttl; // Time to live. Length of time in seconds 
//                   //  that the record can be cached.
//     uint32_t expiration; // expiration time in seconds since epoch
//     uint32_t inception; // inception time in seconds since epoch
//     uint16_t key_tag; // tag of the key used for signature.
//     char signer_name[16]; // length of signer name.
// } r_data_t;
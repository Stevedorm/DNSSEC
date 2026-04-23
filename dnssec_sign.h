#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define HASH_ALGORITHM     EVP_sha256() // Use SHA-256 for hashing

// ==========================================
// Function prototypes
// ==========================================

EVP_PKEY *load_private_key( const char *filename );
EVP_PKEY *load_public_key( const char *filename );
bool load_signature( const char *filename , unsigned char **sig , size_t *sig_len );
bool load_sigbase( const char *filename , unsigned char **sigbase , size_t *sigbase_len );
void hexdump (  const char *label , const unsigned char *data , size_t len  );
void print_sha256 (  const char *label , unsigned char *data , size_t len  );
int hex_to_bin (  const char *hex , unsigned char **out , size_t *out_len  );
int b64_to_bin (  const char *b64 , unsigned char **out , size_t *out_len  );
void compare_sigs (  const unsigned char *a , size_t a_len ,
                  const unsigned char *b , size_t b_len  );
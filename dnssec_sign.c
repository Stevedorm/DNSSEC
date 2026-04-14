#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>


// TODO: Group up main function , make code prettier , add more comments , etc.

// ==========================================
// Function prototypes
// ==========================================
void hexdump (  const char *label , unsigned char *data , size_t len  );
void print_sha256 (  const char *label , unsigned char *data , size_t len  );
int hex_to_bin (  const char *hex , unsigned char **out , size_t *out_len  );
int b64_to_bin (  const char *b64 , unsigned char **out , size_t *out_len  );
void compare_sigs (  unsigned char *a , size_t a_len ,
                  unsigned char *b , size_t b_len  );

// ==========================================
// Main
// ==========================================
int main (  int argc , char *argv[]  )
{
    if  (  argc != 5  )
    {
        fprintf (  stderr , "Usage: %s <private.pem> <public.pem> <sigbase.hex> <rrsig.b64>\n\n" , argv[0]  );
        fprintf (  stderr , "  private.pem  - private key in PEM format\n"  );
        fprintf (  stderr , "  public.pem   - public key in PEM format\n"  );
        fprintf (  stderr , "  sigbase.hex  - signature base as a hex string file\n"  );
        fprintf (  stderr , "  rrsig.b64    - existing RRSIG signature field as base64 file\n"  );
        return EXIT_FAILURE;
    }

    // ==============================
    // Load private key
    // ==============================
    FILE *f = fopen (  argv[1] , "r"  );
    if  ( !f )
    { 
        fprintf (  stderr , "Error: cannot open private key\n"  ); 
        return EXIT_FAILURE;
    }

    EVP_PKEY *privkey = PEM_read_PrivateKey (  f , NULL , NULL , NULL  );
    fclose (  f  );

    if  ( !privkey )
    { 
        fprintf (  stderr , "Error: failed to read private key\n"  ); 
        return EXIT_FAILURE;
    }
    printf (  "Private key loaded: %d bits\n" , EVP_PKEY_bits  (  privkey  )  );
    // ==============================
    //Private key loaded
    // ==============================

    // ==============================
    // Load public key
    // ==============================
    f = fopen (  argv[2] , "r"  );
    if  ( !f )
    { 
        fprintf  (  stderr , "Error: cannot open public key\n"  ); 
        return EXIT_FAILURE;
    }

    EVP_PKEY *pubkey = PEM_read_PUBKEY  (  f , NULL , NULL , NULL  );
    fclose (  f  );

    if  ( !pubkey )
    { 
        fprintf  (  stderr , "Error: failed to read public key\n"  ); 
        return EXIT_FAILURE; 
    }
    printf (  "Public key loaded:  %d bits\n\n" , EVP_PKEY_bits  (  pubkey  )  );
    // ==============================
    // Public key loaded
    // ==============================

    // Load signature base from hex file
    f = fopen (  argv[3] , "r"  );
    if  ( !f )
    { 
        fprintf (  stderr , "Error: cannot open sigbase hex file\n"  ); 
        return EXIT_FAILURE; 
    }

    fseek (  f , 0 , SEEK_END  );
    long hex_file_len = ftell (  f  );
    rewind (  f  );
    char *hex_str = malloc (  hex_file_len + 1  );
    fread (  hex_str , 1 , hex_file_len , f  );
    fclose (  f  );
    hex_str[hex_file_len] = 0;
    // Strip newlines
    hex_str[strcspn (  hex_str , "\r\n"  )] = 0;

    unsigned char *sigbase = NULL;
    size_t sigbase_len = 0;

    if  (  !hex_to_bin (  hex_str , &sigbase , &sigbase_len  )  )
    {
        free (  hex_str  );
        return EXIT_FAILURE;
    }
    free (  hex_str  );

    hexdump (  "Signature base  (  from hex  )" , sigbase , sigbase_len  );

    print_sha256 (  "signature base" , sigbase , sigbase_len  );

    // ==============================
    // Load existing RRSIG base64
    // ==============================
    f = fopen (  argv[4] , "r"  );
    if  ( !f )
    { 
        fprintf (  stderr , "Error: cannot open RRSIG base64 file\n"  ); 
        return EXIT_FAILURE; 
    }

    fseek (  f , 0 , SEEK_END  );
    long b64_file_len = ftell (  f  );
    rewind (  f  );
    char *b64_str = malloc (  b64_file_len + 1  );
    fread (  b64_str , 1 , b64_file_len , f  );
    fclose (  f  );
    b64_str[b64_file_len] = 0;

    unsigned char *existing_sig = NULL;
    size_t existing_sig_len = 0;

    if  (  !b64_to_bin (  b64_str , &existing_sig , &existing_sig_len  )  )
    {
        free (  b64_str  );
        return EXIT_FAILURE;
    }
    free (  b64_str  );

    hexdump (  "Existing RRSIG signature" , existing_sig , existing_sig_len  );

    // Generate the signature
    unsigned char *gen_sig = NULL;
    size_t gen_sig_len = 0;

    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new ();
    if  (  EVP_DigestSignInit (  sign_ctx , NULL , EVP_sha256 () , NULL , privkey  ) != 1 ||
        EVP_DigestSignUpdate (  sign_ctx , sigbase , sigbase_len  ) != 1 ||
        EVP_DigestSignFinal (  sign_ctx , NULL , &gen_sig_len  ) != 1  )
    {
        fprintf (  stderr , "Error: signing init failed\n"  );
        return EXIT_FAILURE;
    }

    gen_sig = malloc (  gen_sig_len  );

    if  (  EVP_DigestSignFinal (  sign_ctx , gen_sig , &gen_sig_len  ) != 1  )
    {
        fprintf (  stderr , "Error: signing final failed\n"  );
        return EXIT_FAILURE;
    }
    
    EVP_MD_CTX_free (  sign_ctx  );

    hexdump (  "Generated signature" , gen_sig , gen_sig_len  );

    // Verify generated signature with public key
    printf (  "=== Verify: generated signature with public key ===\n"  );
    EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new ();
    if  (  EVP_DigestVerifyInit (  verify_ctx , NULL , EVP_sha256 () , NULL , pubkey  ) == 1 &&
        EVP_DigestVerifyUpdate (  verify_ctx , sigbase , sigbase_len  ) == 1 &&
        EVP_DigestVerifyFinal (  verify_ctx , gen_sig , gen_sig_len  ) == 1  )
    {
        printf (  "PASS: generated signature verifies correctly\n\n"  );
    }
    else
    {
        printf (  "FAIL: generated signature did not verify\n\n"  );
    }
    EVP_MD_CTX_free (  verify_ctx  );

    // Verify existing RRSIG with public key
    printf (  "=== Verify: existing RRSIG with public key ===\n"  );
    verify_ctx = EVP_MD_CTX_new ();
    if  (  EVP_DigestVerifyInit (  verify_ctx , NULL , EVP_sha256 () , NULL , pubkey  ) == 1 &&
        EVP_DigestVerifyUpdate (  verify_ctx , sigbase , sigbase_len  ) == 1 &&
        EVP_DigestVerifyFinal (  verify_ctx , existing_sig , existing_sig_len  ) == 1  )
    {
        printf (  "PASS: existing RRSIG verifies correctly\n\n"  );
    }
    else
    {
        printf (  "FAIL: existing RRSIG did not verify - sigbase may not match exactly\n\n"  );
    }
    EVP_MD_CTX_free (  verify_ctx  );

    // Binary comparison
    compare_sigs (  gen_sig , gen_sig_len , existing_sig , existing_sig_len  );

    // Cleanup
    free (  sigbase  );
    free (  existing_sig  );
    free (  gen_sig  );
    EVP_PKEY_free (  privkey  );
    EVP_PKEY_free (  pubkey  );

    return EXIT_SUCCESS;
}

// ==========================================
// Utility functions Below
// ==========================================

// Decode a hex string into bytes
int hex_to_bin (  const char *hex , unsigned char **out , size_t *out_len  ) {
    size_t hex_len = strlen (  hex  );
    if  (  hex_len % 2 != 0  ) {
        fprintf (  stderr , "Error: odd hex string length\n"  );
        return 0;
    }
    *out_len = hex_len / 2;
    *out = malloc (  *out_len  );

    for  (  size_t i = 0; i < *out_len; i++  ) {
        unsigned int byte;
        if  (  sscanf (  hex +  (  i * 2  ) , "%02x" , &byte  ) != 1  ) {
            fprintf (  stderr , "Error: invalid hex at position %zu\n" , i * 2  );
            free (  *out  );
            return 0;
        }
         (  *out  )[i] =  (  unsigned char  )byte;
    }
    return 1;
}

// Decode a base64 string into bytes  (  handles newlines/whitespace  )
int b64_to_bin (  const char *b64 , unsigned char **out , size_t *out_len  ) {
    // Strip whitespace into a clean buffer
    char *clean = malloc (  strlen (  b64  ) + 1  );
    int ci = 0;
    for  (  int i = 0; b64[i]; i++  )
        if  (  b64[i] != ' ' && b64[i] != '\n' && b64[i] != '\r' && b64[i] != '\t'  )
            clean[ci++] = b64[i];
    clean[ci] = 0;

    size_t bin_len =  (  ci * 3  ) / 4 + 4;
    *out = malloc (  bin_len  );

    BIO *b64_bio = BIO_new (  BIO_f_base64 ()  );
    BIO *mem_bio = BIO_new_mem_buf (  clean , -1  );
    BIO_push (  b64_bio , mem_bio  );
    BIO_set_flags (  b64_bio , BIO_FLAGS_BASE64_NO_NL  );

    int decoded = BIO_read (  b64_bio , *out , bin_len  );
    BIO_free_all (  b64_bio  );
    free (  clean  );

    if  (  decoded <= 0  ) {
        fprintf (  stderr , "Error: base64 decode failed\n"  );
        free (  *out  );
        return 0;
    }

    *out_len = decoded;
    return 1;
}

// Print a hex dump with ASCII
void hexdump (  const char *label , unsigned char *data , size_t len  ) {
    printf (  "\n=== %s  (  %zu bytes  ) ===\n" , label , len  );
    for  (  size_t i = 0; i < len; i++  ) {
        if  (  i % 16 == 0  ) printf (  "%04zx  " , i  );
        printf (  "%02x " , data[i]  );
        if  (   (  i + 1  ) % 8 == 0 &&  (  i + 1  ) % 16 != 0  ) printf (  " "  );
        if  (   (  i + 1  ) % 16 == 0  ) {
            printf (  " |"  );
            for  (  size_t j = i - 15; j <= i; j++  )
                printf (  "%c" ,  (  data[j] >= 32 && data[j] < 127  ) ? data[j] : '.'  );
            printf (  "|\n"  );
        }
    }
    // Handle last partial line
    if  (  len % 16 != 0  ) {
        size_t remaining = len % 16;
        for  (  size_t i = 0; i < 16 - remaining; i++  ) printf (  "   "  );
        if  (  remaining <= 8  ) printf (  " "  );
        printf (  " |"  );
        for  (  size_t i = len - remaining; i < len; i++  )
            printf (  "%c" ,  (  data[i] >= 32 && data[i] < 127  ) ? data[i] : '.'  );
        printf (  "|\n"  );
    }
    printf (  "\n"  );
}

// Print the SHA-256 digest of a buffer
void print_sha256 (  const char *label , unsigned char *data , size_t len  ) {
    unsigned char digest[32];
    EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
    EVP_DigestInit_ex (  ctx , EVP_sha256 () , NULL  );
    EVP_DigestUpdate (  ctx , data , len  );
    unsigned int digest_len;
    EVP_DigestFinal_ex (  ctx , digest , &digest_len  );
    EVP_MD_CTX_free (  ctx  );

    printf (  "SHA-256 (  %s  ):\n  " , label  );
    for  (  int i = 0; i < 32; i++  ) {
        printf (  "%02x" , digest[i]  );
        if  (   (  i + 1  ) % 16 == 0 && i != 31  ) printf (  "\n  "  );
    }
    printf (  "\n\n"  );
}

// Binary comparison with first difference highlighted
void compare_sigs (  unsigned char *a , size_t a_len ,
                  unsigned char *b , size_t b_len  ) {
    printf (  "=== Binary Comparison ===\n"  );
    printf (  "Generated signature length : %zu bytes\n" , a_len  );
    printf (  "Existing  signature length : %zu bytes\n" , b_len  );

    if  (  a_len != b_len  ) {
        printf (  "DIFFER: lengths do not match\n\n"  );
        return;
    }

    int first_diff = -1;
    for  (  size_t i = 0; i < a_len; i++  ) {
        if  (  a[i] != b[i]  ) { first_diff = i; break; }
    }

    if  (  first_diff == -1  ) {
        printf (  "MATCH: signatures are byte-for-byte identical\n\n"  );
    } else {
        printf (  "DIFFER: first difference at byte %d\n" , first_diff  );
        printf (  "  Generated[%d] = 0x%02x\n" , first_diff , a[first_diff]  );
        printf (  "  Existing [%d] = 0x%02x\n\n" , first_diff , b[first_diff]  );
    }
}
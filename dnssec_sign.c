#include "dnssec_sign.h"
/*
 * DNSSEC signature verification tool
 *
 * This program helps validate a reconstructed DNSSEC signature base by:
 *   1. loading a private/public key pair,
 *   2. decoding a reconstructed signature base from hex,
 *   3. decoding an existing RRSIG from base64,
 *   4. generating a fresh signature over the reconstructed input,
 *   5. verifying both signatures with the public key, and
 *   6. comparing the generated and existing signatures byte-for-byte.
 * 
 * 
 * Author: Steven Dormady
 * 
*/


// TODO: Group up main function , make code prettier , add more comments , etc.

// =========================================================================
// Main - driver for all operations
// =========================================================================
int main( int argc , char *argv [] )
{
    // -------------------------------------------------------
    // Argument validation
    // The program needs exactly 4 arguments:
    //   1. private.pem  - private key for signing
    //   2. public.pem   - public key for verification
    //   3. sigbase.hex  - the signature base we constructed
    //   4. rrsig.b64    - the real signature from the zone
    // -------------------------------------------------------
    if ( argc != 5 )
    {
        fprintf( stderr , "Usage: %s <private.pem> <public.pem> <sigbase.hex> <rrsig.b64>\n\n" , argv [ 0 ]  );
        fprintf( stderr , "  private.pem  - private key in PEM format\n" );
        fprintf( stderr , "  public.pem   - public key in PEM format\n" );
        fprintf( stderr , "  sigbase.hex  - signature base as a hex string file\n" );
        fprintf( stderr , "  rrsig.b64    - existing RRSIG signature field as base64 file\n" );
        return EXIT_FAILURE;
    }



    // =========================================================================
    // Load private key
    // This key will be used later to SIGN the signature base.
    EVP_PKEY *privkey = load_private_key( argv [ 1 ] );
    if  ( !privkey )
    {
        return EXIT_FAILURE;
    }

    // Print bit length to confirm we loaded the right key (ZSK 1024 bits, KSK would be 2048 bits)
    printf( "Private key loaded: %d bits\n" , EVP_PKEY_bits( privkey ) );

    // Private key loaded successfully
    // =========================================================================



    // =========================================================================
    // Load public key
    EVP_PKEY *pubkey = load_public_key( argv [ 2 ] );
    if  ( !pubkey )
    {
        fprintf( stderr , "Error: failed to read public key\n" );
        return EXIT_FAILURE;
    }


    printf( "Public key loaded:  %d bits\n\n" , EVP_PKEY_bits( pubkey ) );
    // Public key loaded successfully
    // =========================================================================



    // =========================================================================
    // Load signature base from hex file
    unsigned char *sigbase = NULL;
    size_t sigbase_len = 0;
    if ( !load_sigbase( argv [ 3 ] , &sigbase , &sigbase_len ) )
    {
        return EXIT_FAILURE;
    }
    // signature base is loaded successfully
    // =========================================================================



    // Show the raw bytes so we can visually verify each field
    hexdump( "Signature base ( from hex )" , sigbase , sigbase_len );

    // Hash the signature base with SHA-256 and print the digest.
    print_sha256( "signature base" , sigbase , sigbase_len );

    // ==============================================
    // Load existing RRSIG base64 signature from file
    unsigned char *existing_sig = NULL;
    size_t existing_sig_len = 0;
    if ( !load_sigbase( argv [ 4 ] , &existing_sig , &existing_sig_len ) )
    {
        return EXIT_FAILURE;
    }

    hexdump( "Existing RRSIG signature" , existing_sig , existing_sig_len );
    // Existing RRSIG loaded
    // ==============================================

    
    // All arguments are loaded and ready to go at this point, we have:
    // - privkey : the private key for signing
    // - pubkey  : the public key for verification
    // - sigbase  : the signature base bytes we constructed
    // - existing_sig : the real RRSIG signature bytes from the zone, for comparison

    
    // ==============================
    // Generate the signature
    // ==============================
    unsigned char *gen_sig = NULL;
    size_t gen_sig_len = 0;

    // Sign the sigbase with the private key using SHA-256 and the private key
    EVP_MD_CTX *sign_ctx = EVP_MD_CTX_new ();
    if( !sign_ctx )
    {
        fprintf( stderr , "Error: failed to create signing context\n" );
        return EXIT_FAILURE;
    }

    if (   EVP_DigestSignInit  ( sign_ctx , NULL , HASH_ALGORITHM , NULL , privkey ) != 1 
        || EVP_DigestSignUpdate( sign_ctx , sigbase , sigbase_len ) != 1
        || EVP_DigestSignFinal ( sign_ctx , NULL , &gen_sig_len ) != 1 )
    {
        fprintf( stderr , "Error: signing init failed\n" );
        return EXIT_FAILURE;
    }

    gen_sig = malloc( gen_sig_len );

    // Do final signing step to get the actual signature bytes. This is where the RSA operation happens.
    if ( EVP_DigestSignFinal( sign_ctx , gen_sig , &gen_sig_len ) != 1 )
    {
        fprintf( stderr , "Error: signing final failed\n" );
        return EXIT_FAILURE;
    }
    // ==============================
    // Signature generated
    // ==============================
    
    EVP_MD_CTX_free( sign_ctx );

    hexdump( "Generated signature" , gen_sig , gen_sig_len );

    // ==============================
    // Verify generated signature with public key
    // ==============================
    printf( "=== Verify: generated signature with public key ===\n" );
    EVP_MD_CTX *verify_ctx = EVP_MD_CTX_new ();
    if( !verify_ctx )
    {
        fprintf( stderr , "Error: failed to create verification context\n" );
        return EXIT_FAILURE;
    }

    if (   EVP_DigestVerifyInit  ( verify_ctx , NULL , HASH_ALGORITHM , NULL , pubkey ) == 1 
        && EVP_DigestVerifyUpdate( verify_ctx , sigbase , sigbase_len ) == 1 
        && EVP_DigestVerifyFinal ( verify_ctx , gen_sig , gen_sig_len ) == 1 )
    {
        printf( "PASS: generated signature verifies correctly\n\n" );
    }
    else
    {
        printf( "FAIL: generated signature did not verify\n\n" );
    }
    EVP_MD_CTX_free( verify_ctx );

    // ==============================
    // Verify existing RRSIG with public key
    // ==============================
    printf( "=== Verify: existing RRSIG with public key ===\n" );
    verify_ctx = EVP_MD_CTX_new ();
    if( !verify_ctx )
    {
        fprintf( stderr , "Error: failed to create verification context\n" );
        return EXIT_FAILURE;
    }

    if (   EVP_DigestVerifyInit  ( verify_ctx , NULL , HASH_ALGORITHM , NULL , pubkey ) == 1 
        && EVP_DigestVerifyUpdate( verify_ctx , sigbase , sigbase_len ) == 1 
        && EVP_DigestVerifyFinal ( verify_ctx , existing_sig , existing_sig_len ) == 1 )
    {
        printf( "PASS: existing RRSIG verifies correctly\n\n" );
    }
    else
    {
        printf( "FAIL: existing RRSIG did not verify - sigbase may not match exactly\n\n" );
    }

    EVP_MD_CTX_free( verify_ctx );

    // ==============================
    // Binary comparison
    // Since RSA-PKCS1-v1_5 is deterministic, if the same key
    // signs the same data the output bytes are always identical.
    // A byte-for-byte match here is the strongest possible proof
    // that the reconstruction is correct.
    // ==============================
    compare_sigs( gen_sig , gen_sig_len , existing_sig , existing_sig_len );

    // Cleanup
    free( sigbase );
    free( existing_sig );
    free( gen_sig );
    EVP_PKEY_free( privkey );
    EVP_PKEY_free( pubkey );

    return EXIT_SUCCESS;
}

// ==========================================
// Utility functions below
// ==========================================

// Load a private key from a PEM file using OpenSSL's EVP_PKEY interface
EVP_PKEY *load_private_key( const char *filename )
{
    FILE *f = fopen( filename , "r" );
    if  ( !f )
    { 
        fprintf( stderr , "Error: cannot open private key\n" ); 
        return NULL;
    }

    // Generic PEM reader that can handle both RSA and ECDSA keys, works for RSA in this case
    EVP_PKEY *privkey = PEM_read_PrivateKey( f , NULL , NULL , NULL );
    fclose( f );

    if  ( !privkey )
    { 
        fprintf( stderr , "Error: failed to read private key\n" ); 
        return NULL;
    }

    printf( "Private key loaded: %d bits\n" , EVP_PKEY_bits( privkey ) );
    return privkey;
}

// Load a public key from a PEM file using OpenSSL's EVP_PKEY interface
EVP_PKEY *load_public_key( const char *filename )
{
    FILE *f = fopen( filename , "r" );
    if  ( !f )
    { 
        fprintf( stderr , "Error: cannot open public key\n" ); 
        return NULL;
    }

    // Generic PEM reader that can handle both RSA and ECDSA keys, works for RSA in this case
    EVP_PKEY *pubkey = PEM_read_PUBKEY( f , NULL , NULL , NULL );
    fclose( f );

    if  ( !pubkey )
    { 
        fprintf( stderr , "Error: failed to read public key\n" ); 
        return NULL;
    }

    printf( "Public key loaded:  %d bits\n" , EVP_PKEY_bits( pubkey ) );
    return pubkey;
}

// Load a base64-encoded signature from a file, decode it into binary, 
// and store the result in *sig and *sig_len
bool load_signature( const char *filename , unsigned char **sig , size_t *sig_len )
{
    FILE *f = fopen( filename , "r" );
    if  ( !f )
    { 
        fprintf( stderr , "Error: cannot open signature file\n" );
        return false;
    }

    fseek( f , 0 , SEEK_END );
    long b64_file_len = ftell( f ); // find length of file for allocation
    rewind( f );
    char *b64_str = malloc( b64_file_len + 1 );
    if( !b64_str )
    {
        fprintf( stderr , "Error: memory allocation failed - b64_str\n" );
        fclose( f );
        return false;
    }
    fread( b64_str , 1 , b64_file_len , f );
    fclose( f );
    b64_str [ b64_file_len ]  = 0; // Null-terminate the string

    // Convert the base64 string into binary signature bytes and store for later.
    if ( !b64_to_bin( b64_str , sig , sig_len ) )
    {
        free( b64_str );
        return false;
    }
    free( b64_str );

    return true;
}

// Load a hex-encoded signature base from a file, decode it into binary, 
// and store the result in *sigbase and *sigbase_len
bool load_sigbase( const char *filename , unsigned char **sigbase , size_t *sigbase_len )
{
    FILE *f = fopen( filename , "r" );
    if  ( !f )
    { 
        fprintf( stderr , "Error: cannot open sigbase hex file\n" ); 
        return false; 
    }

    fseek( f , 0 , SEEK_END );
    long hex_file_len = ftell( f ); // find length of file for allocation
    rewind( f );
    char *hex_str = malloc( hex_file_len + 1 );
    if( !hex_str )
    {
        fprintf( stderr , "Error: memory allocation failed - hex_str\n" );
        fclose( f );
        return false;
    }
    fread( hex_str , 1 , hex_file_len , f );
    fclose( f );
    hex_str [ hex_file_len ]  = 0;

    // Strip trailing newline if present
    hex_str [ strcspn( hex_str , "\r\n" ) ]  = 0;

    // Convert the hex string into binary signature base bytes and store for later.
    if ( !hex_to_bin( hex_str , sigbase , sigbase_len ) )
    {
        free( hex_str );
        return false;
    }
    free( hex_str );

    return true;
}


// Decode a hex string into bytes
int hex_to_bin( const char *hex , unsigned char **out , size_t *out_len )
{
    size_t hex_len = strlen( hex );
    if ( hex_len % 2 != 0 )
    {
        fprintf( stderr , "Error: odd hex string length\n" );
        return 0;
    }
    *out_len = hex_len / 2;
    *out = malloc( *out_len );

    // Convert each pair of hex characters into a byte
    for ( size_t i = 0; i < *out_len; i++ )
    {
        unsigned int byte;
        if ( sscanf( hex + ( i * 2 ) , "%02x" , &byte ) != 1 )
        {
            fprintf( stderr , "Error: invalid hex at position %zu\n" , i * 2 );
            free( *out );
            return 0;
        }
        ( *out ) [ i ]  = ( unsigned char )byte;
    }
    return 1;
}

// ==========================================
// Decode a base64 string into bytes ( handles newlines/whitespace )
// Written by Claude, adapted from OpenSSL BIO base64 decoding examples
// Example: "AAEC" -> { 0x00, 0x01, 0x02 }
// ==========================================
int b64_to_bin( const char *b64 , unsigned char **out , size_t *out_len )
{
    // Strip whitespace into a clean buffer
    char *clean = malloc( strlen( b64 ) + 1 );
    int ci = 0;
    for ( int i = 0; b64 [ i ] ; i++ )
    {
        if (   b64 [ i ]  != ' ' && b64 [ i ]  != '\n' 
            && b64 [ i ]  != '\r' && b64 [ i ]  != '\t' )
            {
                clean [ ci++ ]  = b64 [ i ] ;
            }
    }
    clean [ ci ]  = 0;

    size_t bin_len = ( ci * 3 ) / 4 + 4;
    *out = malloc( bin_len );

    BIO *b64_bio = BIO_new( BIO_f_base64 () );
    BIO *mem_bio = BIO_new_mem_buf( clean , -1 );
    BIO_push( b64_bio , mem_bio );
    BIO_set_flags( b64_bio , BIO_FLAGS_BASE64_NO_NL );

    int decoded = BIO_read( b64_bio , *out , bin_len );
    BIO_free_all( b64_bio );
    free( clean );

    if ( decoded <= 0 )
    {
        fprintf( stderr , "Error: base64 decode failed\n" );
        free( *out );
        return 0;
    }

    *out_len = decoded;
    return 1;
}

// ==========================================
// Print a hex dump with ASCII, purely for debugging and cosmetic
// Makes it easier to visually compare the signature base and 
// signatures, and see any differences byte by byte
// ==========================================
void hexdump( const char *label , const unsigned char *data , size_t len )
{
    printf( "\n=== %s ( %zu bytes ) ===\n" , label , len );
    // Print offset, hex bytes, and ASCII representation in a format similar to hexdump -C
    // This loop prints every full line of 16 bytes
    for ( size_t i = 0; i < len; i++ )
    {
        if ( i % 16 == 0 )
        {
            printf( "%04zx  " , i );
        }

        printf( "%02x " , data [ i ]  );

        if ( ( i + 1 ) % 8 == 0 && ( i + 1 ) % 16 != 0 ) 
        {
            printf( " " );
        }

        if ( ( i + 1 ) % 16 == 0 )
        {
            printf( " |" );
            for ( size_t j = i - 15; j <= i; j++ )
            {
                printf( "%c" , ( data [ j ]  >= 32 && data [ j ]  < 127 ) ? data [ j ]  : '.' );
            }
            printf( "|\n" );
        }
    }
    // Handle last partial line
    if ( len % 16 != 0 )
    {
        size_t remaining = len % 16;
        for ( size_t i = 0; i < 16 - remaining; i++ ) 
        {
            printf( "   " );
        }
        if ( remaining <= 8 ) 
        {
            printf( " " );
        }
        printf( " |" );
        for ( size_t i = len - remaining; i < len; i++ )
        {
            printf( "%c" , ( data [ i ]  >= 32 && data [ i ]  < 127 ) ? data [ i ]  : '.' );
        }
        printf( "|\n" );
    }
    printf( "\n" );
}

// ==========================================
// Print the SHA-256 digest of a buffer, purely for debugging and cosmetic
// Helps to see any differences in the signature base or the generated signature at a glance
// ==========================================
void print_sha256( const char *label , unsigned char *data , size_t len )
{
    // == Compute SHA-256 digest ==
    unsigned char digest [ 32 ] ;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new ();
    EVP_DigestInit_ex( ctx , HASH_ALGORITHM , NULL );
    EVP_DigestUpdate( ctx , data , len );

    unsigned int digest_len;
    EVP_DigestFinal_ex( ctx , digest , &digest_len );
    EVP_MD_CTX_free( ctx );

    // == Print the digest ==
    printf( "SHA-256( %s ):\n  " , label );

    for ( int i = 0; i < 32; i++ )
    {
        printf( "%02x" , digest [ i ]  );
        // Line breaks after 16 bytes for readability
        if ( ( i + 1 ) % 16 == 0 && i != 31 ) 
        {
            printf( "\n  " );
        }
    }
    printf( "\n\n" );
}

// ==================================================================
// Compare two signatures byte-by-byte and report the first difference
// Provides a better way to understand how the generated signature differs
// from the existing one, beyond just "verify failed"
// ==================================================================
void compare_sigs ( const unsigned char *a , size_t a_len ,
                  const unsigned char *b , size_t b_len )
{
    printf( "=== Binary Comparison ===\n" );
    printf( "Generated signature length : %zu bytes\n" , a_len );
    printf( "Existing  signature length : %zu bytes\n" , b_len );

    // length check is important because if the lengths differ, 
    // we know right away they can't be identical, and it also 
    // prevents out-of-bounds access in the loop below
    if ( a_len != b_len )
    {
        printf( "DIFFER: lengths do not match\n\n" );
        return;
    }

    // Loop through and compare each byte until we find a difference, 
    // then report the offset and byte values
    int first_diff = -1;
    for ( size_t i = 0; i < a_len; i++ )
    {
        if ( a [ i ]  != b [ i ]  )
        {
            first_diff = i;
            break;
        }
    }

    // If no differences found, the signatures are identical.
    // Otherwise, show the first byte that differs.
    if ( first_diff == -1 )
    {
        printf( "MATCH: signatures are byte-for-byte identical\n\n" );
    } 
    else
    {
        printf( "DIFFER: first difference at byte %d\n" , first_diff );
        printf( "  Generated [ %d ]  = 0x%02x\n" , first_diff , a [ first_diff ]  );
        printf( "  Existing  [ %d ]  = 0x%02x\n\n" , first_diff , b [ first_diff ]  );
    }
}
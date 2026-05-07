/*
 * bind2pem.c
 *
 * Converts BIND9 DNSSEC key files into PEM format using OpenSSL 3.0+.
 *
 * BIND9 generates two files per DNSSEC key pair:
 *   Kexample.com.+008+12345.private  -- the private key in a custom text format
 *   Kexample.com.+008+12345.key      -- the public key as a DNS zone record (DNSKEY RR)
 *
 * This tool reads either file and writes a standard PEM file:
 *   .private  ->  PEM private key  (-----BEGIN PRIVATE KEY-----)
 *   .key      ->  PEM public key   (-----BEGIN PUBLIC KEY-----)
 *
 * Compile:
 *   gcc -o bind2pem bind2pem.c -lssl -lcrypto
 *
 * Usage:
 *   ./bind2pem Kexample.com.+008+12345.private  private.pem
 *   ./bind2pem Kexample.com.+008+12345.key      public.pem
 *
 * Note: Currently supports RSA keys only (algorithms 5 and 8).
 *       ECDSA (algorithm 13) uses a different wire format and is not handled.
 *
 * OpenSSL 3.0 note:
 *   The old RSA_new() / RSA_set0_key() / EVP_PKEY_assign_RSA() API is deprecated.
 *   This file uses the modern EVP_PKEY_fromdata() approach throughout, which
 *   builds keys by passing an OSSL_PARAM array directly — no RSA struct needed.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>        // BIGNUM — arbitrary-precision integers
#include <openssl/pem.h>       // PEM_write_PrivateKey / PEM_write_PUBKEY
#include <openssl/evp.h>       // EVP_PKEY, EVP_PKEY_CTX, EVP_PKEY_fromdata
#include <openssl/core_names.h>// OSSL_PKEY_PARAM_RSA_* constants
#include <openssl/param_build.h>// OSSL_PARAM_BLD — helper for building param arrays

#define MAX_LINE   4096
#define MAX_FIELDS 20

/*
 * Field — a simple key/value pair used to hold one line from a BIND .private file.
 *
 * Example .private file content:
 *   Algorithm: 8 (RSASHA256)
 *   Modulus: AwEAAb3f...
 *   PublicExponent: AQAB
 *   PrivateExponent: ...
 */
typedef struct
{
    char key[ 256 ];
    char value[ 4096 ];
} Field;


// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

/*
 * parse_bind_file()
 *
 * Opens a BIND .private key file and splits each "Key: Value" line into
 * the fields array. Lines without a ": " separator are silently skipped.
 *
 * Returns 1 on success, 0 if the file could not be opened.
 */
int parse_bind_file( const char *filename, Field *fields, int *count )
{
    FILE *f = fopen( filename, "r" );

    if ( !f )
    {
        fprintf( stderr, "Error: cannot open file '%s'\n", filename );
        return 0;
    }

    char line[ MAX_LINE ];
    *count = 0;

    while ( fgets( line, sizeof( line ), f ) )
    {
        // Strip trailing newline / carriage return
        line[ strcspn( line, "\r\n" ) ] = 0;

        // Find the ": " separator between key name and value
        char *sep = strstr( line, ": " );

        if ( !sep )
        {
            continue;   // Skip blank lines, comments, or malformed lines
        }

        *sep = 0;   // Split the string: 'line' is now just the key name

        strncpy( fields[ *count ].key,   line,    255  );
        strncpy( fields[ *count ].value, sep + 2, 4095 ); // sep+2 skips the ": "

        ( *count )++;

        if ( *count >= MAX_FIELDS )
        {
            break;  // Guard against overrunning the fixed-size array
        }
    }

    fclose( f );
    return 1;
}

/*
 * get_field()
 *
 * Linear search through the parsed fields array for a named key.
 * Returns a pointer to the value string, or NULL if not found.
 */
const char *get_field( Field *fields, int count, const char *key )
{
    for ( int i = 0; i < count; i++ )
    {
        if ( strcmp( fields[ i ].key, key ) == 0 )
        {
            return fields[ i ].value;
        }
    }

    return NULL;
}

/*
 * b64_to_bn()
 *
 * Decodes a base64 string and returns it as a BIGNUM (big-endian unsigned integer).
 * BIND stores all RSA components as base64-encoded big-endian byte arrays,
 * which maps directly to what BN_bin2bn() expects.
 *
 * Ownership: the returned BIGNUM must be freed by the caller with BN_free(),
 * unless it is handed to OSSL_PARAM_BLD_push_BN() which takes a reference.
 *
 * Returns NULL on failure.
 */
BIGNUM *b64_to_bn( const char *b64 )
{
    int b64_len = strlen( b64 );
    int bin_len = ( b64_len * 3 ) / 4 + 4; // Upper bound on decoded size

    unsigned char *bin = malloc( bin_len );

    if ( !bin )
    {
        return NULL;
    }

    // Use an OpenSSL BIO chain to base64-decode the string.
    // BIO_f_base64() is the decoder filter; BIO_new_mem_buf() is the data source.
    BIO *b64_bio = BIO_new( BIO_f_base64() );
    BIO *mem_bio = BIO_new_mem_buf( b64, -1 ); // -1 = use strlen internally

    BIO_push( b64_bio, mem_bio );

    // BIO_FLAGS_BASE64_NO_NL: BIND values are single-line strings with no
    // embedded newlines, so tell the decoder not to expect line breaks
    BIO_set_flags( b64_bio, BIO_FLAGS_BASE64_NO_NL );

    int decoded_len = BIO_read( b64_bio, bin, bin_len );

    BIO_free_all( b64_bio ); // Frees both BIOs in the chain

    if ( decoded_len <= 0 )
    {
        free( bin );
        return NULL;
    }

    // Interpret the raw bytes as a big-endian unsigned integer
    BIGNUM *bn = BN_bin2bn( bin, decoded_len, NULL );

    free( bin );
    return bn;
}

/*
 * b64_to_bin()
 *
 * Decodes a base64 string into a raw byte buffer (not a BIGNUM).
 * Used for the DNSKEY wire-format blob in .key files, which packs
 * multiple fields together and must be parsed byte-by-byte.
 *
 * On success: allocates *out, fills it, returns byte count.
 * On failure: sets *out = NULL, returns -1.
 * Caller must free() *out.
 */
int b64_to_bin( const char *b64, unsigned char **out )
{
    int b64_len = strlen( b64 );
    int bin_len = ( b64_len * 3 ) / 4 + 4;

    *out = malloc( bin_len );

    if ( !*out )
    {
        return -1;
    }

    // Same BIO chain as b64_to_bn()
    BIO *b64_bio = BIO_new( BIO_f_base64() );
    BIO *mem_bio = BIO_new_mem_buf( b64, -1 );

    BIO_push( b64_bio, mem_bio );
    BIO_set_flags( b64_bio, BIO_FLAGS_BASE64_NO_NL );

    int decoded_len = BIO_read( b64_bio, *out, bin_len );

    BIO_free_all( b64_bio );

    if ( decoded_len <= 0 )
    {
        free( *out );
        *out = NULL;
        return -1;
    }

    return decoded_len;
}


// ---------------------------------------------------------------------------
// Private key conversion ( .private file )
// ---------------------------------------------------------------------------

/*
 * convert_private()
 *
 * Reads a BIND9 .private file and writes a PEM-encoded RSA private key
 * using the OpenSSL 3.0 EVP_PKEY_fromdata() API (no deprecated RSA_* calls).
 *
 * BIND .private file RSA fields:
 *   Modulus          n   -- the RSA modulus
 *   PublicExponent   e   -- public exponent (almost always 65537)
 *   PrivateExponent  d   -- private exponent
 *   Prime1           p   -- first prime factor
 *   Prime2           q   -- second prime factor
 *   Exponent1        dmp1 = d mod (p-1)   \
 *   Exponent2        dmq1 = d mod (q-1)    > CRT parameters for fast decryption
 *   Coefficient      iqmp = q^-1 mod p    /
 *
 * OpenSSL 3.0 approach:
 *   Instead of RSA_new() + RSA_set0_key() + EVP_PKEY_assign_RSA(), we:
 *     1. Decode each field to a BIGNUM
 *     2. Push all BIGNUMs into an OSSL_PARAM_BLD parameter builder
 *     3. Call EVP_PKEY_fromdata() to build the EVP_PKEY directly
 *   This avoids all deprecated RSA_* functions.
 *
 * Returns 1 on success, 0 on failure.
 */
int convert_private( const char *infile, const char *outfile )
{
    Field fields[ MAX_FIELDS ];
    int   count = 0;

    if ( !parse_bind_file( infile, fields, &count ) )
    {
        return 0;
    }

    const char *algo = get_field( fields, count, "Algorithm" );

    if ( !algo )
    {
        fprintf( stderr, "Error: no Algorithm field found\n" );
        return 0;
    }

    printf( "Algorithm: %s\n", algo );

    // Retrieve all eight RSA component strings from the parsed file
    const char *mod  = get_field( fields, count, "Modulus"         );
    const char *pub  = get_field( fields, count, "PublicExponent"  );
    const char *priv = get_field( fields, count, "PrivateExponent" );
    const char *p1   = get_field( fields, count, "Prime1"          );
    const char *p2   = get_field( fields, count, "Prime2"          );
    const char *e1   = get_field( fields, count, "Exponent1"       );
    const char *e2   = get_field( fields, count, "Exponent2"       );
    const char *coef = get_field( fields, count, "Coefficient"     );

    if ( !mod || !pub || !priv || !p1 || !p2 || !e1 || !e2 || !coef )
    {
        fprintf( stderr, "Error: missing one or more RSA key fields\n" );
        return 0;
    }

    // Decode every base64 field into a BIGNUM
    BIGNUM *n    = b64_to_bn( mod  );   // modulus
    BIGNUM *e    = b64_to_bn( pub  );   // public exponent
    BIGNUM *d    = b64_to_bn( priv );   // private exponent
    BIGNUM *p    = b64_to_bn( p1   );   // prime p
    BIGNUM *q    = b64_to_bn( p2   );   // prime q
    BIGNUM *dmp1 = b64_to_bn( e1   );   // d mod (p-1)
    BIGNUM *dmq1 = b64_to_bn( e2   );   // d mod (q-1)
    BIGNUM *iqmp = b64_to_bn( coef );   // q^-1 mod p

    if ( !n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp )
    {
        fprintf( stderr, "Error: failed to decode one or more key components\n" );
        BN_free( n ); BN_free( e );    BN_free( d );    BN_free( p );
        BN_free( q ); BN_free( dmp1 ); BN_free( dmq1 ); BN_free( iqmp );
        return 0;
    }

    /*
     * Build an OSSL_PARAM array describing the RSA key.
     *
     * OSSL_PARAM_BLD is a helper that lets us push named parameters
     * (using the OSSL_PKEY_PARAM_RSA_* string constants from core_names.h)
     * and then serialise them into an OSSL_PARAM array for EVP_PKEY_fromdata().
     */
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();

    if ( !bld )
    {
        fprintf( stderr, "Error: OSSL_PARAM_BLD_new() failed\n" );
        BN_free( n ); BN_free( e );    BN_free( d );    BN_free( p );
        BN_free( q ); BN_free( dmp1 ); BN_free( dmq1 ); BN_free( iqmp );
        return 0;
    }

    // Push each RSA component into the builder using its OpenSSL parameter name.
    // OSSL_PARAM_BLD_push_BN() does NOT take ownership — BIGNUMs must stay
    // alive until OSSL_PARAM_BLD_to_param() has been called below.
    if ( !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_N,    n    ) ||
         !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_E,    e    ) ||
         !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_D,    d    ) ||
         !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_FACTOR1,   p    ) ||
         !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_FACTOR2,   q    ) ||
         !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_EXPONENT1, dmp1 ) ||
         !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_EXPONENT2, dmq1 ) ||
         !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_COEFFICIENT1, iqmp ) )
    {
        fprintf( stderr, "Error: failed to push RSA parameters into builder\n" );
        OSSL_PARAM_BLD_free( bld );
        BN_free( n ); BN_free( e );    BN_free( d );    BN_free( p );
        BN_free( q ); BN_free( dmp1 ); BN_free( dmq1 ); BN_free( iqmp );
        return 0;
    }

    // Serialise the builder into a flat OSSL_PARAM array
    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param( bld );

    OSSL_PARAM_BLD_free( bld ); // Builder itself is no longer needed

    if ( !params )
    {
        fprintf( stderr, "Error: OSSL_PARAM_BLD_to_param() failed\n" );
        BN_free( n ); BN_free( e );    BN_free( d );    BN_free( p );
        BN_free( q ); BN_free( dmp1 ); BN_free( dmq1 ); BN_free( iqmp );
        return 0;
    }

    /*
     * EVP_PKEY_fromdata() builds an EVP_PKEY from the parameter array.
     * We need a context (EVP_PKEY_CTX) first, specifying "RSA" as the key type.
     * EVP_PKEY_KEYPAIR means we are providing a full key pair (public + private).
     */
    EVP_PKEY_CTX *ctx  = EVP_PKEY_CTX_new_from_name( NULL, "RSA", NULL );
    EVP_PKEY     *pkey = NULL;

    if ( !ctx )
    {
        fprintf( stderr, "Error: EVP_PKEY_CTX_new_from_name() failed\n" );
        OSSL_PARAM_free( params );
        BN_free( n ); BN_free( e );    BN_free( d );    BN_free( p );
        BN_free( q ); BN_free( dmp1 ); BN_free( dmq1 ); BN_free( iqmp );
        return 0;
    }

    if ( EVP_PKEY_fromdata_init( ctx ) <= 0 ||
         EVP_PKEY_fromdata( ctx, &pkey, EVP_PKEY_KEYPAIR, params ) <= 0 )
    {
        fprintf( stderr, "Error: EVP_PKEY_fromdata() failed for private key\n" );
        EVP_PKEY_CTX_free( ctx );
        OSSL_PARAM_free( params );
        BN_free( n ); BN_free( e );    BN_free( d );    BN_free( p );
        BN_free( q ); BN_free( dmp1 ); BN_free( dmq1 ); BN_free( iqmp );
        return 0;
    }

    // Clean up everything that was only needed to build the key
    EVP_PKEY_CTX_free( ctx );
    OSSL_PARAM_free( params );
    BN_free( n ); BN_free( e );    BN_free( d );    BN_free( p );
    BN_free( q ); BN_free( dmp1 ); BN_free( dmq1 ); BN_free( iqmp );

    FILE *out = fopen( outfile, "w" );

    if ( !out )
    {
        fprintf( stderr, "Error: cannot open output file '%s'\n", outfile );
        EVP_PKEY_free( pkey );
        return 0;
    }

    // Write the private key as an unencrypted PEM file.
    // NULL cipher + NULL passphrase = plaintext output.
    // Add an encryption cipher here (e.g. EVP_aes_256_cbc()) to password-protect it.
    if ( PEM_write_PrivateKey( out, pkey, NULL, NULL, 0, NULL, NULL ) != 1 )
    {
        fprintf( stderr, "Error: PEM_write_PrivateKey failed\n" );
        fclose( out );
        EVP_PKEY_free( pkey );
        return 0;
    }

    fclose( out );
    EVP_PKEY_free( pkey );

    printf( "Success: private key written to %s\n", outfile );
    return 1;
}


// ---------------------------------------------------------------------------
// Public key conversion ( .key file )
// ---------------------------------------------------------------------------

/*
 * convert_public()
 *
 * Reads a BIND9 .key file (a DNS zone file with a DNSKEY record) and writes
 * a PEM-encoded RSA public key using the OpenSSL 3.0 EVP_PKEY_fromdata() API.
 *
 * A BIND .key file looks like:
 *
 *   ; This is a zone-signing key, keyid 12345, for example.com.
 *   example.com. 3600 IN DNSKEY 256 3 8 AwEAAb3f...==
 *
 * DNSKEY record fields:
 *   flags     256 = ZSK (zone-signing key), 257 = KSK (key-signing key)
 *   protocol  always 3 for DNSSEC
 *   algorithm 8 = RSASHA256, 5 = RSASHA1, etc.
 *   blob      base64-encoded public key in RFC 3110 wire format
 *
 * RSA DNSKEY wire format (RFC 3110 section 2):
 *   byte  0:       if != 0 -> exponent length in bytes
 *   byte  0:       if == 0 -> bytes 1+2 are a 16-bit big-endian exponent length
 *   bytes [offset .. offset+exp_len-1]:  public exponent e
 *   bytes [offset+exp_len .. end]:       modulus n
 *
 * Returns 1 on success, 0 on failure.
 */
int convert_public( const char *infile, const char *outfile )
{
    FILE *f = fopen( infile, "r" );

    if ( !f )
    {
        fprintf( stderr, "Error: cannot open '%s'\n", infile );
        return 0;
    }

    char line[ MAX_LINE ];
    char full_b64[ 4096 ] = { 0 };  // Accumulates the complete base64 key blob
    int  found = 0;

    while ( fgets( line, sizeof( line ), f ) )
    {
        // BIND .key files start with "; " comment lines — skip them
        if ( line[ 0 ] == ';' )
        {
            continue;
        }

        line[ strcspn( line, "\r\n" ) ] = 0;

        // Find the DNSKEY keyword on this line
        char *dnskey = strstr( line, "DNSKEY" );

        if ( !dnskey )
        {
            continue;
        }

        // Tokenize: name TTL IN DNSKEY flags protocol algorithm blob...
        // strtok splits on spaces/tabs and modifies the string in place
        char *token = strtok( dnskey, " \t" );  // "DNSKEY"

        token = strtok( NULL, " \t" );           // flags
        printf( "Flags: %s\n", token );

        token = strtok( NULL, " \t" );           // protocol (skip, always 3)
        token = strtok( NULL, " \t" );           // algorithm number
        printf( "Algorithm: %s\n", token );

        // Collect all remaining tokens on this line as the start of the base64 blob
        token = strtok( NULL, " \t" );

        while ( token != NULL )
        {
            strncat( full_b64, token, sizeof( full_b64 ) - strlen( full_b64 ) - 1 );
            token = strtok( NULL, " \t" );
        }

        found = 1;

        // BIND may line-wrap the base64 blob — read and append any continuation lines
        long pos;

        while ( ( pos = ftell( f ) ), fgets( line, sizeof( line ), f ) )
        {
            line[ strcspn( line, "\r\n" ) ] = 0;

            // A comment or blank line marks the end of this record
            if ( line[ 0 ] == ';' || strlen( line ) == 0 )
            {
                break;
            }

            // If we hit another DNS record, rewind the file position so it
            // isn't consumed and can be parsed by a future iteration
            if ( strstr( line, "DNSKEY" ) || strstr( line, "IN " ) )
            {
                fseek( f, pos, SEEK_SET );
                break;
            }

            // Strip leading whitespace before appending the continuation chunk
            char *p = line;

            while ( *p == ' ' || *p == '\t' )
            {
                p++;
            }

            strncat( full_b64, p, sizeof( full_b64 ) - strlen( full_b64 ) - 1 );
        }

        break;  // Only process the first DNSKEY record in the file
    }

    fclose( f );

    if ( !found || strlen( full_b64 ) == 0 )
    {
        fprintf( stderr, "Error: no DNSKEY record found in '%s'\n", infile );
        return 0;
    }

    printf( "Full base64 blob (%zu chars)\n", strlen( full_b64 ) );

    // Decode the full base64 blob into raw bytes (the RFC 3110 wire format)
    unsigned char *blob     = NULL;
    int            blob_len = b64_to_bin( full_b64, &blob );

    if ( blob_len < 4 )
    {
        fprintf( stderr, "Error: key blob too short (%d bytes)\n", blob_len );
        free( blob );
        return 0;
    }

    printf( "Decoded blob: %d bytes = %d bits\n", blob_len, blob_len * 8 );

    /*
     * Parse the RSA wire format (RFC 3110 §2):
     *
     *   blob[0] != 0  ->  exp_len = blob[0],              data starts at byte 1
     *   blob[0] == 0  ->  exp_len = blob[1]<<8 | blob[2], data starts at byte 3
     *
     * The exponent e is followed immediately by the modulus n.
     */
    int exp_len, offset;

    if ( blob[ 0 ] == 0 )
    {
        // Rare: exponent longer than 255 bytes, length encoded in next two bytes
        exp_len = ( blob[ 1 ] << 8 ) | blob[ 2 ];
        offset  = 3;
    }
    else
    {
        // Common case: e.g. e=65537 needs only 3 bytes, length fits in one byte
        exp_len = blob[ 0 ];
        offset  = 1;
    }

    int mod_len = blob_len - offset - exp_len;  // Modulus fills the rest of the blob

    printf( "Exponent: %d bytes, Modulus: %d bytes = %d bits\n",
            exp_len, mod_len, mod_len * 8 );

    if ( mod_len <= 0 )
    {
        fprintf( stderr, "Error: malformed key blob — modulus length is %d\n", mod_len );
        free( blob );
        return 0;
    }

    // Extract e and n as BIGNUMs from their positions in the wire-format blob
    BIGNUM *e = BN_bin2bn( blob + offset,           exp_len, NULL );  // exponent
    BIGNUM *n = BN_bin2bn( blob + offset + exp_len, mod_len, NULL );  // modulus

    free( blob );   // Raw wire-format bytes no longer needed

    if ( !e || !n )
    {
        fprintf( stderr, "Error: failed to parse exponent/modulus from blob\n" );
        BN_free( e );
        BN_free( n );
        return 0;
    }

    /*
     * Build the public key using EVP_PKEY_fromdata().
     * A public key only needs n and e — no private components.
     * EVP_PKEY_PUBLIC_KEY tells OpenSSL we are supplying a public-only key.
     */
    OSSL_PARAM_BLD *bld = OSSL_PARAM_BLD_new();

    if ( !bld )
    {
        fprintf( stderr, "Error: OSSL_PARAM_BLD_new() failed\n" );
        BN_free( e );
        BN_free( n );
        return 0;
    }

    if ( !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_N, n ) ||
         !OSSL_PARAM_BLD_push_BN( bld, OSSL_PKEY_PARAM_RSA_E, e ) )
    {
        fprintf( stderr, "Error: failed to push RSA parameters into builder\n" );
        OSSL_PARAM_BLD_free( bld );
        BN_free( e );
        BN_free( n );
        return 0;
    }

    OSSL_PARAM *params = OSSL_PARAM_BLD_to_param( bld );

    OSSL_PARAM_BLD_free( bld );

    if ( !params )
    {
        fprintf( stderr, "Error: OSSL_PARAM_BLD_to_param() failed\n" );
        BN_free( e );
        BN_free( n );
        return 0;
    }

    EVP_PKEY_CTX *ctx  = EVP_PKEY_CTX_new_from_name( NULL, "RSA", NULL );
    EVP_PKEY     *pkey = NULL;

    if ( !ctx )
    {
        fprintf( stderr, "Error: EVP_PKEY_CTX_new_from_name() failed\n" );
        OSSL_PARAM_free( params );
        BN_free( e );
        BN_free( n );
        return 0;
    }

    if ( EVP_PKEY_fromdata_init( ctx ) <= 0 ||
         EVP_PKEY_fromdata( ctx, &pkey, EVP_PKEY_PUBLIC_KEY, params ) <= 0 )
    {
        fprintf( stderr, "Error: EVP_PKEY_fromdata() failed for public key\n" );
        EVP_PKEY_CTX_free( ctx );
        OSSL_PARAM_free( params );
        BN_free( e );
        BN_free( n );
        return 0;
    }

    EVP_PKEY_CTX_free( ctx );
    OSSL_PARAM_free( params );
    BN_free( e );
    BN_free( n );

    FILE *out = fopen( outfile, "w" );

    if ( !out )
    {
        fprintf( stderr, "Error: cannot open output file '%s'\n", outfile );
        EVP_PKEY_free( pkey );
        return 0;
    }

    // PEM_write_PUBKEY writes a "PUBLIC KEY" block (PKCS#8 SubjectPublicKeyInfo).
    // This is preferred over PEM_write_RSAPublicKey ("RSA PUBLIC KEY") because
    // the PKCS#8 format includes the algorithm identifier and is more widely supported.
    if ( PEM_write_PUBKEY( out, pkey ) != 1 )
    {
        fprintf( stderr, "Error: PEM_write_PUBKEY failed\n" );
        fclose( out );
        EVP_PKEY_free( pkey );
        return 0;
    }

    fclose( out );
    EVP_PKEY_free( pkey );

    printf( "Success: public key written to %s\n", outfile );
    return 1;
}


// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/*
 * main()
 *
 * Detects the input file type from its extension and routes to the
 * appropriate converter:
 *   .private  ->  convert_private()  ->  PEM private key
 *   .key      ->  convert_public()   ->  PEM public key
 *
 * Exits 0 on success, 1 on any error.
 */
int main( int argc, char *argv[] )
{
    if ( argc != 3 )
    {
        fprintf( stderr, "Usage: %s <input.private|input.key> <output.pem>\n", argv[ 0 ] );
        fprintf( stderr, "  .private  ->  PEM private key\n" );
        fprintf( stderr, "  .key      ->  PEM public key\n"  );
        return 1;
    }

    const char *infile = argv[ 1 ];
    size_t      len    = strlen( infile );

    // Match the extension by checking the tail of the filename string,
    // so it works correctly regardless of path length or key name length
    if ( len > 8 && strcmp( infile + len - 8, ".private" ) == 0 )
    {
        return convert_private( infile, argv[ 2 ] ) ? 0 : 1;
    }
    else if ( len > 4 && strcmp( infile + len - 4, ".key" ) == 0 )
    {
        return convert_public( infile, argv[ 2 ] ) ? 0 : 1;
    }
    else
    {
        fprintf( stderr, "Error: unrecognised file extension\n" );
        fprintf( stderr, "File must end in .private or .key\n" );
        return 1;
    }
}
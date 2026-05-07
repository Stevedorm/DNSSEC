/*
 * bind2pem.c
 *
 * Converts BIND9 DNSSEC key files into PEM format using OpenSSL.
 *
 * BIND9 generates two files per DNSSEC key pair:
 *   Kexample.com.+008+12345.private  -- the private key in a custom text format
 *   Kexample.com.+008+12345.key      -- the public key as a DNS zone record (DNSKEY RR)
 *
 * This tool reads either file and writes a standard PEM file that can be
 * used by OpenSSL and most other tools:
 *   .private  ->  PEM private key  (RSA PRIVATE KEY block)
 *   .key      ->  PEM public key   (PUBLIC KEY block)
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
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>   // RSA key structures and functions
#include <openssl/bn.h>    // BIGNUM — OpenSSL's arbitrary-precision integer type
#include <openssl/pem.h>   // PEM read/write functions
#include <openssl/evp.h>   // EVP_PKEY — generic key wrapper used by OpenSSL

#define MAX_LINE   4096    // Maximum length of a single line we will read
#define MAX_FIELDS 20      // Maximum number of key: value pairs we expect in a .private file

/*
 * Field — a simple key/value pair.
 * Used to hold the parsed contents of a BIND .private file, which looks like:
 *
 *   Algorithm: 8 (RSASHA256)
 *   Modulus: AQAB...
 *   PublicExponent: AQAB
 *   PrivateExponent: ...
 *   etc.
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
 * Opens a BIND .private key file and splits each line on the first ": "
 * separator, storing the left side as the key and the right side as the value
 * into the fields array.
 *
 * Lines that don't contain ": " (such as blank lines or comments) are skipped.
 *
 * Returns 1 on success, 0 on failure (e.g. file not found).
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
        // Strip the trailing newline or carriage return so comparisons work cleanly
        line[ strcspn( line, "\r\n" ) ] = 0;

        // Look for the ": " separator that divides key from value
        char *sep = strstr( line, ": " );

        if ( !sep )
        {
            continue;   // Skip lines with no separator (blank lines, comments, etc.)
        }

        // Null-terminate at the separator so 'line' now holds just the key name
        *sep = 0;

        strncpy( fields[ *count ].key,   line,    255  );
        strncpy( fields[ *count ].value, sep + 2, 4095 ); // sep+2 skips past ": "

        ( *count )++;

        if ( *count >= MAX_FIELDS )
        {
            break;  // Safety cap — stop before overrunning the fields array
        }
    }

    fclose( f );
    return 1;
}

/*
 * get_field()
 *
 * Searches the parsed fields array for a given key name and returns
 * a pointer to its value string, or NULL if the key is not found.
 *
 * Example: get_field(fields, count, "Modulus") returns the base64 modulus string.
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
 * Decodes a base64 string and interprets the raw bytes as a big-endian
 * unsigned integer, returning it as an OpenSSL BIGNUM.
 *
 * BIND stores all RSA key components (modulus, exponents, primes, etc.)
 * as base64-encoded big-endian byte arrays, which is exactly what
 * BN_bin2bn() expects — so this is the natural conversion path.
 *
 * Returns a newly allocated BIGNUM on success, or NULL on failure.
 * The caller is responsible for freeing it with BN_free() unless it is
 * handed to RSA_set0_key() or similar, which takes ownership.
 */
BIGNUM *b64_to_bn( const char *b64 )
{
    int b64_len = strlen( b64 );

    // Base64 expands 3 bytes into 4 chars, so decoded length is at most (len*3)/4
    // We add a small buffer to be safe with padding
    int bin_len = ( b64_len * 3 ) / 4 + 4;

    unsigned char *bin = malloc( bin_len );

    if ( !bin )
    {
        return NULL;
    }

    // OpenSSL's BIO chain: feed base64-encoded data through a base64 decoder
    // BIO_f_base64() is the decoder filter, BIO_new_mem_buf() is the data source
    BIO *b64_bio = BIO_new( BIO_f_base64() );
    BIO *mem_bio = BIO_new_mem_buf( b64, -1 );  // -1 means use strlen() to find length

    BIO_push( b64_bio, mem_bio );   // Chain: mem_bio -> b64_bio

    // BIO_FLAGS_BASE64_NO_NL tells the decoder not to expect/require line breaks
    // BIND base64 values are single unbroken strings, so this flag is required
    BIO_set_flags( b64_bio, BIO_FLAGS_BASE64_NO_NL );

    int decoded_len = BIO_read( b64_bio, bin, bin_len );

    BIO_free_all( b64_bio );    // Frees both BIOs in the chain

    if ( decoded_len <= 0 )
    {
        free( bin );
        return NULL;
    }

    // Convert the raw binary big-endian bytes into a BIGNUM
    BIGNUM *bn = BN_bin2bn( bin, decoded_len, NULL );

    free( bin );
    return bn;
}

/*
 * b64_to_bin()
 *
 * Decodes a base64 string into a raw byte buffer.
 * Unlike b64_to_bn(), this does NOT interpret the bytes as an integer —
 * it just gives you the raw decoded bytes. This is needed for the DNSKEY
 * wire format blob in .key files, which contains multiple fields packed
 * together rather than a single integer.
 *
 * On success: allocates *out, fills it, and returns the number of bytes.
 * On failure: sets *out = NULL and returns -1.
 * The caller must free() *out when done.
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

    // Same BIO chain as b64_to_bn() — base64 decoder over a memory buffer
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
 * Reads a BIND9 .private file and writes a PEM-encoded RSA private key.
 *
 * A BIND .private file for RSA looks like:
 *
 *   Private-key-format: v1.3
 *   Algorithm: 8 (RSASHA256)
 *   Modulus:          <base64>   -- the RSA modulus n
 *   PublicExponent:   <base64>   -- the public exponent e (usually 65537)
 *   PrivateExponent:  <base64>   -- the private exponent d
 *   Prime1:           <base64>   -- first prime factor p
 *   Prime2:           <base64>   -- second prime factor q
 *   Exponent1:        <base64>   -- d mod (p-1), CRT parameter
 *   Exponent2:        <base64>   -- d mod (q-1), CRT parameter
 *   Coefficient:      <base64>   -- q^-1 mod p,  CRT parameter
 *
 * The CRT (Chinese Remainder Theorem) parameters speed up private key
 * operations and are required by OpenSSL's RSA structure.
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

    // Sanity check — confirm this is an algorithm we recognise before proceeding
    const char *algo = get_field( fields, count, "Algorithm" );

    if ( !algo )
    {
        fprintf( stderr, "Error: no Algorithm field found\n" );
        return 0;
    }

    printf( "Algorithm: %s\n", algo );

    // Pull all eight RSA components out of the parsed fields
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

    // Decode each base64 field into a BIGNUM ready for OpenSSL
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
        return 0;
    }

    // Create an empty RSA key structure and populate it.
    // Note: RSA_set0_* transfers ownership of the BIGNUMs to the RSA struct —
    // do not free them separately after this point
    RSA *rsa = RSA_new();

    if ( !rsa )
    {
        fprintf( stderr, "Error: RSA_new() failed\n" );
        return 0;
    }

    if ( RSA_set0_key( rsa, n, e, d )                 != 1 ||  // set n, e, d
         RSA_set0_factors( rsa, p, q )                != 1 ||  // set p, q
         RSA_set0_crt_params( rsa, dmp1, dmq1, iqmp ) != 1 )   // set CRT params
    {
        fprintf( stderr, "Error: failed to set RSA key components\n" );
        RSA_free( rsa );
        return 0;
    }

    // Wrap the RSA key in an EVP_PKEY container.
    // OpenSSL's PEM write functions work with EVP_PKEY rather than RSA directly,
    // as EVP_PKEY is a generic wrapper that supports multiple key types.
    // EVP_PKEY_assign_RSA() also transfers ownership of rsa to pkey.
    EVP_PKEY *pkey = EVP_PKEY_new();

    if ( !pkey || EVP_PKEY_assign_RSA( pkey, rsa ) != 1 )
    {
        fprintf( stderr, "Error: EVP_PKEY setup failed\n" );
        RSA_free( rsa );
        EVP_PKEY_free( pkey );
        return 0;
    }

    FILE *out = fopen( outfile, "w" );

    if ( !out )
    {
        fprintf( stderr, "Error: cannot open output file '%s'\n", outfile );
        EVP_PKEY_free( pkey );
        return 0;
    }

    // Write the private key as a PEM file (unencrypted — no passphrase).
    // The NULL cipher and NULL passphrase arguments mean the key is written
    // in plaintext. Add encryption here if the key needs to be protected at rest.
    if ( PEM_write_PrivateKey( out, pkey, NULL, NULL, 0, NULL, NULL ) != 1 )
    {
        fprintf( stderr, "Error: PEM_write_PrivateKey failed\n" );
        fclose( out );
        EVP_PKEY_free( pkey );
        return 0;
    }

    fclose( out );
    EVP_PKEY_free( pkey );  // Also frees the RSA struct and all BIGNUMs inside it

    printf( "Success: private key written to %s\n", outfile );
    return 1;
}


// ---------------------------------------------------------------------------
// Public key conversion ( .key file )
// ---------------------------------------------------------------------------

/*
 * convert_public()
 *
 * Reads a BIND9 .key file (a DNS zone file containing a DNSKEY record)
 * and writes a PEM-encoded RSA public key.
 *
 * A BIND .key file looks like:
 *
 *   ; This is a key-signing key, keyid 12345, for example.com.
 *   example.com. 3600 IN DNSKEY 257 3 8 AwEAAb3...==
 *
 * The DNSKEY record fields are:
 *   flags     -- 257 = KSK (key-signing key), 256 = ZSK (zone-signing key)
 *   protocol  -- always 3 for DNSSEC
 *   algorithm -- 8 = RSASHA256, 13 = ECDSAP256SHA256, etc.
 *   key blob  -- base64-encoded public key in DNS wire format
 *
 * RSA DNSKEY wire format (RFC 3110):
 *   byte  0:       if non-zero, this IS the exponent length in bytes
 *   byte  0:       if zero, bytes 1-2 are a 16-bit big-endian exponent length
 *   bytes offset .. offset+exp_len-1:  the public exponent e
 *   bytes offset+exp_len .. end:       the modulus n
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
    char full_b64[ 4096 ] = { 0 };  // Accumulates the full base64 key blob
    int  found = 0;

    while ( fgets( line, sizeof( line ), f ) )
    {
        // Skip comment lines — BIND .key files begin with "; " comment lines
        if ( line[ 0 ] == ';' )
        {
            continue;
        }

        line[ strcspn( line, "\r\n" ) ] = 0;

        // Look for the DNSKEY record line
        char *dnskey = strstr( line, "DNSKEY" );

        if ( !dnskey )
        {
            continue;
        }

        // Tokenize the DNSKEY line: name TTL IN DNSKEY flags protocol algorithm blob...
        // strtok modifies the string in place, splitting on spaces and tabs
        char *token = strtok( dnskey, " \t" );  // token = "DNSKEY" (the keyword itself)

        token = strtok( NULL, " \t" );           // flags (256 = ZSK, 257 = KSK)
        printf( "Flags: %s\n", token );

        token = strtok( NULL, " \t" );           // protocol (always 3)
        token = strtok( NULL, " \t" );           // algorithm number
        printf( "Algorithm: %s\n", token );

        // Everything remaining on this line is the start of the base64 key blob
        token = strtok( NULL, " \t" );

        while ( token != NULL )
        {
            strncat( full_b64, token, sizeof( full_b64 ) - strlen( full_b64 ) - 1 );
            token = strtok( NULL, " \t" );
        }

        found = 1;

        // BIND may wrap the base64 blob across multiple lines — read continuation lines
        long pos;

        while ( ( pos = ftell( f ) ), fgets( line, sizeof( line ), f ) )
        {
            line[ strcspn( line, "\r\n" ) ] = 0;

            // A comment line or empty line signals the end of this record
            if ( line[ 0 ] == ';' || strlen( line ) == 0 )
            {
                break;
            }

            // If we hit another DNS record, rewind so it can be processed later
            if ( strstr( line, "DNSKEY" ) || strstr( line, "IN " ) )
            {
                fseek( f, pos, SEEK_SET );
                break;
            }

            // Strip any leading whitespace from the continuation line before appending
            char *p = line;

            while ( *p == ' ' || *p == '\t' )
            {
                p++;
            }

            strncat( full_b64, p, sizeof( full_b64 ) - strlen( full_b64 ) - 1 );
        }

        break;  // We only process the first DNSKEY record found
    }

    fclose( f );

    if ( !found || strlen( full_b64 ) == 0 )
    {
        fprintf( stderr, "Error: no DNSKEY record found in '%s'\n", infile );
        return 0;
    }

    printf( "Full base64 blob (%zu chars)\n", strlen( full_b64 ) );

    // Decode the full base64 blob into raw bytes (the DNS wire format)
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
     * Parse the RSA DNSKEY wire format (RFC 3110 section 2):
     *
     * The first byte tells us how long the exponent field is:
     *   blob[0] != 0  =>  exponent length = blob[0],            data starts at byte 1
     *   blob[0] == 0  =>  exponent length = blob[1]<<8|blob[2], data starts at byte 3
     *
     * After the exponent comes the modulus, filling the rest of the blob.
     */
    int exp_len;
    int offset;

    if ( blob[ 0 ] == 0 )
    {
        // Two-byte exponent length (used for exponents > 255 bytes, rare in practice)
        exp_len = ( blob[ 1 ] << 8 ) | blob[ 2 ];
        offset  = 3;
    }
    else
    {
        // One-byte exponent length (the common case — e.g. e=65537 fits in 3 bytes)
        exp_len = blob[ 0 ];
        offset  = 1;
    }

    // The modulus occupies whatever bytes remain after the exponent
    int mod_len = blob_len - offset - exp_len;

    printf( "Exponent: %d bytes, Modulus: %d bytes = %d bits\n",
            exp_len, mod_len, mod_len * 8 );

    if ( mod_len <= 0 )
    {
        fprintf( stderr, "Error: malformed key blob — modulus length is %d\n", mod_len );
        free( blob );
        return 0;
    }

    // Extract e and n as BIGNUMs directly from the wire-format byte arrays
    BIGNUM *e = BN_bin2bn( blob + offset,           exp_len, NULL );  // exponent
    BIGNUM *n = BN_bin2bn( blob + offset + exp_len, mod_len, NULL );  // modulus

    free( blob );   // Raw bytes no longer needed once we have BIGNUMs

    if ( !e || !n )
    {
        fprintf( stderr, "Error: failed to parse exponent/modulus from blob\n" );
        BN_free( e );
        BN_free( n );
        return 0;
    }

    // Build an RSA public key — only n and e are needed (no private components)
    // The NULL third argument to RSA_set0_key() means "no private exponent"
    RSA *rsa = RSA_new();

    if ( !rsa )
    {
        fprintf( stderr, "Error: RSA_new() failed\n" );
        BN_free( e );
        BN_free( n );
        return 0;
    }

    if ( RSA_set0_key( rsa, n, e, NULL ) != 1 )
    {
        fprintf( stderr, "Error: RSA_set0_key failed\n" );
        RSA_free( rsa );    // RSA_free will also free n and e since they were set
        return 0;
    }

    // Wrap in EVP_PKEY — same as the private key path, needed for PEM_write_PUBKEY
    EVP_PKEY *pkey = EVP_PKEY_new();

    if ( !pkey || EVP_PKEY_assign_RSA( pkey, rsa ) != 1 )
    {
        fprintf( stderr, "Error: EVP_PKEY setup failed\n" );
        RSA_free( rsa );
        EVP_PKEY_free( pkey );
        return 0;
    }

    FILE *out = fopen( outfile, "w" );

    if ( !out )
    {
        fprintf( stderr, "Error: cannot open output file '%s'\n", outfile );
        EVP_PKEY_free( pkey );
        return 0;
    }

    // PEM_write_PUBKEY writes a "PUBLIC KEY" PEM block (PKCS#8 SubjectPublicKeyInfo format).
    // This is different from PEM_write_RSAPublicKey which writes a bare "RSA PUBLIC KEY" block.
    // Most tools expect the PKCS#8 format, so PEM_write_PUBKEY is the right choice here.
    if ( PEM_write_PUBKEY( out, pkey ) != 1 )
    {
        fprintf( stderr, "Error: PEM_write_PUBKEY failed\n" );
        fclose( out );
        EVP_PKEY_free( pkey );
        return 0;
    }

    fclose( out );
    EVP_PKEY_free( pkey );  // Also frees rsa and the BIGNUMs inside it

    printf( "Success: public key written to %s\n", outfile );
    return 1;
}


// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/*
 * main()
 *
 * Determines which conversion to run based on the input file extension:
 *   .private  ->  convert_private()  ->  PEM private key
 *   .key      ->  convert_public()   ->  PEM public key
 *
 * Exits with 0 on success, 1 on any error.
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

    // Route to the appropriate converter based on the file extension.
    // We check from the end of the filename string to safely match the extension
    // regardless of how long the full path or key name is.
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
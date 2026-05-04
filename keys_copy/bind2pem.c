#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

#define MAX_LINE 4096
#define MAX_FIELDS 20

typedef struct {
    char key[256];
    char value[4096];
} Field;

// ---------------------------------------------------------------------------
// Shared utilities
// ---------------------------------------------------------------------------

int parse_bind_file(const char *filename, Field *fields, int *count) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: cannot open file '%s'\n", filename);
        return 0;
    }

    char line[MAX_LINE];
    *count = 0;

    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = 0;
        char *sep = strstr(line, ": ");
        if (!sep) continue;
        *sep = 0;
        strncpy(fields[*count].key, line, 255);
        strncpy(fields[*count].value, sep + 2, 4095);
        (*count)++;
        if (*count >= MAX_FIELDS) break;
    }

    fclose(f);
    return 1;
}

const char *get_field(Field *fields, int count, const char *key) {
    for (int i = 0; i < count; i++)
        if (strcmp(fields[i].key, key) == 0)
            return fields[i].value;
    return NULL;
}

BIGNUM *b64_to_bn(const char *b64) {
    int b64_len = strlen(b64);
    int bin_len = (b64_len * 3) / 4 + 4;
    unsigned char *bin = malloc(bin_len);
    if (!bin) return NULL;

    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new_mem_buf(b64, -1);
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_len = BIO_read(b64_bio, bin, bin_len);
    BIO_free_all(b64_bio);

    if (decoded_len <= 0) { free(bin); return NULL; }

    BIGNUM *bn = BN_bin2bn(bin, decoded_len, NULL);
    free(bin);
    return bn;
}

// Base64 decode into a raw buffer, returns length
int b64_to_bin(const char *b64, unsigned char **out) {
    int b64_len = strlen(b64);
    int bin_len = (b64_len * 3) / 4 + 4;
    *out = malloc(bin_len);
    if (!*out) return -1;

    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new_mem_buf(b64, -1);
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_len = BIO_read(b64_bio, *out, bin_len);
    BIO_free_all(b64_bio);

    if (decoded_len <= 0) { free(*out); *out = NULL; return -1; }
    return decoded_len;
}

// ---------------------------------------------------------------------------
// Private key conversion (.private file)
// ---------------------------------------------------------------------------

int convert_private(const char *infile, const char *outfile) {
    Field fields[MAX_FIELDS];
    int count = 0;
    if (!parse_bind_file(infile, fields, &count)) return 0;

    const char *algo = get_field(fields, count, "Algorithm");
    if (!algo) { fprintf(stderr, "Error: no Algorithm field\n"); return 0; }
    printf("Algorithm: %s\n", algo);

    const char *mod  = get_field(fields, count, "Modulus");
    const char *pub  = get_field(fields, count, "PublicExponent");
    const char *priv = get_field(fields, count, "PrivateExponent");
    const char *p1   = get_field(fields, count, "Prime1");
    const char *p2   = get_field(fields, count, "Prime2");
    const char *e1   = get_field(fields, count, "Exponent1");
    const char *e2   = get_field(fields, count, "Exponent2");
    const char *coef = get_field(fields, count, "Coefficient");

    if (!mod || !pub || !priv || !p1 || !p2 || !e1 || !e2 || !coef) {
        fprintf(stderr, "Error: missing RSA fields\n");
        return 0;
    }

    BIGNUM *n    = b64_to_bn(mod);
    BIGNUM *e    = b64_to_bn(pub);
    BIGNUM *d    = b64_to_bn(priv);
    BIGNUM *p    = b64_to_bn(p1);
    BIGNUM *q    = b64_to_bn(p2);
    BIGNUM *dmp1 = b64_to_bn(e1);
    BIGNUM *dmq1 = b64_to_bn(e2);
    BIGNUM *iqmp = b64_to_bn(coef);

    if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp) {
        fprintf(stderr, "Error: failed to decode key components\n");
        return 0;
    }

    RSA *rsa = RSA_new();
    if (RSA_set0_key(rsa, n, e, d) != 1 ||
        RSA_set0_factors(rsa, p, q) != 1 ||
        RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) != 1) {
        fprintf(stderr, "Error: failed to set RSA components\n");
        RSA_free(rsa);
        return 0;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    FILE *out = fopen(outfile, "w");
    if (!out) { fprintf(stderr, "Error: cannot open output file\n"); return 0; }
    PEM_write_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL);
    fclose(out);
    EVP_PKEY_free(pkey);

    printf("Success: private key written to %s\n", outfile);
    return 1;
}

// ---------------------------------------------------------------------------
// Public key conversion (.key file)
// DNSKEY wire format for RSA:
//   if blob[0] == 0: exponent length is 2 bytes at blob[1..2]
//   else:            exponent length is blob[0]
//   followed by:     exponent bytes, then modulus bytes
// ---------------------------------------------------------------------------

int convert_public(const char *infile, const char *outfile) {
    FILE *f = fopen(infile, "r");
    if (!f) { fprintf(stderr, "Error: cannot open '%s'\n", infile); return 0; }

    char line[MAX_LINE];
    char full_b64[4096] = {0};
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        // Skip comment lines
        if (line[0] == ';') continue;
        line[strcspn(line, "\r\n")] = 0;

        char *dnskey = strstr(line, "DNSKEY");
        if (!dnskey) continue;

        // Tokenize: name TTL IN DNSKEY flags proto algo blob...
        char *token = strtok(dnskey, " \t");  // "DNSKEY"
        token = strtok(NULL, " \t");           // flags
        printf("Flags: %s\n", token);
        token = strtok(NULL, " \t");           // protocol
        token = strtok(NULL, " \t");           // algorithm
        printf("Algorithm: %s\n", token);

        // Collect remaining tokens on this line
        token = strtok(NULL, " \t");
        while (token != NULL) {
            strncat(full_b64, token, sizeof(full_b64) - strlen(full_b64) - 1);
            token = strtok(NULL, " \t");
        }

        found = 1;

        // Now read any continuation lines (non-comment, non-empty, no DNSKEY keyword)
        // These are the wrapped base64 lines
        long pos;
        while ((pos = ftell(f)), fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = 0;

            // Stop if we hit a comment or a new record
            if (line[0] == ';' || strlen(line) == 0) break;
            if (strstr(line, "DNSKEY") || strstr(line, "IN ")) {
                // Rewind so we don't consume a new record
                fseek(f, pos, SEEK_SET);
                break;
            }

            // Strip all whitespace and append
            char *p = line;
            while (*p == ' ' || *p == '\t') p++;
            strncat(full_b64, p, sizeof(full_b64) - strlen(full_b64) - 1);
        }

        break;
    }
    fclose(f);

    if (!found || strlen(full_b64) == 0) {
        fprintf(stderr, "Error: no DNSKEY record found\n");
        return 0;
    }

    printf("Full base64 blob (%zu chars): %s\n", strlen(full_b64), full_b64);

    // Decode the blob
    unsigned char *blob = NULL;
    int blob_len = b64_to_bin(full_b64, &blob);

    if (blob_len < 4) { fprintf(stderr, "Error: key blob too short (%d bytes)\n", blob_len); return 0; }
    printf("Decoded blob: %d bytes = %d bits\n", blob_len, blob_len * 8);

    // Parse RSA wire format
    int exp_len, offset;
    if (blob[0] == 0) {
        exp_len = (blob[1] << 8) | blob[2];
        offset = 3;
    } else {
        exp_len = blob[0];
        offset = 1;
    }

    int mod_len = blob_len - offset - exp_len;
    printf("Exponent: %d bytes, Modulus: %d bytes = %d bits\n", exp_len, mod_len, mod_len * 8);

    if (mod_len <= 0) { fprintf(stderr, "Error: malformed key blob\n"); free(blob); return 0; }

    BIGNUM *e = BN_bin2bn(blob + offset, exp_len, NULL);
    BIGNUM *n = BN_bin2bn(blob + offset + exp_len, mod_len, NULL);
    free(blob);

    if (!e || !n) { fprintf(stderr, "Error: failed to parse e/n\n"); return 0; }

    RSA *rsa = RSA_new();
    if (RSA_set0_key(rsa, n, e, NULL) != 1) {
        fprintf(stderr, "Error: RSA_set0_key failed\n");
        RSA_free(rsa);
        return 0;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(pkey, rsa);

    FILE *out = fopen(outfile, "w");
    if (!out) { fprintf(stderr, "Error: cannot open output file\n"); return 0; }
    PEM_write_PUBKEY(out, pkey);
    fclose(out);
    EVP_PKEY_free(pkey);

    printf("Success: public key written to %s\n", outfile);
    return 1;
}

// ---------------------------------------------------------------------------
// Main — detect file type by extension
// ---------------------------------------------------------------------------

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input.private|input.key> <output.pem>\n", argv[0]);
        return 1;
    }

    const char *infile = argv[1];
    size_t len = strlen(infile);

    if (len > 8 && strcmp(infile + len - 8, ".private") == 0) {
        return convert_private(infile, argv[2]) ? 0 : 1;
    } else if (len > 4 && strcmp(infile + len - 4, ".key") == 0) {
        return convert_public(infile, argv[2]) ? 0 : 1;
    } else {
        fprintf(stderr, "Error: cannot determine file type from extension.\n");
        fprintf(stderr, "File must end in .private or .key\n");
        return 1;
    }
}
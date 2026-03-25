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

// Parse the BIND private key file into key-value pairs
int parse_bind_file(const char *filename, Field *fields, int *count) {
    FILE *f = fopen(filename, "r");
    if (!f) {
        fprintf(stderr, "Error: cannot open file '%s'\n", filename);
        return 0;
    }

    char line[MAX_LINE];
    *count = 0;

    while (fgets(line, sizeof(line), f)) {
        // Strip trailing newline/carriage return
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

// Find a field value by key name
const char *get_field(Field *fields, int count, const char *key) {
    for (int i = 0; i < count; i++) {
        if (strcmp(fields[i].key, key) == 0)
            return fields[i].value;
    }
    return NULL;
}

// Decode a base64 string into a BIGNUM
BIGNUM *b64_to_bn(const char *b64) {
    // Calculate decoded length
    int b64_len = strlen(b64);
    int bin_len = (b64_len * 3) / 4 + 4;
    unsigned char *bin = malloc(bin_len);
    if (!bin) return NULL;

    // Use OpenSSL's base64 decode via BIO
    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new_mem_buf(b64, -1);
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded_len = BIO_read(b64_bio, bin, bin_len);
    BIO_free_all(b64_bio);

    if (decoded_len <= 0) {
        free(bin);
        return NULL;
    }

    BIGNUM *bn = BN_bin2bn(bin, decoded_len, NULL);
    free(bin);
    return bn;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <input.private> <output.pem>\n", argv[0]);
        return 1;
    }

    Field fields[MAX_FIELDS];
    int count = 0;

    if (!parse_bind_file(argv[1], fields, &count)) return 1;

    // Check algorithm
    const char *algo = get_field(fields, count, "Algorithm");
    if (!algo) {
        fprintf(stderr, "Error: no Algorithm field found\n");
        return 1;
    }
    printf("Algorithm: %s\n", algo);

    // Extract all RSA components
    const char *mod  = get_field(fields, count, "Modulus");
    const char *pub  = get_field(fields, count, "PublicExponent");
    const char *priv = get_field(fields, count, "PrivateExponent");
    const char *p1   = get_field(fields, count, "Prime1");
    const char *p2   = get_field(fields, count, "Prime2");
    const char *e1   = get_field(fields, count, "Exponent1");
    const char *e2   = get_field(fields, count, "Exponent2");
    const char *coef = get_field(fields, count, "Coefficient");

    if (!mod || !pub || !priv || !p1 || !p2 || !e1 || !e2 || !coef) {
        fprintf(stderr, "Error: missing one or more RSA key fields\n");
        return 1;
    }

    // Decode all fields to BIGNUMs
    BIGNUM *n    = b64_to_bn(mod);
    BIGNUM *e    = b64_to_bn(pub);
    BIGNUM *d    = b64_to_bn(priv);
    BIGNUM *p    = b64_to_bn(p1);
    BIGNUM *q    = b64_to_bn(p2);
    BIGNUM *dmp1 = b64_to_bn(e1);
    BIGNUM *dmq1 = b64_to_bn(e2);
    BIGNUM *iqmp = b64_to_bn(coef);

    if (!n || !e || !d || !p || !q || !dmp1 || !dmq1 || !iqmp) {
        fprintf(stderr, "Error: failed to decode one or more key components\n");
        return 1;
    }

    // Build the RSA key
    RSA *rsa = RSA_new();
    if (!rsa) {
        fprintf(stderr, "Error: RSA_new() failed\n");
        return 1;
    }

    // Set key components (OpenSSL takes ownership of the BIGNUMs)
    if (RSA_set0_key(rsa, n, e, d) != 1 ||
        RSA_set0_factors(rsa, p, q) != 1 ||
        RSA_set0_crt_params(rsa, dmp1, dmq1, iqmp) != 1) {
        fprintf(stderr, "Error: failed to set RSA key components\n");
        RSA_free(rsa);
        return 1;
    }

    // Wrap in EVP_PKEY
    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        fprintf(stderr, "Error: EVP_PKEY_assign_RSA failed\n");
        return 1;
    }

    // Write to PEM file
    FILE *out = fopen(argv[2], "w");
    if (!out) {
        fprintf(stderr, "Error: cannot open output file '%s'\n", argv[2]);
        return 1;
    }

    if (PEM_write_PrivateKey(out, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
        fprintf(stderr, "Error: PEM_write_PrivateKey failed\n");
        fclose(out);
        return 1;
    }

    fclose(out);
    EVP_PKEY_free(pkey);

    printf("Success: written to %s\n", argv[2]);
    return 0;
}

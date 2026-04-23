#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

int b64_to_bin(const char *b64, unsigned char **out, size_t *out_len) {
    // Strip whitespace into a clean buffer
    char *clean = malloc(strlen(b64) + 1);
    int ci = 0;
    for (int i = 0; b64[i]; i++)
        if (b64[i] != ' ' && b64[i] != '\n' && b64[i] != '\r' && b64[i] != '\t')
            clean[ci++] = b64[i];
    clean[ci] = 0;

    size_t bin_len = (ci * 3) / 4 + 4;
    *out = malloc(bin_len);

    BIO *b64_bio = BIO_new(BIO_f_base64());
    BIO *mem_bio = BIO_new_mem_buf(clean, -1);
    BIO_push(b64_bio, mem_bio);
    BIO_set_flags(b64_bio, BIO_FLAGS_BASE64_NO_NL);

    int decoded = BIO_read(b64_bio, *out, bin_len);
    BIO_free_all(b64_bio);
    free(clean);

    if (decoded <= 0) {
        fprintf(stderr, "Error: base64 decode failed\n");
        free(*out);
        return 0;
    }

    *out_len = decoded;
    return 1;
}
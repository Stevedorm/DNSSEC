#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// ---------------------------------------------------------------------------
// Wire format helpers
// ---------------------------------------------------------------------------

// Append bytes to a buffer
int buf_append(unsigned char *buf, int *pos, const void *data, int len) {
    memcpy(buf + *pos, data, len);
    *pos += len;
    return 1;
}

// Encode a DNS name into wire format (lowercased)
// e.g. "jmu.lab." -> \x03jmu\x03lab\x00
int encode_name(const char *name, unsigned char *out, int *len) {
    *len = 0;
    char tmp[256];
    strncpy(tmp, name, 255);

    // Lowercase
    for (int i = 0; tmp[i]; i++)
        if (tmp[i] >= 'A' && tmp[i] <= 'Z') tmp[i] += 32;

    char *label = strtok(tmp, ".");
    while (label) {
        int llen = strlen(label);
        out[(*len)++] = (unsigned char)llen;
        memcpy(out + *len, label, llen);
        *len += llen;
        label = strtok(NULL, ".");
    }
    out[(*len)++] = 0; // root label
    return 1;
}

// ---------------------------------------------------------------------------
// Build the RRSIG signature base (RFC 4034 Section 6.2)
// ---------------------------------------------------------------------------

// Represents one RR's RDATA for an A record (simplest case)
typedef struct {
    uint32_t ip;  // network byte order
} RDataA;

int build_signature_base(
    // RRSIG fields
    uint16_t type_covered,   // e.g. 1 for A
    uint8_t  algorithm,      // 8 for RSASHA256
    uint8_t  labels,         // number of labels in owner name
    uint32_t orig_ttl,
    uint32_t sig_expiration,
    uint32_t sig_inception,
    uint16_t key_tag,
    const char *signers_name,
    // RRset fields
    const char *owner_name,
    uint16_t rrtype,
    uint16_t rrclass,        // 1 for IN
    uint32_t ttl,
    RDataA *rdata_list,      // array of A records
    int rdata_count,
    // Output
    unsigned char *out,
    int *out_len
) {
    int pos = 0;
    uint16_t tmp16;
    uint32_t tmp32;

    // --- RRSIG RDATA (without signature field) ---

    // Type covered
    tmp16 = htons(type_covered);
    buf_append(out, &pos, &tmp16, 2);

    // Algorithm
    buf_append(out, &pos, &algorithm, 1);

    // Labels
    buf_append(out, &pos, &labels, 1);

    // Original TTL
    tmp32 = htonl(orig_ttl);
    buf_append(out, &pos, &tmp32, 4);

    // Signature expiration
    tmp32 = htonl(sig_expiration);
    buf_append(out, &pos, &tmp32, 4);

    // Signature inception
    tmp32 = htonl(sig_inception);
    buf_append(out, &pos, &tmp32, 4);

    // Key tag
    tmp16 = htons(key_tag);
    buf_append(out, &pos, &tmp16, 2);

    // Signer's name in wire format
    unsigned char name_wire[256];
    int name_len = 0;
    encode_name(signers_name, name_wire, &name_len);
    buf_append(out, &pos, name_wire, name_len);

    // --- RRset in canonical wire format ---
    // Each RR: owner name | type | class | ttl | rdlength | rdata
    // Must be sorted by RDATA for same owner/type/class (RFC 4034 6.3)
    // For A records, sort by IP value
    RDataA sorted[64];
    memcpy(sorted, rdata_list, rdata_count * sizeof(RDataA));

    // Bubble sort by IP (network byte order comparison)
    for (int i = 0; i < rdata_count - 1; i++)
        for (int j = 0; j < rdata_count - i - 1; j++)
            if (ntohl(sorted[j].ip) > ntohl(sorted[j+1].ip)) {
                RDataA t = sorted[j]; sorted[j] = sorted[j+1]; sorted[j+1] = t;
            }

    unsigned char owner_wire[256];
    int owner_len = 0;
    encode_name(owner_name, owner_wire, &owner_len);

    for (int i = 0; i < rdata_count; i++) {
        // Owner name
        buf_append(out, &pos, owner_wire, owner_len);
        // Type
        tmp16 = htons(rrtype);
        buf_append(out, &pos, &tmp16, 2);
        // Class
        tmp16 = htons(rrclass);
        buf_append(out, &pos, &tmp16, 2);
        // TTL (use original TTL from RRSIG, not current)
        tmp32 = htonl(ttl);
        buf_append(out, &pos, &tmp32, 4);
        // RDLENGTH (4 bytes for A record)
        tmp16 = htons(4);
        buf_append(out, &pos, &tmp16, 2);
        // RDATA
        buf_append(out, &pos, &sorted[i].ip, 4);
    }

    *out_len = pos;
    return 1;
}

// ---------------------------------------------------------------------------
// Sign the signature base with RSA private key (RSASSA-PKCS1-v1_5 + SHA256)
// ---------------------------------------------------------------------------

int sign_data(const char *privkey_pem, unsigned char *data, int data_len,
              unsigned char **sig, size_t *sig_len) {
    FILE *f = fopen(privkey_pem, "r");
    if (!f) { fprintf(stderr, "Error: cannot open private key PEM\n"); return 0; }

    EVP_PKEY *pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) { fprintf(stderr, "Error: failed to read private key\n"); return 0; }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1 ||
        EVP_DigestSignUpdate(ctx, data, data_len) != 1 ||
        EVP_DigestSignFinal(ctx, NULL, sig_len) != 1) {
        fprintf(stderr, "Error: signing failed\n");
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    *sig = malloc(*sig_len);
    if (EVP_DigestSignFinal(ctx, *sig, sig_len) != 1) {
        fprintf(stderr, "Error: signing final failed\n");
        free(*sig);
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return 0;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 1;
}

// ---------------------------------------------------------------------------
// Verify a signature with RSA public key
// ---------------------------------------------------------------------------

int verify_data(const char *pubkey_pem, unsigned char *data, int data_len,
                unsigned char *sig, size_t sig_len) {
    FILE *f = fopen(pubkey_pem, "r");
    if (!f) { fprintf(stderr, "Error: cannot open public key PEM\n"); return 0; }

    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) { fprintf(stderr, "Error: failed to read public key\n"); return 0; }

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int result = 0;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) == 1 &&
        EVP_DigestVerifyUpdate(ctx, data, data_len) == 1 &&
        EVP_DigestVerifyFinal(ctx, sig, sig_len) == 1) {
        result = 1;
    }

    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return result;
}

// ---------------------------------------------------------------------------
// Load an existing RRSIG signature from a binary file for comparison
// ---------------------------------------------------------------------------

int load_signature(const char *filename, unsigned char **sig, size_t *sig_len) {
    FILE *f = fopen(filename, "rb");
    if (!f) { fprintf(stderr, "Error: cannot open signature file\n"); return 0; }
    fseek(f, 0, SEEK_END);
    *sig_len = ftell(f);
    rewind(f);
    *sig = malloc(*sig_len);
    fread(*sig, 1, *sig_len, f);
    fclose(f);
    return 1;
}

// Print hex dump
void hexdump(const char *label, unsigned char *data, size_t len) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else if ((i + 1) % 8 == 0) printf("  ");
        else printf(" ");
    }
    printf("\n\n");
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <private.pem> <public.pem> <existing_sig.bin>\n", argv[0]);
        fprintf(stderr, "  existing_sig.bin = raw signature bytes extracted from RRSIG record\n");
        return 1;
    }

    // -------------------------------------------------------------------------
    // Configure your RRset and RRSIG parameters here
    // These values must match exactly what BIND used when it signed your zone
    // Extract them from: dig @ns jmu.lab A +dnssec
    // -------------------------------------------------------------------------

    const char *owner_name   = "jmu.lab.";
    const char *signers_name = "jmu.lab.";
    uint16_t type_covered    = 1;       // A record
    uint8_t  algorithm       = 8;       // RSASHA256
    uint8_t  labels          = 2;       // "jmu.lab." has 2 labels
    uint32_t orig_ttl        = 3600;
    uint32_t sig_expiration  = 0;       // REPLACE: from RRSIG (unix timestamp)
    uint32_t sig_inception   = 0;       // REPLACE: from RRSIG (unix timestamp)
    uint16_t key_tag         = 14329;   // your ZSK key tag

    // Your A records for jmu.lab. -- add all of them
    RDataA rdata[] = {
        { inet_addr("x.x.x.x") },      // REPLACE with real IP(s)
    };
    int rdata_count = 1;

    // -------------------------------------------------------------------------

    // Build the signature base
    unsigned char sigbase[65536];
    int sigbase_len = 0;

    build_signature_base(
        type_covered, algorithm, labels, orig_ttl,
        sig_expiration, sig_inception, key_tag,
        signers_name, owner_name,
        type_covered, 1, orig_ttl,
        rdata, rdata_count,
        sigbase, &sigbase_len
    );

    printf("=== Signature base constructed: %d bytes ===\n\n", sigbase_len);
    hexdump("Signature base", sigbase, sigbase_len);

    // Sign with private key
    unsigned char *our_sig = NULL;
    size_t our_sig_len = 0;

    if (!sign_data(argv[1], sigbase, sigbase_len, &our_sig, &our_sig_len)) {
        fprintf(stderr, "Signing failed\n");
        return 1;
    }
    hexdump("Our generated signature", our_sig, our_sig_len);

    // Verify with public key
    printf("=== Verifying our signature with public key ===\n");
    if (verify_data(argv[2], sigbase, sigbase_len, our_sig, our_sig_len))
        printf("PASS: Our signature verifies correctly\n\n");
    else
        printf("FAIL: Our signature did not verify\n\n");

    // Load and compare existing RRSIG
    unsigned char *existing_sig = NULL;
    size_t existing_sig_len = 0;

    if (load_signature(argv[3], &existing_sig, &existing_sig_len)) {
        hexdump("Existing RRSIG signature", existing_sig, existing_sig_len);

        // Verify existing sig with our public key
        printf("=== Verifying existing RRSIG with our public key ===\n");
        if (verify_data(argv[2], sigbase, sigbase_len, existing_sig, existing_sig_len))
            printf("PASS: Existing RRSIG verifies correctly against our reconstructed data\n\n");
        else
            printf("FAIL: Existing RRSIG did not verify - signature base may not match exactly\n\n");

        // Binary comparison
        printf("=== Binary comparison ===\n");
        if (our_sig_len == existing_sig_len &&
            memcmp(our_sig, existing_sig, our_sig_len) == 0)
            printf("MATCH: Generated signature is byte-for-byte identical to existing RRSIG\n");
        else
            printf("DIFFER: Signatures differ (expected for RSA - see note below)\n");

        free(existing_sig);
    }

    free(our_sig);
    return 0;
}
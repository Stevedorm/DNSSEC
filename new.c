/*
    new.c

    Build:
      gcc -Wall -Wextra -O2 new.c -o new -lssl -lcrypto

    Example run:
      ./new

    What this demonstrates:
      1) Parse RRSIG header fields from a hex string
      2) Rebuild the exact signed_data for a covered A RR
      3) Sign with an RSA private key (your ZSK private key in PEM)
      4) Verify with the matching public key
      5) Optionally verify using DNSKEY RSA public-key bytes

    Notes:
      - This example assumes algorithm 8 (RSASHA256).
      - It signs one A RR for simplicity.
      - In real DNSSEC, an RRset may contain multiple RRs and must be sorted canonically.
      - The sample hex below contains only the RRSIG header and signer name, not the signature blob.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <arpa/inet.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>

/* ----------------------------- Data types ----------------------------- */

typedef struct {
    uint16_t type_covered;   /* e.g. 1 for A */
    uint8_t  algorithm;      /* e.g. 8 for RSASHA256 */
    uint8_t  labels;         /* label count */
    uint32_t original_ttl;   /* use this in canonical RRset */
    uint32_t expiration;     /* signature expiration */
    uint32_t inception;      /* signature inception */
    uint16_t key_tag;        /* DNSSEC key tag */
    char signer_name[256];   /* dotted form, e.g. "jmu.lab." */

    uint8_t *signature;      /* actual signature bytes, if present */
    size_t signature_len;
} RRSIG_RDATA;

/* --------------------------- Helper functions -------------------------- */

static uint16_t read_u16_be(const uint8_t *buf) {
    return ((uint16_t)buf[0] << 8) | (uint16_t)buf[1];
}

static uint32_t read_u32_be(const uint8_t *buf) {
    return ((uint32_t)buf[0] << 24) |
           ((uint32_t)buf[1] << 16) |
           ((uint32_t)buf[2] << 8)  |
           (uint32_t)buf[3];
}

static void write_u16_be(uint8_t *buf, uint16_t v) {
    buf[0] = (uint8_t)(v >> 8);
    buf[1] = (uint8_t)(v & 0xff);
}

static void write_u32_be(uint8_t *buf, uint32_t v) {
    buf[0] = (uint8_t)(v >> 24);
    buf[1] = (uint8_t)(v >> 16);
    buf[2] = (uint8_t)(v >> 8);
    buf[3] = (uint8_t)(v & 0xff);
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t **out, size_t *out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return -1;

    *out_len = len / 2;
    *out = malloc(*out_len);
    if (!*out) return -1;

    for (size_t i = 0; i < *out_len; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) {
            free(*out);
            *out = NULL;
            *out_len = 0;
            return -1;
        }
        (*out)[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void print_hex(const uint8_t *buf, size_t len, const char *label) {
    printf("%s (%zu bytes):\n", label, len);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else printf(" ");
    }
    if (len % 16 != 0) printf("\n");
}

static const char *rrtype_to_string(uint16_t type) {
    switch (type) {
        case 1:  return "A";
        case 2:  return "NS";
        case 5:  return "CNAME";
        case 6:  return "SOA";
        case 15: return "MX";
        case 16: return "TXT";
        case 28: return "AAAA";
        case 43: return "DS";
        case 46: return "RRSIG";
        case 48: return "DNSKEY";
        default: return "UNKNOWN";
    }
}

static const char *dnssec_algo_to_string(uint8_t algo) {
    switch (algo) {
        case 8:  return "RSASHA256";
        case 10: return "RSASHA512";
        case 13: return "ECDSAP256SHA256";
        case 14: return "ECDSAP384SHA384";
        case 15: return "ED25519";
        default: return "UNKNOWN";
    }
}

/* ------------------------- DNS name processing ------------------------- */

/*
    Parse a DNS wire-format name from buf[*offset...] into dotted form.
    Example wire: 03 6a 6d 75 03 6c 61 62 00 -> "jmu.lab."
*/
static int parse_dns_name(const uint8_t *buf, size_t buf_len,
                          size_t *offset, char *out, size_t out_size) {
    size_t pos = *offset;
    size_t out_pos = 0;

    if (out_size == 0) return -1;

    while (1) {
        if (pos >= buf_len) return -1;

        uint8_t labellen = buf[pos++];

        if (labellen == 0) {
            if (out_pos + 1 >= out_size) return -1;
            out[out_pos++] = '.';
            out[out_pos] = '\0';
            break;
        }

        /* Reject compressed names here; RRSIG signer name should be canonicalized separately */
        if ((labellen & 0xC0) == 0xC0) return -1;

        if (pos + labellen > buf_len) return -1;
        if (out_pos + labellen + 1 >= out_size) return -1;

        memcpy(&out[out_pos], &buf[pos], labellen);
        out_pos += labellen;
        pos += labellen;

        out[out_pos++] = '.';
    }

    *offset = pos;
    return 0;
}

/*
    Convert dotted name to canonical DNS wire format:
      - lowercase
      - uncompressed
      - root-terminated
*/
static int name_to_wire(const char *name, uint8_t *out, size_t out_cap, size_t *out_len) {
    char tmp[256];
    size_t n = strlen(name);

    if (n == 0 || n >= sizeof(tmp)) return -1;
    strcpy(tmp, name);

    for (size_t i = 0; i < n; i++) {
        if (tmp[i] >= 'A' && tmp[i] <= 'Z') tmp[i] = (char)(tmp[i] - 'A' + 'a');
    }

    /* Remove trailing dot for strtok convenience if present */
    if (n > 0 && tmp[n - 1] == '.') tmp[n - 1] = '\0';

    size_t pos = 0;
    char *save = NULL;
    char *tok = strtok_r(tmp, ".", &save);

    while (tok) {
        size_t len = strlen(tok);
        if (len > 63 || pos + 1 + len >= out_cap) return -1;

        out[pos++] = (uint8_t)len;
        memcpy(out + pos, tok, len);
        pos += len;

        tok = strtok_r(NULL, ".", &save);
    }

    if (pos + 1 > out_cap) return -1;
    out[pos++] = 0x00;
    *out_len = pos;
    return 0;
}

/* --------------------------- RRSIG parsing ----------------------------- */

static int parse_rrsig_rdata(const uint8_t *rdata, size_t rdata_len, RRSIG_RDATA *out) {
    if (!rdata || !out) return -1;

    memset(out, 0, sizeof(*out));

    /* Fixed header is 18 bytes: 2 + 1 + 1 + 4 + 4 + 4 + 2 */
    if (rdata_len < 18) return -1;

    size_t offset = 0;

    out->type_covered = read_u16_be(rdata + offset); offset += 2;
    out->algorithm    = rdata[offset++];
    out->labels       = rdata[offset++];
    out->original_ttl = read_u32_be(rdata + offset); offset += 4;
    out->expiration   = read_u32_be(rdata + offset); offset += 4;
    out->inception    = read_u32_be(rdata + offset); offset += 4;
    out->key_tag      = read_u16_be(rdata + offset); offset += 2;

    if (parse_dns_name(rdata, rdata_len, &offset, out->signer_name, sizeof(out->signer_name)) != 0) {
        return -1;
    }

    out->signature_len = rdata_len - offset;
    if (out->signature_len > 0) {
        out->signature = malloc(out->signature_len);
        if (!out->signature) return -1;
        memcpy(out->signature, rdata + offset, out->signature_len);
    }

    return 0;
}

static void free_rrsig_rdata(RRSIG_RDATA *rrsig) {
    if (!rrsig) return;
    free(rrsig->signature);
    rrsig->signature = NULL;
    rrsig->signature_len = 0;
}

/* -------------------- Build exact DNSSEC signed input ------------------- */

/*
    Builds signed_data for one covered A RR:
      signed_data =
        RRSIG_RDATA_without_signature
        ||
        owner_name_canonical
        || type || class || original_ttl || rdlength || rdata

    This is the DNSSEC input that gets hashed and signed/verified.
*/
static int build_signed_data_a(const RRSIG_RDATA *sig,
                               const char *owner_name,
                               const char *ipv4_text,
                               uint8_t **out,
                               size_t *out_len) {
    if (!sig || !owner_name || !ipv4_text || !out || !out_len) return -1;

    uint8_t signer_wire[256];
    uint8_t owner_wire[256];
    size_t signer_len = 0, owner_len = 0;
    uint8_t addr[4];

    if (inet_pton(AF_INET, ipv4_text, addr) != 1) return -1;
    if (name_to_wire(sig->signer_name, signer_wire, sizeof(signer_wire), &signer_len) != 0) return -1;
    if (name_to_wire(owner_name, owner_wire, sizeof(owner_wire), &owner_len) != 0) return -1;

    size_t total =
        2 + 1 + 1 + 4 + 4 + 4 + 2 + signer_len + /* RRSIG fields except signature */
        owner_len + 2 + 2 + 4 + 2 + 4;           /* one A RR */

    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    size_t p = 0;

    write_u16_be(buf + p, sig->type_covered); p += 2;
    buf[p++] = sig->algorithm;
    buf[p++] = sig->labels;
    write_u32_be(buf + p, sig->original_ttl); p += 4;
    write_u32_be(buf + p, sig->expiration); p += 4;
    write_u32_be(buf + p, sig->inception); p += 4;
    write_u16_be(buf + p, sig->key_tag); p += 2;
    memcpy(buf + p, signer_wire, signer_len); p += signer_len;

    memcpy(buf + p, owner_wire, owner_len); p += owner_len;
    write_u16_be(buf + p, 1); p += 2;                  /* TYPE A */
    write_u16_be(buf + p, 1); p += 2;                  /* CLASS IN */
    write_u32_be(buf + p, sig->original_ttl); p += 4; /* MUST use Original TTL */
    write_u16_be(buf + p, 4); p += 2;                  /* A RDLENGTH */
    memcpy(buf + p, addr, 4); p += 4;                  /* IPv4 RDATA */

    *out = buf;
    *out_len = p;
    return 0;
}

/* ----------------------- OpenSSL key loading --------------------------- */

static EVP_PKEY *load_private_key_pem(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;

    EVP_PKEY *pkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

static EVP_PKEY *load_public_key_pem(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;

    EVP_PKEY *pkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    return pkey;
}

/* ----------------------- Base64 decode utility ------------------------- */

static int base64_decode(const char *b64, uint8_t **out, size_t *out_len) {
    BIO *bmem = NULL, *b64bio = NULL;
    size_t in_len = strlen(b64);
    uint8_t *buf = malloc(in_len); /* enough for decoded data */
    if (!buf) return -1;

    b64bio = BIO_new(BIO_f_base64());
    bmem = BIO_new_mem_buf((void *)b64, (int)in_len);
    if (!b64bio || !bmem) {
        BIO_free_all(b64bio);
        BIO_free_all(bmem);
        free(buf);
        return -1;
    }

    BIO_set_flags(b64bio, BIO_FLAGS_BASE64_NO_NL);
    bmem = BIO_push(b64bio, bmem);

    int n = BIO_read(bmem, buf, (int)in_len);
    BIO_free_all(bmem);

    if (n <= 0) {
        free(buf);
        return -1;
    }

    *out = buf;
    *out_len = (size_t)n;
    return 0;
}

/* ----------------- Convert DNSKEY RSA bytes -> EVP_PKEY ---------------- */

/*
    RFC-style RSA DNSKEY public key bytes:
      if first byte != 0:
         first byte = exponent length
      else:
         next 2 bytes = exponent length
      then exponent bytes
      then modulus bytes
*/
static EVP_PKEY *dnskey_rsa_bytes_to_evp(const uint8_t *pub, size_t pub_len) {
    if (!pub || pub_len < 3) return NULL;

    size_t off = 0;
    size_t e_len = 0;

    if (pub[0] == 0) {
        if (pub_len < 3) return NULL;
        e_len = ((size_t)pub[1] << 8) | pub[2];
        off = 3;
    } else {
        e_len = pub[0];
        off = 1;
    }

    if (off + e_len > pub_len) return NULL;
    size_t n_len = pub_len - off - e_len;
    if (n_len == 0) return NULL;

    const uint8_t *e_bytes = pub + off;
    const uint8_t *n_bytes = pub + off + e_len;

    BIGNUM *e = BN_bin2bn(e_bytes, (int)e_len, NULL);
    BIGNUM *n = BN_bin2bn(n_bytes, (int)n_len, NULL);
    if (!e || !n) {
        BN_free(e);
        BN_free(n);
        return NULL;
    }

    RSA *rsa = RSA_new();
    if (!rsa) {
        BN_free(e);
        BN_free(n);
        return NULL;
    }

    if (RSA_set0_key(rsa, n, e, NULL) != 1) {
        RSA_free(rsa);
        BN_free(n);
        BN_free(e);
        return NULL;
    }

    EVP_PKEY *pkey = EVP_PKEY_new();
    if (!pkey) {
        RSA_free(rsa);
        return NULL;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        EVP_PKEY_free(pkey);
        RSA_free(rsa);
        return NULL;
    }

    return pkey;
}

/* ------------------------- Sign / verify logic ------------------------- */

static int sign_rsasha256(EVP_PKEY *private_key,
                          const uint8_t *data, size_t data_len,
                          uint8_t **sig_out, size_t *sig_len_out) {
    if (!private_key || !data || !sig_out || !sig_len_out) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    int rc = -1;
    size_t sig_len = 0;
    uint8_t *sig = NULL;

    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, private_key) != 1) goto done;
    if (EVP_DigestSignUpdate(ctx, data, data_len) != 1) goto done;
    if (EVP_DigestSignFinal(ctx, NULL, &sig_len) != 1) goto done;

    sig = malloc(sig_len);
    if (!sig) goto done;

    if (EVP_DigestSignFinal(ctx, sig, &sig_len) != 1) goto done;

    *sig_out = sig;
    *sig_len_out = sig_len;
    sig = NULL;
    rc = 0;

done:
    free(sig);
    EVP_MD_CTX_free(ctx);
    return rc;
}

static int verify_rsasha256(EVP_PKEY *public_key,
                            const uint8_t *data, size_t data_len,
                            const uint8_t *sig, size_t sig_len) {
    if (!public_key || !data || !sig) return -1;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) return -1;

    int ok = -1;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, public_key) != 1) goto done;
    if (EVP_DigestVerifyUpdate(ctx, data, data_len) != 1) goto done;

    ok = EVP_DigestVerifyFinal(ctx, sig, sig_len);
    /* 1 = valid, 0 = invalid, <0 = error */

done:
    EVP_MD_CTX_free(ctx);
    return ok;
}

/* ------------------------------- main ---------------------------------- */

int main(void) {
    /*
        This is your sample RRSIG header hex:
        0001 = A
        08   = RSASHA256
        03   = labels
        00015180 = 86400
        69bc4cd1 = expiration
        69aa311d = inception
        37f9 = key tag
        036a6d75036c616200 = jmu.lab.
        no signature bytes present in this sample
    */
    const char *rrsig_hex =
        "000108030001518069bc4cd169aa311d37f9036a6d75036c616200";

    /*
        Covered RR we want to sign/verify:
          quad.jmu.lab. 86400 IN A 192.168.107.130
    */
    const char *owner_name = "quad.jmu.lab.";
    const char *a_ipv4 = "192.168.107.130";

    /*
        Key files:
          keys/zsk_private.pem  <- your ZSK private key in PEM
          keys/zsk_public.pem   <- matching PEM public key (optional but convenient)

        If you only have DNSKEY text from the zone, you can instead use
        dnskey_public_b64 below and verify through dnskey_rsa_bytes_to_evp().
    */
    const char *private_key_path = "keys/zsk_private.pem";
    const char *public_key_path  = "keys/zsk_public.pem";

    /*
        Optional: put the base64 Public Key field from the zone's DNSKEY here.
        Example DNSKEY presentation format:
          jmu.lab. IN DNSKEY 256 3 8 AwEAAc....

        You would copy only the final base64 field into dnskey_public_b64.
        Leave empty "" if not using this path.
    */
    const char *dnskey_public_b64 = "";

    uint8_t *rrsig_bytes = NULL;
    size_t rrsig_len = 0;
    RRSIG_RDATA rrsig;

    if (hex_to_bytes(rrsig_hex, &rrsig_bytes, &rrsig_len) != 0) {
        fprintf(stderr, "Failed to convert RRSIG hex to bytes.\n");
        return 1;
    }

    if (parse_rrsig_rdata(rrsig_bytes, rrsig_len, &rrsig) != 0) {
        fprintf(stderr, "Failed to parse RRSIG.\n");
        free(rrsig_bytes);
        return 1;
    }

    printf("Parsed RRSIG:\n");
    printf("  Type Covered : %u (%s)\n", rrsig.type_covered, rrtype_to_string(rrsig.type_covered));
    printf("  Algorithm    : %u (%s)\n", rrsig.algorithm, dnssec_algo_to_string(rrsig.algorithm));
    printf("  Labels       : %u\n", rrsig.labels);
    printf("  Original TTL : %u\n", rrsig.original_ttl);
    printf("  Expiration   : %u (0x%08x)\n", rrsig.expiration, rrsig.expiration);
    printf("  Inception    : %u (0x%08x)\n", rrsig.inception, rrsig.inception);
    printf("  Key Tag      : %u\n", rrsig.key_tag);
    printf("  Signer Name  : %s\n", rrsig.signer_name);
    printf("  SignatureLen : %zu\n\n", rrsig.signature_len);

    uint8_t *signed_data = NULL;
    size_t signed_len = 0;

    if (build_signed_data_a(&rrsig, owner_name, a_ipv4, &signed_data, &signed_len) != 0) {
        fprintf(stderr, "Failed to rebuild signed_data.\n");
        free_rrsig_rdata(&rrsig);
        free(rrsig_bytes);
        return 1;
    }

    print_hex(signed_data, signed_len, "Reconstructed DNSSEC signed_data");

    /* ---------- Sign with private ZSK ---------- */
    EVP_PKEY *priv = load_private_key_pem(private_key_path);
    if (!priv) {
        fprintf(stderr, "\nCould not open private key at: %s\n", private_key_path);
        fprintf(stderr, "Create keys/zsk_private.pem and rerun.\n");
        goto cleanup;
    }

    uint8_t *sig = NULL;
    size_t sig_len = 0;

    if (sign_rsasha256(priv, signed_data, signed_len, &sig, &sig_len) != 0) {
        fprintf(stderr, "Signing failed.\n");
        EVP_PKEY_free(priv);
        goto cleanup;
    }

    print_hex(sig, sig_len, "\nGenerated RRSIG signature bytes");

    EVP_PKEY_free(priv);

    /* ---------- Verify using PEM public key if available ---------- */
    EVP_PKEY *pub = load_public_key_pem(public_key_path);
    if (pub) {
        int ok = verify_rsasha256(pub, signed_data, signed_len, sig, sig_len);
        if (ok == 1) {
            printf("\nVerification with PEM public key: VALID\n");
        } else if (ok == 0) {
            printf("\nVerification with PEM public key: INVALID\n");
        } else {
            printf("\nVerification with PEM public key: ERROR\n");
        }
        EVP_PKEY_free(pub);
    } else {
        printf("\nNo PEM public key found at %s, skipping PEM verify.\n", public_key_path);
    }

    /* ---------- Verify using DNSKEY base64 Public Key field if provided ---------- */
    if (dnskey_public_b64[0] != '\0') {
        uint8_t *dnskey_pub = NULL;
        size_t dnskey_pub_len = 0;

        if (base64_decode(dnskey_public_b64, &dnskey_pub, &dnskey_pub_len) == 0) {
            EVP_PKEY *dnskey_pub_evp = dnskey_rsa_bytes_to_evp(dnskey_pub, dnskey_pub_len);
            if (dnskey_pub_evp) {
                int ok = verify_rsasha256(dnskey_pub_evp, signed_data, signed_len, sig, sig_len);
                if (ok == 1) {
                    printf("Verification with DNSKEY public-key bytes: VALID\n");
                } else if (ok == 0) {
                    printf("Verification with DNSKEY public-key bytes: INVALID\n");
                } else {
                    printf("Verification with DNSKEY public-key bytes: ERROR\n");
                }
                EVP_PKEY_free(dnskey_pub_evp);
            } else {
                printf("Could not convert DNSKEY public-key bytes into an EVP_PKEY.\n");
            }
            free(dnskey_pub);
        } else {
            printf("Could not base64-decode DNSKEY public key field.\n");
        }
    } else {
        printf("No DNSKEY base64 public key provided, skipping DNSKEY-byte verify.\n");
    }

    /* ---------- Tamper test ---------- */
    if (signed_len > 0) {
        signed_data[signed_len - 1] ^= 0x01; /* flip one bit */
        EVP_PKEY *pub2 = load_public_key_pem(public_key_path);
        if (pub2) {
            int ok = verify_rsasha256(pub2, signed_data, signed_len, sig, sig_len);
            if (ok == 1) {
                printf("Tamper test: unexpectedly VALID\n");
            } else if (ok == 0) {
                printf("Tamper test: INVALID as expected\n");
            } else {
                printf("Tamper test: ERROR\n");
            }
            EVP_PKEY_free(pub2);
        }
    }

    free(sig);

cleanup:
    free(signed_data);
    free_rrsig_rdata(&rrsig);
    free(rrsig_bytes);
    return 0;
}
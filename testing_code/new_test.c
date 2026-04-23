#include "test.h"

/*
To-Do:
Check that the current time is between the inception and expiration times. If not, the signature is not valid.
Use the key tag to find the corresponding DNSKEY record and verify the signature using the algorithm specified in the algo field. This will involve using a cryptographic library to perform the verification.
Compare signatures, likely with a diff file.
*/

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

/* dotted name -> canonical DNS wire format, lowercase, trailing root */
static int name_to_wire(const char *name, uint8_t *out, size_t out_cap, size_t *out_len) {
    char tmp[256];
    size_t n = strlen(name);
    if (n >= sizeof(tmp)) return -1;
    strcpy(tmp, name);

    // lowercase
    for (size_t i = 0; i < n; i++) {
        if (tmp[i] >= 'A' && tmp[i] <= 'Z') tmp[i] = (char)(tmp[i] - 'A' + 'a');
    }

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
    out[pos++] = 0x00;  // root
    *out_len = pos;
    return 0;
}

/* Build the exact DNSSEC signed_data for one A RR */
int build_signed_data_a(const r_data_t *sig,
                        const char *owner_name,
                        const char *ipv4_text,
                        uint8_t **out,
                        size_t *out_len) {
    uint8_t signer_wire[256], owner_wire[256], addr[4];
    size_t signer_len = 0, owner_len = 0;

    if (inet_pton(AF_INET, ipv4_text, addr) != 1) return -1;
    if (name_to_wire(sig->signer_name, signer_wire, sizeof(signer_wire), &signer_len) != 0) return -1;
    if (name_to_wire(owner_name, owner_wire, sizeof(owner_wire), &owner_len) != 0) return -1;

    size_t total =
        2 + 1 + 1 + 4 + 4 + 4 + 2 + signer_len +   // RRSIG fields except signature
        owner_len + 2 + 2 + 4 + 2 + 4;             // one A RR

    uint8_t *buf = malloc(total);
    if (!buf) return -1;

    size_t p = 0;

    write_u16_be(buf + p, sig->type); p += 2;
    buf[p++] = sig->algo;
    buf[p++] = sig->labels;
    write_u32_be(buf + p, sig->ttl); p += 4;
    write_u32_be(buf + p, sig->expiration); p += 4;
    write_u32_be(buf + p, sig->inception); p += 4;
    write_u16_be(buf + p, sig->key_tag); p += 2;
    memcpy(buf + p, signer_wire, signer_len); p += signer_len;

    memcpy(buf + p, owner_wire, owner_len); p += owner_len;
    write_u16_be(buf + p, 1); p += 2;                  // TYPE A
    write_u16_be(buf + p, 1); p += 2;                  // CLASS IN
    write_u32_be(buf + p, sig->ttl); p += 4; // OrigTTL from RRSIG
    write_u16_be(buf + p, 4); p += 2;                  // RDLENGTH
    memcpy(buf + p, addr, 4); p += 4;                  // IPv4 RDATA

    *out = buf;
    *out_len = p;
    return 0;
}

static void print_hex(const uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02x", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else printf(" ");
    }
    if (len % 16 != 0) printf("\n");
}

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t **out, size_t *out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        return -1;
    }

    *out_len = len / 2;
    *out = malloc(*out_len);
    if (!*out) {
        return -1;
    }

    for (size_t i = 0; i < *out_len; i++) {
        int high = hex_value(hex[2 * i]);
        int low = hex_value(hex[2 * i + 1]);
        if (high < 0 || low < 0) {
            free(*out);
            *out = NULL;
            *out_len = 0;
            return -1;
        }
        (*out)[i] = (uint8_t)((high << 4) | low);
    }

    return 0;
}

void parse_rdata(uint8_t *buf, r_data_t *r) {

    r->type = ntohs(*(uint16_t*)buf);
    buf += 2;

    r->algo = *buf;
    buf += 1;

    r->labels = *buf;
    buf += 1;

    r->ttl = ntohl(*(uint32_t*)buf);
    buf += 4;

    r->expiration = ntohl(*(uint32_t*)buf);
    // r->expiration = strtoull(buf, (char**)(&buf + 4), 16);
    buf += 4;

    r->inception = ntohl(*(uint32_t*)buf);
    // r->inception = strtoull(buf, (char**)(&buf + 4), 16);
    buf += 4;

    r->key_tag = ntohl(*(uint16_t*)buf);
    buf += 2;

    memcpy(r->signer_name, buf, 16);
    buf += 16;
}

static int parse_domain_name (const uint8_t *buf, size_t buf_len, size_t *offset, char *name, size_t name_len) {
    
    size_t pos = *offset;
    size_t name_pos = 0;

    if (name_len == 0) {
        return -1; // Invalid name buffer length
    }

    while (1) {
        if (pos >= buf_len) {
            return -1;
        }

        uint8_t labellen = buf[pos++];
        if (labellen == 0) {
            if (name_pos + 1 >= name_len) {
                return -1;
            }
            name[name_pos++] = '.';
            name[name_pos] = '\0';
            break;
        }
    }

    // while (pos < buf_len) {
    //     uint8_t label_len = buf[pos];
    //     if (label_len == 0) {
    //         break; // End of domain name
    //     }
    //     if (label_len > 63 || pos + label_len >= buf_len) {
    //         return -1; // Invalid label length
    //     }
    //     if (name_pos + label_len + 1 >= domain_name_len) {
    //         return -1; // Domain name buffer too small
    //     }
    //     memcpy(domain_name + name_pos, buf + pos + 1, label_len);
    //     name_pos += label_len;
    //     domain_name[name_pos] = '.'; // Add dot after each label
    //     name_pos++;
    //     pos += label_len + 1; // Move to the next label
    // }
    // if (name_pos > 0) {
    //     domain_name[name_pos - 1] = '\0'; // Null-terminate the domain name
    // } else {
    //     domain_name[0] = '\0'; // Empty domain name
    // }
    // *offset = pos + 1; // Move past the null byte
    // return 0; // Success
}

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/pem.h>

/*
RSA DNSKEY public key format:
- if first byte != 0: that byte is exponent length
- if first byte == 0: next two bytes are exponent length
- then exponent bytes
- then modulus bytes
*/

EVP_PKEY *dnskey_rsa_to_evp(const uint8_t *pub, size_t pub_len) {
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

int verify_dnssec_rsa_sha256(const uint8_t *signed_data, size_t signed_len,
                             const uint8_t *signature, size_t sig_len,
                             const uint8_t *dnskey_pub, size_t dnskey_pub_len) {
    int ok = 0;
    EVP_PKEY *pkey = dnskey_rsa_to_evp(dnskey_pub, dnskey_pub_len);
    EVP_MD_CTX *ctx = NULL;

    if (!pkey) return 0;

    ctx = EVP_MD_CTX_new();
    if (!ctx) goto done;

    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, pkey) != 1) goto done;
    if (EVP_DigestVerifyUpdate(ctx, signed_data, signed_len) != 1) goto done;

    ok = EVP_DigestVerifyFinal(ctx, signature, sig_len);
    /* ok == 1 means valid, 0 means invalid, <0 means error */

done:
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return ok == 1;
}

int main (int argc, char *argv[]) {
    // Getting time
    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime);
    
    timeinfo = localtime(&rawtime);
    if (timeinfo == NULL) {
        perror("localtime error");
        return EXIT_FAILURE;
    }

    const char *hex = "000108030001518069bc4cd169aa311d37f9036a6d75036c616200";
    uint8_t *bytes = NULL;
    size_t bytes_len = 0;

    // hex_to_bytes(hex, bytes, &bytes_len);

    r_data_t a_test;
    uint8_t *signed_data = NULL;
size_t signed_len = 0;

if (build_signed_data_a(&a_test, "quad.jmu.lab.", "192.168.107.130",
                        &signed_data, &signed_len) == 0) {
    print_hex(signed_data, signed_len);
    free(signed_data);
}
    
    // parse_rdata(bytes, &a_test);

    if (rawtime < a_test.inception) {
        printf("Signature is not valid, not yet valid.\n");
        // return EXIT_FAILURE;
    } else if (rawtime > a_test.expiration) {
        printf("Signature is not valid, expired.\n");
        // return EXIT_FAILURE;
    }

    printf("\nDecimal values:\n");
    printf("type: %u\n", a_test.type);
    printf("algo: %u\n", a_test.algo);
    printf("labels: %u\n", a_test.labels);
    printf("ttl: %u\n", a_test.ttl);
    printf("expiration: %lu\n", a_test.expiration);
    printf("inception: %lu\n", a_test.inception);
    printf("key_tag: %u\n", a_test.key_tag);
    printf("signer_name: %s\n", a_test.signer_name);

    printf("\nHex values:\n");
    printf("type: %x\n", a_test.type);
    printf("algo: %x\n", a_test.algo);
    printf("labels: %x\n", a_test.labels);
    printf("ttl: %x\n", a_test.ttl);
    printf("expiration: %x\n", a_test.expiration);
    printf("inception: %x\n", a_test.inception);
    printf("key_tag: %x\n", a_test.key_tag);
    printf("signer_name: %s\n", a_test.signer_name);

//     if (verify_dnssec_rsa_sha256(signed_data, signed_len,
//                              signature, signature_len,
//                              dnskey_public_key, dnskey_public_key_len)) {
//     printf("DNSSEC signature is valid\n");
// } else {
//     printf("DNSSEC signature is NOT valid\n");
// }

    return EXIT_SUCCESS;
}
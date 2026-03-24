#include "test.h"

/*
To-Do:
Check that the current time is between the inception and expiration times. If not, the signature is not valid.
Use the key tag to find the corresponding DNSKEY record and verify the signature using the algorithm specified in the algo field. This will involve using a cryptographic library to perform the verification.
Compare signatures, likely with a diff file.
*/

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
    
    parse_rdata(bytes, &a_test);

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

    return EXIT_SUCCESS;
}
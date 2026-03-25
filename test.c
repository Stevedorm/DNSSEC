//----------------------------------------------------
// test.c, a dive into trying to create my own signatures 
// to compare to valid signatures to verify the signature.
//
// Author: Steven Dormady   dormadsa@dukes.jmu.edu
// Date: 04/17/2026         stevedorm2022@gmail.com
//
//----------------------------------------------------



#include "test.h"

/*
To-Do:
Check that the current time is between the inception and expiration times. If not, the signature is not valid.
Use the key tag to find the corresponding DNSKEY record and verify the signature using the algorithm specified in the algo field. This will involve using a cryptographic library to perform the verification.
Compare signatures, likely with a diff file.
*/

void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) {
        sscanf(hex + (2 * i), "%2hhx", &bytes[i]);
    }
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
        // if (pos >= buf_len) {
        //     return -1;
        // }

        uint8_t labellen = buf[pos++];
        if (labellen == 0) {
            if (name_pos + 1 >= name_len) {
                return -1;
            }
            name[name_pos++] = '.';
            name[name_pos] = '\0';
            break;
        } else {
            if (labellen > 63) {
                return -1; // Invalid label length
            }
            if (name_pos + labellen + 1 >= name_len) {
                return -1; // Domain name buffer too small
            }
            memcpy(name + name_pos, buf + pos, labellen);
            name_pos += labellen;
            name[name_pos] = '.'; // Add dot after each label
            name_pos++;
            pos += labellen; // Move to the next label
        }
    }
    return 0; // Success
}

int main (int argc, char *argv[]) {

    time_t rawtime;
    struct tm *timeinfo;

    time(&rawtime); 

    timeinfo = gmtime(&rawtime);

    // Check if gmtime was successful (it can return NULL on error).
    if (timeinfo == NULL) {
        perror("gmtime error");
        exit(EXIT_FAILURE);
    }

    // printf("UTC Time: %2d:%02d:%02d\n", (timeinfo->tm_hour), timeinfo->tm_min, timeinfo->tm_sec);

    char hex[] = "000108030001518069bc4cd169aa311d37f9036a6d75036c616200";
    uint8_t buffer[24];
    size_t len = 24;

    r_data_t a_test;

    hex_to_bytes(hex, buffer, len);

    parse_rdata(buffer, &a_test);

    if (rawtime < a_test.inception) {
        printf("Signature is not valid, not yet valid.\n");
        // return EXIT_FAILURE;
    } else if (rawtime > a_test.expiration) {
        printf("Signature is not valid, expired.\n");
        // return EXIT_FAILURE;
    }

    // Hardcopded for testing purposes
    char *name;
    name = (char*)malloc(10 * sizeof(char));
    if (name == NULL) {
        perror("Error allocating memory");
        // exit(EXIT_FAILURE);
    }

    size_t name_len = 15;
    if (parse_domain_name(buffer, len, &name_len, name, 9) != 0) {
        perror("Error parsing domain name");
        // exit(EXIT_FAILURE);
    }

    memcpy(a_test.signer_name, name, 9);

    printf("\nDecimal values:\n");
    printf("type: %u\n", a_test.type);
    printf("algo: %u\n", a_test.algo);
    printf("labels: %u\n", a_test.labels);
    printf("ttl: %u\n", a_test.ttl);
    printf("expiration: %u\n", a_test.expiration);
    printf("inception: %u\n", a_test.inception);
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

    size_t hash_len = EVP_MD_get_size(EVP_sha256());

    char *output_buffer = (char*)malloc(hash_len);

    EVP_Q_digest(NULL, "sha256", NULL, hex, strlen(hex), output_buffer, &hash_len);
    printf("\nSHA-256 hash of hex string: ");
    for (size_t i = 0; i < hash_len; i++) {
        printf("%02x", (unsigned char)output_buffer[i]);
    }
    printf("\n");
    int fd = open("hash.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    write(fd, output_buffer, hash_len);
    close(fd);
    return 0;
}
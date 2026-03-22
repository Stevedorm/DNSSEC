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

    // r->expiration = ntohl(*(uint32_t*)buf);
    // r->expiration = strtoull(buf, (char**)(&buf + 4), 16);
    buf += 4;

    r->inception = ntohl(*(uint32_t*)buf);
    buf += 4;

    r->key_tag = ntohl(*(uint32_t*)buf);
    buf += 4;

    memcpy(r->signer_name, buf, 16);
    buf += 16;
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

    printf("UTC Time: %2d:%02d:%02d\n", (timeinfo->tm_hour), timeinfo->tm_min, timeinfo->tm_sec);

    char hex[] = "000108030001518069bc4cd169aa311d37f9036a6d75036c616200";
    uint8_t buffer[24];

    hex_to_bytes(hex, buffer, 24);
    // if (data == NULL) {
    //     perror("Error opening file");
    //     return EXIT_FAILURE;
    // }
    // r_data_t a_test; // = {0};
    r_data_t a_test;
    
    parse_rdata(buffer, &a_test);
    // fread(&a_test->type, sizeof(uint16_t), 1, data);
    // a_test->type = ntohs(*(uint16_t*)buffer);
    // buffer += 2;
    printf("type: %x\n", a_test.type);
    // fread(&a_test->algo, sizeof(uint8_t), 1, data);
    // fread(&a_test->labels, sizeof(uint8_t), 1, data);
    // fread(&a_test->ttl, sizeof(uint32_t), 1, data);
    // fread(&a_test->expiration, sizeof(uint32_t), 1, data);
    // fread(&a_test->inception, sizeof(uint32_t), 1, data);
    // fread(&a_test->key_tag, sizeof(uint32_t), 1, data);
    // fread(&a_test->signer_name, sizeof(uint32_t), 1, data);

    printf("type: %u\n", a_test.type);
    printf("algo: %u\n", a_test.algo);
    printf("labels: %u\n", a_test.labels);
    printf("ttl: %u\n", a_test.ttl);
    printf("expiration: %u\n", a_test.expiration);
    printf("inception: %u\n", a_test.inception);
    printf("key_tag: %u\n", a_test.key_tag);
    printf("signer_name: %s\n", a_test.signer_name);

    // fclose(data);

    return 0;
}
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

/*
1 for yes private, 0 for not private
*/
EVP_PKEY *load_key_pem(const char *filepath, int private) {
    FILE *fp = fopen(filepath, "r");
    if (!fp) {
        fprintf(stderr, "Error opening private key file: %s\n", filepath);
        return NULL;
    }
    EVP_PKEY *key = EVP_PKEY_new() ;
    if (private) {
        key = PEM_read_PrivateKey(fp, &key, NULL, NULL);
        fclose(fp);
        if (!key) {
            fprintf(stderr, "Error reading private key from file: %s\n", filepath);
            return NULL;
        }
        return key;
    } else {
        key = PEM_read_PUBKEY(fp, &key, NULL, NULL);
        fclose(fp);
        if (!key) {
            fprintf(stderr, "Error reading public key from file: %s\n", filepath);
            return NULL;
        }
        return key;
    }
    EVP_PKEY *key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!key) {
        fprintf(stderr, "Error reading private key from file: %s\n", filepath);
        return NULL;
    }
    return key;
}

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

    r->key_tag = ntohs(*(uint16_t*)buf);
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

    char *key = argv[1];

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

    // EVP_PKEY_sign() to create a signature using the private key and the data to be signed. This will involve specifying the algorithm and providing the data in the correct format.
    printf("test1\n");
    fflush(stdout);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(mdctx, (unsigned char*)hex, strlen(hex));

    // size_t hash_len = EVP_MD_get_size(EVP_sha256());

    // char *output_buffer = (char*)malloc(hash_len);
    // SHA256_CTX sha256;
    // SHA256_Init(&sha256);
    // SHA256_Update(&sha256, hex, strlen(hex));
    // SHA256_Final((unsigned char*)output_buffer, &sha256);
    for (size_t i = 0; i < strlen(hex); i++) {
        printf("%02x", (unsigned char)hex[i]);
    }
    printf("\n");

    // EVP_Q_digest(NULL, "sha256", NULL, buffer, strlen(buffer), output_buffer, &hash_len);
    printf("\nSHA-256 hash of hex string: ");
    // for (size_t i = 0; i < hash_len; i++) {
    //     printf("%02x", (unsigned char)output_buffer[i]);
    // }
    printf("\ntest\n");
    fflush(stdout);
    // FILE * fp = fopen("./keys/jmu-lab/jmu_zsk_public.pem","rb");
    printf("test2\n");
    fflush(stdout);

    EVP_PKEY *key = NULL;

    if (strstr(key, "private") != NULL) {
        printf("Loading private key...\n");
        key = load_key_pem("./keys/jmu-lab/jmu_zsk_private.pem", 1);
        if (!key) {
            fprintf(stderr, "Failed to load private key.\n");
            return EXIT_FAILURE;
        }
        printf("Private key loaded successfully.\n");
        EVP_PKEY_free(key);
    } else if (strstr(key, "public") != NULL) {
        printf("Loading public key...\n");
        key = load_key_pem("./keys/jmu-lab/jmu_zsk_public.pem", 0);
        if (!key) {
            fprintf(stderr, "Failed to load public key.\n");
            return EXIT_FAILURE;
        }
        printf("Public key loaded successfully.\n");
        EVP_PKEY_free(key);
    } else {
        fprintf(stderr, "Invalid argument. Use 'private' or 'public'.\n");
        return EXIT_FAILURE;
    }

    
    
    // key = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    if (!key) {
        fprintf(stderr, "Error reading public key\n");
        return EXIT_FAILURE;
    }

    EVP_PKEY_CTX *ctx;

    ctx = EVP_PKEY_CTX_new(key, NULL);
    if (!ctx) {
        fprintf(stderr, "Error creating context\n");
        return EXIT_FAILURE;
    }

    if (EVP_PKEY_sign_init( ctx ) <= 0)
    {
        printf("Sign init failed");
        EVP_PKEY_CTX_free( ctx ); exit( -1 ) ;
    }
    printf("test3\n");
    fflush(stdout);
    // fclose(fp);


    // printf("\nSHA-256 hash of hex string: ");
    // for (size_t i = 0; i < hash_len; i++) {
    //     printf("%02x", (unsigned char)output_buffer[i]);
    // }
    return 0;
}
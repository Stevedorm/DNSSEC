#include "test.h"

FILE *pcap = NULL;

int main (int argc, char *argv[]) {

    FILE *pcap = fopen("captures/delv_valid.pcap", "rb");
    if (pcap == NULL) {
        perror("Error opening file");
        return EXIT_FAILURE;
    }
    printf("File opened successfully\n");
    
    fclose(pcap);

    return 0;
}
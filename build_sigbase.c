#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <arpa/inet.h>

// ---------------------------------------------------------------------------
// DNS wire format name encoding
// e.g. "quad.jmu.lab." -> 04 71756164 03 6a6d75 03 6c6162 00
// ---------------------------------------------------------------------------
int encode_name(const char *name, unsigned char *out) {
    int pos = 0;
    char tmp[256];
    strncpy(tmp, name, 255);
    tmp[255] = 0;

    // Remove trailing dot if present
    int len = strlen(tmp);
    if (len > 0 && tmp[len-1] == '.') tmp[len-1] = 0;

    // Lowercase the name
    for (int i = 0; tmp[i]; i++)
        if (tmp[i] >= 'A' && tmp[i] <= 'Z') tmp[i] += 32;

    // Encode each label
    char *label = strtok(tmp, ".");
    while (label) {
        int llen = strlen(label);
        out[pos++] = (unsigned char)llen;
        memcpy(out + pos, label, llen);
        pos += llen;
        label = strtok(NULL, ".");
    }
    out[pos++] = 0x00; // root label
    return pos;
}

// ---------------------------------------------------------------------------
// Convert BIND timestamp string YYYYMMDDHHmmSS to unix timestamp
// ---------------------------------------------------------------------------
uint32_t parse_timestamp(const char *ts) {
    struct tm t = {0};
    // Parse: YYYY MM DD HH mm SS
    sscanf(ts, "%4d%2d%2d%2d%2d%2d",
           &t.tm_year, &t.tm_mon, &t.tm_mday,
           &t.tm_hour, &t.tm_min, &t.tm_sec);
    t.tm_year -= 1900;  // tm_year is years since 1900
    t.tm_mon  -= 1;     // tm_mon is 0-11
    t.tm_isdst = 0;

    // Use timegm for UTC (not mktime which uses local time)
    return (uint32_t)timegm(&t);
}

// ---------------------------------------------------------------------------
// Convert dotted decimal IP string to 4 bytes
// ---------------------------------------------------------------------------
int parse_ip(const char *ip_str, unsigned char *out) {
    unsigned int a, b, c, d;
    if (sscanf(ip_str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) {
        fprintf(stderr, "Error: invalid IP address '%s'\n", ip_str);
        return 0;
    }
    out[0] = a; out[1] = b; out[2] = c; out[3] = d;
    return 1;
}

// ---------------------------------------------------------------------------
// Write a 2-byte big endian value
// ---------------------------------------------------------------------------
void write_u16(unsigned char *buf, int *pos, uint16_t val) {
    buf[(*pos)++] = (val >> 8) & 0xff;
    buf[(*pos)++] = val & 0xff;
}

// ---------------------------------------------------------------------------
// Write a 4-byte big endian value
// ---------------------------------------------------------------------------
void write_u32(unsigned char *buf, int *pos, uint32_t val) {
    buf[(*pos)++] = (val >> 24) & 0xff;
    buf[(*pos)++] = (val >> 16) & 0xff;
    buf[(*pos)++] = (val >> 8)  & 0xff;
    buf[(*pos)++] = val & 0xff;
}

// ---------------------------------------------------------------------------
// Sort IP addresses for canonical RRset ordering (RFC 4034 Section 6.3)
// For A records, sort numerically by IP value
// ---------------------------------------------------------------------------
int compare_ips(const void *a, const void *b) {
    uint32_t ia = ntohl(*(uint32_t*)a);
    uint32_t ib = ntohl(*(uint32_t*)b);
    return (ia > ib) - (ia < ib);
}

// ---------------------------------------------------------------------------
// Print a pretty hex dump with labels
// ---------------------------------------------------------------------------
void hexdump(const char *label, unsigned char *data, int len) {
    printf("\n=== %s (%d bytes) ===\n", label, len);
    for (int i = 0; i < len; i++) {
        if (i % 16 == 0) printf("%04x  ", i);
        printf("%02x ", data[i]);
        if ((i+1) % 8 == 0 && (i+1) % 16 != 0) printf(" ");
        if ((i+1) % 16 == 0) {
            printf(" |");
            for (int j = i-15; j <= i; j++)
                printf("%c", (data[j] >= 32 && data[j] < 127) ? data[j] : '.');
            printf("|\n");
        }
    }
    if (len % 16 != 0) {
        int rem = len % 16;
        for (int i = 0; i < 16-rem; i++) printf("   ");
        if (rem <= 8) printf(" ");
        printf(" |");
        for (int i = len-rem; i < len; i++)
            printf("%c", (data[i] >= 32 && data[i] < 127) ? data[i] : '.');
        printf("|\n");
    }
    printf("\n");
}

// ---------------------------------------------------------------------------
// Print a field-by-field breakdown of the signature base
// ---------------------------------------------------------------------------
void print_breakdown(unsigned char *buf, int len,
                     int signer_name_len, int owner_name_len,
                     int rdata_count) {
    int i = 0;
    printf("=== Field Breakdown ===\n");
    printf("  Type Covered   : %02x %02x       (%u)\n",
           buf[i], buf[i+1], (buf[i]<<8)|buf[i+1]); i+=2;
    printf("  Algorithm      : %02x          (%u)\n",
           buf[i], buf[i]); i+=1;
    printf("  Labels         : %02x          (%u)\n",
           buf[i], buf[i]); i+=1;
    printf("  Original TTL   : %02x %02x %02x %02x (%u)\n",
           buf[i],buf[i+1],buf[i+2],buf[i+3],
           (buf[i]<<24)|(buf[i+1]<<16)|(buf[i+2]<<8)|buf[i+3]); i+=4;
    printf("  Expiration     : %02x %02x %02x %02x (%u)\n",
           buf[i],buf[i+1],buf[i+2],buf[i+3],
           (buf[i]<<24)|(buf[i+1]<<16)|(buf[i+2]<<8)|buf[i+3]); i+=4;
    printf("  Inception      : %02x %02x %02x %02x (%u)\n",
           buf[i],buf[i+1],buf[i+2],buf[i+3],
           (buf[i]<<24)|(buf[i+1]<<16)|(buf[i+2]<<8)|buf[i+3]); i+=4;
    printf("  Key Tag        : %02x %02x       (%u)\n",
           buf[i], buf[i+1], (buf[i]<<8)|buf[i+1]); i+=2;

    printf("  Signer Name    : ");
    for (int j = 0; j < signer_name_len; j++) printf("%02x ", buf[i+j]);
    printf("\n"); i += signer_name_len;

    for (int r = 0; r < rdata_count; r++) {
        printf("  --- RR %d ---\n", r+1);
        printf("  Owner Name     : ");
        for (int j = 0; j < owner_name_len; j++) printf("%02x ", buf[i+j]);
        printf("\n"); i += owner_name_len;
        printf("  Type           : %02x %02x\n", buf[i], buf[i+1]); i+=2;
        printf("  Class          : %02x %02x\n", buf[i], buf[i+1]); i+=2;
        printf("  TTL            : %02x %02x %02x %02x\n",
               buf[i],buf[i+1],buf[i+2],buf[i+3]); i+=4;
        printf("  RDLENGTH       : %02x %02x\n", buf[i], buf[i+1]); i+=2;
        printf("  RDATA          : %02x %02x %02x %02x  (%u.%u.%u.%u)\n",
               buf[i],buf[i+1],buf[i+2],buf[i+3],
               buf[i],buf[i+1],buf[i+2],buf[i+3]); i+=4;
    }
    printf("\n");
}

// ---------------------------------------------------------------------------
// Main - fill in values from your dig output at the top
// ---------------------------------------------------------------------------
int main(void) {

    // =========================================================
    // FILL THESE IN FROM YOUR DIG OUTPUT
    // =========================================================

    // From the RRSIG record:
    uint16_t    type_covered = 1;                   // A=1, MX=15, NS=2, etc.
    uint8_t     algorithm    = 8;                   // 8 = RSASHA256
    uint8_t     labels       = 3;                   // count labels in owner name
    uint32_t    orig_ttl     = 86400;               // original TTL from RRSIG
    const char *expiration   = "20260408112304";    // from RRSIG
    const char *inception    = "20260325132346";    // from RRSIG
    uint16_t    key_tag      = 14329;               // from RRSIG

    // Names:
    const char *signers_name = "jmu.lab.";          // zone name
    const char *owner_name   = "quad.jmu.lab.";     // record owner

    // RRset - add all IPs if multiple A records exist:
    const char *ips[]  = { "192.168.107.64" };
    int         ip_count = 1;

    // =========================================================

    // Convert timestamps
    uint32_t sig_exp = parse_timestamp(expiration);
    uint32_t sig_inc = parse_timestamp(inception);

    printf("Expiration : %s -> 0x%08x (%u)\n", expiration, sig_exp, sig_exp);
    printf("Inception  : %s -> 0x%08x (%u)\n", inception,  sig_inc, sig_inc);

    // Encode names to wire format
    unsigned char signer_wire[256], owner_wire[256];
    int signer_len = encode_name(signers_name, signer_wire);
    int owner_len  = encode_name(owner_name,   owner_wire);

    // Parse and sort IP addresses
    unsigned char rdata[64][4];
    for (int i = 0; i < ip_count; i++)
        parse_ip(ips[i], rdata[i]);
    qsort(rdata, ip_count, 4, compare_ips);

    // Build the signature base
    unsigned char sigbase[65536];
    int pos = 0;

    // RRSIG RDATA fields
    write_u16(sigbase, &pos, type_covered);
    sigbase[pos++] = algorithm;
    sigbase[pos++] = labels;
    write_u32(sigbase, &pos, orig_ttl);
    write_u32(sigbase, &pos, sig_exp);
    write_u32(sigbase, &pos, sig_inc);
    write_u16(sigbase, &pos, key_tag);
    memcpy(sigbase + pos, signer_wire, signer_len);
    pos += signer_len;

    // RRset wire format
    for (int i = 0; i < ip_count; i++) {
        memcpy(sigbase + pos, owner_wire, owner_len);
        pos += owner_len;
        write_u16(sigbase, &pos, type_covered);  // type
        write_u16(sigbase, &pos, 1);             // class IN
        write_u32(sigbase, &pos, orig_ttl);      // TTL
        write_u16(sigbase, &pos, 4);             // RDLENGTH
        memcpy(sigbase + pos, rdata[i], 4);
        pos += 4;
    }

    // Print field breakdown
    print_breakdown(sigbase, pos, signer_len, owner_len, ip_count);

    // Print hex dump
    hexdump("Signature Base", sigbase, pos);

    // Write hex string to file
    FILE *f = fopen("sigbase.hex", "w");
    if (!f) { fprintf(stderr, "Error: cannot open output file\n"); return 1; }
    for (int i = 0; i < pos; i++) fprintf(f, "%02x", sigbase[i]);
    fclose(f);

    printf("Written to sigbase.hex (%d bytes)\n", pos);
    printf("\nHex string:\n");
    for (int i = 0; i < pos; i++) printf("%02x", sigbase[i]);
    printf("\n");

    return 0;
}
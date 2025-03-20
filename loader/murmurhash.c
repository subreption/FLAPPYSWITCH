#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include "murmurhash.h"

/*
 * MurmurHash3 (x86 32-bit) implementation with canonicalized little-endian reads.
 *
 * This function processes the input string in 4-byte chunks. Each chunk is
 * explicitly assembled from individual bytes in little-endian order. This
 * ensures consistent behavior on both little-endian and big-endian systems.
 */
uint32_t murmurhash(const char *key, uint32_t len, uint32_t seed)
{
    uint32_t c1 = 0xcc9e2d51;
    uint32_t c2 = 0x1b873593;
    uint32_t r1 = 15;
    uint32_t r2 = 13;
    uint32_t m  = 5;
    uint32_t n  = 0xe6546b64;
    uint32_t h = seed;
    uint32_t k = 0;
    uint32_t i, l = len / 4;
    const uint8_t *data = (const uint8_t *) key;
    const uint8_t *tail;

    /* process the body in 4-byte chunks. Construct each 32-bit block in little-endian order */
    for (i = 0; i < l; i++) {
        uint32_t idx = i * 4;
        k = ((uint32_t)data[idx]) |
            (((uint32_t)data[idx + 1]) << 8) |
            (((uint32_t)data[idx + 2]) << 16) |
            (((uint32_t)data[idx + 3]) << 24);

        k *= c1;
        k = (k << r1) | (k >> (32 - r1));
        k *= c2;

        h ^= k;
        h = (h << r2) | (h >> (32 - r2));
        h = h * m + n;
    }

    /* process the tail (remaining bytes) */
    tail = data + (l * 4);
    k = 0;
    switch (len & 3) {
        case 3:
            k ^= ((uint32_t)tail[2]) << 16;
        case 2:
            k ^= ((uint32_t)tail[1]) << 8;
        case 1:
            k ^= ((uint32_t)tail[0]);
            k *= c1;
            k = (k << r1) | (k >> (32 - r1));
            k *= c2;
            h ^= k;
            break;
        default:
            break;
    }

    /* finalization mix - force all bits of a hash block to avalanche */
    h ^= len;
    h ^= h >> 16;
    h *= 0x85ebca6b;
    h ^= h >> 13;
    h *= 0xc2b2ae35;
    h ^= h >> 16;

    return h;
}

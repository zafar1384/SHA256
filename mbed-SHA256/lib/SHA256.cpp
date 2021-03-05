// Author: Remco Bloemen
// Based on:
//   http://en.wikipedia.org/wiki/SHA-2
//   http://www.iwar.org.uk/comsec/resources/cipher/sha256-384-512.pdf
//   some of the OpenSSL optimizations

#include "SHA256.h"

inline unsigned int reverse_bytes(unsigned int num)
{
    //return __rev(x);
    
    return ( ((num & 0xFF000000) >>24 ) | ((num & 0x00FF0000)>>8 )| ((num & 0x0000FF00) << 8 ) | ((num & 0xFF) << 24 )); 
    
}

inline unsigned int rotate_right(unsigned int x, int shift)
{
     return (x >> shift) | (x << (32 - shift));
    //return __ror(x, shift);
}

void SHA256::reset()
{
    hash[0] = 0x6A09E667;
    hash[1] = 0xBB67AE85;
    hash[2] = 0x3C6EF372;
    hash[3] = 0xA54FF53A;
    hash[4] = 0x510E527F;
    hash[5] = 0x9B05688C;
    hash[6] = 0x1F83D9AB;
    hash[7] = 0x5BE0CD19;
    length = 0;
}

void SHA256::append(const char* data, int size)
{
    int index = length % 64;
    length += size;
    const char* end = data + size;
    
    // Word align data
    char* bytes = reinterpret_cast<char*>(w + (index / 4));
    switch(index % 4)
    {
        // Remember to reverse! (little endian!)
        case 1: bytes[2] = *data++; ++index;
        case 2: bytes[1] = *data++; ++index;
        case 3: bytes[0] = *data++; ++index;
        case 0: break;
    }
    if(data > end) {
        // We have overshot reading data
        // but w and length are correct
        return;
    }
    
    // Index is now word alligned
    index /= 4;
    if(index == 16) {
        process_chunk();
        index = 0;
    }
    
    // Process whole words
    int num_words = (end - data) / 4;
    const unsigned int* data_words = reinterpret_cast<const unsigned int*>(data);
    const unsigned int* data_words_end = data_words + num_words;
    while(data_words != data_words_end)
    {
        w[index++] = reverse_bytes(*data_words++);
        if(index == 16) {
            process_chunk();
            index = 0;
        }
    }
    
    // Process trailing data bytes
    // Again, we won't worry about overshooting data
    w[index] = reverse_bytes(*data_words);
}

void SHA256::finalize()
{
    int trailing = length % 64;
    
    // Append the bit '1' to the message
    int last_block = trailing / 4;
    unsigned int bit_in_block = 0x80 << (24 - (trailing % 4) * 8); 
    w[last_block] |= bit_in_block;
    
    // Set all other bits to zero
    w[last_block] &= ~(bit_in_block - 1);
    for(int i = last_block + 1; i < 16; ++i)
        w[i] = 0;
    
    // Make room for the length if necessary
    if(trailing >= 56) {
        process_chunk();
        for(int i = 0; i <= last_block; ++i)
            w[i] = 0;
    }
    
    // Append the length in bits
    w[14] = length >> (32 - 3);
    w[15] = length << 3;
    process_chunk();
    
    // Convert the result to big endian
    for(int i = 0; i < 8; ++i)
       hash[i] = reverse_bytes(hash[i]);
}

#define s0(x) (rotate_right(x, 7) ^ rotate_right(x, 18) ^ (x >> 3))
#define s1(x) (rotate_right(x, 17) ^ rotate_right(x, 19) ^ (x >> 10))
#define s2(x) (rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22))
#define s3(x) (rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25))
#define maj(a,b,c) ((a & b) ^ (a & c) ^ (b & c))
#define ch(a,b,c) ((a & b) ^ ((~a) & c))

const unsigned int k[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

#define ROUND(a,b,c,d,e,f,g,h,i) \
    h += w[i];\
    h += *K++;\
    h += s3(e); \
    h += ch(e, f, g); \
    d += h;\
    h += s2(a);\
    h += maj(a, b, c);

#define W(n) w[(n) & 0xf]

#define ROUND2(a,b,c,d,e,f,g,h,i) \
    W(i) += s0(W(i+1)) + W(i+9) + s1(W(i+14));\
    h += W(i); \
    h += *K++;\
    h += s3(e);\
    h += ch(e, f, g); \
    d += h;\
    h += s2(a);\
    h += maj(a, b, c);

// Process a 512 bit chunk stored in w[1...15]
void SHA256::process_chunk()
{
    // Initialize using current hash
    unsigned int a = hash[0];
    unsigned int b = hash[1];
    unsigned int c = hash[2];
    unsigned int d = hash[3];
    unsigned int e = hash[4];
    unsigned int f = hash[5];
    unsigned int g = hash[6];
    unsigned int h = hash[7];
    
    // Main loop
    const unsigned int* K = k;
    const unsigned int* K_end = k + 64;
    ROUND(a,b,c,d,e,f,g,h,0);
    ROUND(h,a,b,c,d,e,f,g,1);
    ROUND(g,h,a,b,c,d,e,f,2);
    ROUND(f,g,h,a,b,c,d,e,3);
    ROUND(e,f,g,h,a,b,c,d,4);
    ROUND(d,e,f,g,h,a,b,c,5);
    ROUND(c,d,e,f,g,h,a,b,6);
    ROUND(b,c,d,e,f,g,h,a,7);
    ROUND(a,b,c,d,e,f,g,h,8);
    ROUND(h,a,b,c,d,e,f,g,9);
    ROUND(g,h,a,b,c,d,e,f,10);
    ROUND(f,g,h,a,b,c,d,e,11);
    ROUND(e,f,g,h,a,b,c,d,12);
    ROUND(d,e,f,g,h,a,b,c,13);
    ROUND(c,d,e,f,g,h,a,b,14);
    ROUND(b,c,d,e,f,g,h,a,15);
    do {
        ROUND2(a,b,c,d,e,f,g,h,0);
        ROUND2(h,a,b,c,d,e,f,g,1);
        ROUND2(g,h,a,b,c,d,e,f,2);
        ROUND2(f,g,h,a,b,c,d,e,3);
        ROUND2(e,f,g,h,a,b,c,d,4);
        ROUND2(d,e,f,g,h,a,b,c,5);
        ROUND2(c,d,e,f,g,h,a,b,6);
        ROUND2(b,c,d,e,f,g,h,a,7);
        ROUND2(a,b,c,d,e,f,g,h,8);
        ROUND2(h,a,b,c,d,e,f,g,9);
        ROUND2(g,h,a,b,c,d,e,f,10);
        ROUND2(f,g,h,a,b,c,d,e,11);
        ROUND2(e,f,g,h,a,b,c,d,12);
        ROUND2(d,e,f,g,h,a,b,c,13);
        ROUND2(c,d,e,f,g,h,a,b,14);
        ROUND2(b,c,d,e,f,g,h,a,15);
    } while(K != K_end);
    
    // Update hash
    hash[0] += a;
    hash[1] += b;
    hash[2] += c;
    hash[3] += d;
    hash[4] += e;
    hash[5] += f;
    hash[6] += g;
    hash[7] += h; 
}

std::string SHA256::hexString()
{
    const char* hex = "0123456789abcdef";
    std::string hexstr(64, '0');
    for(int i = 0; i < 32; ++i) {
        hexstr[2 * i + 0] = hex[digest()[i] >> 4];
        hexstr[2 * i + 1] = hex[digest()[i] & 0xf];
    }
    return hexstr;
}

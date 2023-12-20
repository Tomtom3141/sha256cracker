#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>

#define MAX_STRING_LENGTH 256
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define Sigma1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define sigma0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define sigma1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

typedef struct {
    uint8_t data[SHA256_BLOCK_SIZE];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

// Constants for SHA-256
static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void sha256_transform(SHA256_CTX *ctx) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; i++, j += 4)
        m[i] = (ctx->data[j] << 24) | (ctx->data[j + 1] << 16) | (ctx->data[j + 2] << 8) | (ctx->data[j + 3]);

    for (; i < 64; i++)
        m[i] = sigma1(m[i - 2]) + m[i - 7] + sigma0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + Sigma1(e) + Ch(e, f, g) + K[i] + m[i];
        t2 = Sigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        ctx->data[ctx->datalen] = data[i];
        ctx->datalen++;
        if (ctx->datalen == SHA256_BLOCK_SIZE) {
            sha256_transform(ctx);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

void sha256_final(SHA256_CTX *ctx, uint8_t hash[SHA256_DIGEST_SIZE]) {
    uint32_t i = ctx->datalen;

    // Pad whatever data is left in the buffer
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56)
            ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < SHA256_BLOCK_SIZE)
            ctx->data[i++] = 0x00;
        sha256_transform(ctx);
        memset(ctx->data, 0, 56);
    }

    // Append the total bit length
    ctx->bitlen += ctx->datalen * 8;
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx);

    // Since the hash is stored little-endian, swap the bytes to big-endian
    for (i = 0; i < 4; i++) {
        hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0xff;
        hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0xff;
        hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0xff;
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0xff;
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0xff;
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0xff;
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0xff;
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0xff;
    }
}

//Bread and butter of program
void generate_random_string(char *random_string, int length) {
	//Determine the characterset that will be used to find the password
	//NOTE: longer charsets increase runtime
    static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':,.<>?";

    for (int i = 0; i < length; i++) {
        //Improves the randomness of character guessing
        srand((unsigned int) time(NULL));
        random_string[i] = charset[rand() % (sizeof(charset) - 1)];
    }

    random_string[length] = '\0';
}

int randomLength(int min, int max) {
    // Seed the random number generator using the current time
    srand((unsigned int)time(NULL));

    // Generate a random number between 0 and RAND_MAX
    int randomNumber = rand();

    // Map the random number to the desired range [min, max]
    int range = max - min + 1;
    int result = (randomNumber % range) + min;

    return result;
}

void sha256_to_string(const unsigned char hash[SHA256_DIGEST_SIZE], char output[SHA256_DIGEST_SIZE * 2 + 1]) {
    static const char hex_chars[] = "0123456789abcdef";

    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        output[i * 2] = hex_chars[(hash[i] >> 4) & 0xf];
        output[i * 2 + 1] = hex_chars[hash[i] & 0xf];
    }
    output[SHA256_DIGEST_SIZE * 2] = '\0';
}

int main(int argc, char *argv[]) {
	//Ensure proper argument count
    if (argc != 4) {
        printf("Usage: %s <SHA256 HASH> <MIN LENGTH> <MAX LENGTH>\n", argv[0]);
        return 1;
    }

    //Declare input variables
    char *sha256_input = argv[1];
    int min_length = atoi(argv[2]);
    int max_length = atoi(argv[3]);

    //Sanitize input
    if (min_length <= 0 || max_length <= 0 || min_length > max_length || max_length > MAX_STRING_LENGTH) {
        printf("Invalid input parameters.\n");
        return 1;
    }
	
	//The random string that will be hashed and compared
    char random_pass[MAX_STRING_LENGTH + 1];
	//The output of the random string that is hashed
    unsigned char hash_output[SHA256_DIGEST_SIZE];

    //Random Search
	bool found = false;
    while (!found) {
		//Have the program determine arbritrary guess length where min<=x<=max
		int length = randomLength(min_length, max_length);
		//Randomize the string contents to be hashed
        generate_random_string(random_pass, length);
		
		//hash the random guess
		SHA256_CTX ctx;
		sha256_init(&ctx);
		sha256_update(&ctx, (uint8_t *)random_pass, strlen(random_pass));
		sha256_final(&ctx, hash_output);

		//convert it into a string for hash comparison with the target
		char sha256_hash[65]; // 64 characters for SHA-256 hash + '\0'
        sha256_hash[64] = '\0';
		sha256_to_string(hash_output, sha256_hash);

        if (strcmp(sha256_hash, sha256_input) == 0) {
			found = true;
			printf("---------------------------------------------\n");
			printf("---------------------------------------------\n");
            printf("Generated hash matched the input SHA256 hash.\n");
            printf("Random string: %s\n", random_pass);
			printf("---------------------------------------------\n");
			printf("---------------------------------------------\n");
            return 0;
        }
		
		//DEBUGGING ONLY DISABLE AFTER TESTING
		//printf("random guess: %s\n", random_pass);
		//printf("hashed out: %s\n", sha256_hash);
    }

    printf("No match found. Try increasing the maximum password length.\n");
    return 1;
}

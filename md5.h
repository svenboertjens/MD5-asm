#ifndef ROUNDS_H
#define ROUNDS_H

#include <stdint.h>

// Holds the internal MD5 hash data
typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint8_t  todo_len;
    uint32_t blocks;
    char     todo[128];
} md5_states;

// Holds the MD5 digest states
typedef struct {
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint8_t  canary;
} md5_digest;

// Initialize the MD5 states struct
#define INIT_MD5_STATES(states) do { \
    (*states).a = 0x67452301; \
    (*states).b = 0xefcdab89; \
    (*states).c = 0x98badcfe; \
    (*states).d = 0x10325476; \
    (*states).blocks = 0; \
    (*states).todo_len = 0; \
} while (0)

/*
  # MD5_UPDATE USAGE:

  The input message should have the todo length padded before it,
  and shoult be sent with the padded length added to the input.
  The length to pad before the input message can also be the static
  size of 63 (at least, use 64 if you'd like).

  Example:

    size_t input_len = 256;
    char input[63 + input_len]; // This is the message we want to input
    input += 63;          // Add 63 to the input to start at YOUR input.

    // Place your message into the input
    fetch_input(input);

    // Send the input to the MD5 update function
    MD5_UPDATE(states, input, input_len)

*/

// Update the MD5 hash with a new input
void MD5_UPDATE(md5_states *states, const void *input, const size_t input_length);
// Digest the MD5 hash
void MD5_DIGEST(md5_digest *digest, const md5_states *states);

#endif // ROUNDS_H

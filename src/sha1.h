/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#pragma once

#include <string>
#include <array>

struct SHA1_CTX {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
};

void SHA1Init(SHA1_CTX* context);
void SHA1Update(SHA1_CTX* context, const uint8_t* data, uint32_t len);
void SHA1Final(std::array<uint8_t, 20>& digest, SHA1_CTX* context);
std::array<uint8_t, 20> sha1(const std::string& s);

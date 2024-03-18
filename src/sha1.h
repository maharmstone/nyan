/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#pragma once

#include <string>
#include <array>

class SHA1 {
public:
    SHA1();
    void update(const uint8_t* data, uint32_t len);
    void finalize(std::array<uint8_t, 20>& digest);

private:
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
};


/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#pragma once

#include <string>
#include <array>
#include <stdint.h>

class SHA1 {
public:
    SHA1();
    void update(const uint8_t* data, size_t len);
    std::array<uint8_t, 20> finalize();

private:
    uint32_t state[5];
    size_t count[2];
    unsigned char buffer[64];
};


#pragma once

#include <span>
#include <stdint.h>

template<typename Hasher>
decltype(Hasher{}.finalize()) authenticode(std::span<const uint8_t> file);

#pragma once

#include <span>
#include <vector>
#include <stdint.h>

template<typename Hasher>
decltype(Hasher{}.finalize()) authenticode(std::span<const uint8_t> file);

template<typename Hasher>
std::vector<std::pair<uint32_t, decltype(Hasher{}.finalize())>> get_page_hashes(std::span<const uint8_t> file);

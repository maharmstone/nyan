/* Copyright (c) Mark Harmstone 2024
 *
 * This file is part of Nyan.
 *
 * Nyan is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public Licence as published by
 * the Free Software Foundation, either version 2 of the Licence, or
 * (at your option) any later version.
 *
 * Nyan is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public Licence for more details.
 *
 * You should have received a copy of the GNU General Public Licence
 * along with Nyan. If not, see <https://www.gnu.org/licenses/>. */

#pragma once

#include <span>
#include <vector>
#include <stdint.h>

template<typename Hasher>
decltype(Hasher{}.finalize()) authenticode(std::span<const uint8_t> file);

template<typename Hasher>
std::vector<std::pair<uint32_t, decltype(Hasher{}.finalize())>> get_page_hashes(std::span<const uint8_t> file);

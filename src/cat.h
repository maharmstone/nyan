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

#include <string>
#include <filesystem>
#include <vector>
#include <span>

struct cat_extension {
    cat_extension(std::string_view name, uint32_t flags, std::u16string_view value) :
        name(name), flags(flags), value(value) {
    }

    std::string name;
    uint32_t flags;
    std::u16string value;
};

struct cat_entry {
    cat_entry(const std::filesystem::path& fn) : fn(fn) {
    }

    std::filesystem::path fn;
    std::vector<cat_extension> extensions;
};

template<typename Hasher>
class cat {
public:
    cat(std::span<const uint8_t> identifier, time_t time) : time(time) {
        this->identifier.assign(identifier.begin(), identifier.end());
    }

    std::vector<uint8_t> write(bool do_page_hashes);

    std::vector<cat_entry> entries;
    std::vector<cat_extension> extensions;

private:
    std::vector<uint8_t> identifier;
    time_t time;
};

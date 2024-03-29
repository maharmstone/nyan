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

#include <stdint.h>
#include <span>
#include <vector>
#include <stdexcept>
#include "pe.h"
#include "authenticode.h"
#include "sha1.h"
#include "sha256.h"

using namespace std;

template<typename Hasher> using hash_type = decltype(Hasher{}.finalize());

template<typename T, typename Hasher>
static hash_type<Hasher> authenticode2(span<const uint8_t> file, uint16_t num_sections,
                                       const T& opthead) {
    Hasher ctx;
    size_t bytes_hashed;

    ctx.update(file.data(), (uintptr_t)&opthead.CheckSum - (uintptr_t)file.data());
    ctx.update((const uint8_t*)&opthead.Subsystem, offsetof(T, DataDirectory) - offsetof(T, Subsystem));

    span dd(opthead.DataDirectory, opthead.NumberOfRvaAndSizes);

    ctx.update((const uint8_t*)dd.data(),
               min(dd.size(), IMAGE_DIRECTORY_ENTRY_CERTIFICATE) * sizeof(IMAGE_DATA_DIRECTORY));

    const uint8_t* ptr;
    uint32_t cert_size;

    if (opthead.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_CERTIFICATE) {
        ptr = (const uint8_t*)&dd[IMAGE_DIRECTORY_ENTRY_CERTIFICATE + 1];
        cert_size = dd[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].Size;
    } else {
        ptr = (const uint8_t*)&dd[opthead.NumberOfRvaAndSizes];
        cert_size = 0;
    }

    ctx.update(ptr, file.data() + opthead.SizeOfHeaders - ptr);
    bytes_hashed = opthead.SizeOfHeaders;

    auto sections = span((const IMAGE_SECTION_HEADER*)((uint8_t*)opthead.DataDirectory + (opthead.NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY))),
                         num_sections);

    // sections should be guaranteed to be sorted

    for (auto s : sections) {
        if (s.SizeOfRawData == 0)
            continue;

        if (s.PointerToRawData + s.SizeOfRawData > file.size())
            throw runtime_error("Section out of bounds.");

        ctx.update(file.data() + s.PointerToRawData, s.SizeOfRawData);
        bytes_hashed += s.SizeOfRawData;
    }

    if (file.size() > bytes_hashed)
        ctx.update(file.data() + bytes_hashed, file.size() - bytes_hashed - cert_size);

    return ctx.finalize();
}

template<typename Hasher>
hash_type<Hasher> authenticode(span<const uint8_t> file) {
    if (file.size() < sizeof(IMAGE_DOS_HEADER))
        throw runtime_error("File too short for IMAGE_DOS_HEADER.");

    auto& dos_header = *(const IMAGE_DOS_HEADER*)file.data();

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        throw runtime_error("Invalid DOS signature.");

    auto& nt_header = *(const IMAGE_NT_HEADERS*)(file.data() + dos_header.e_lfanew);

    if (file.size() < dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS))
        throw runtime_error("File too short for IMAGE_NT_HEADERS.");

    if (nt_header.Signature != IMAGE_NT_SIGNATURE)
        throw runtime_error("Incorrect PE signature.");

    switch (nt_header.OptionalHeader32.Magic) {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            return authenticode2<IMAGE_OPTIONAL_HEADER32, Hasher>(file, nt_header.FileHeader.NumberOfSections,
                                                                  nt_header.OptionalHeader32);

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            return authenticode2<IMAGE_OPTIONAL_HEADER64, Hasher>(file, nt_header.FileHeader.NumberOfSections,
                                                                  nt_header.OptionalHeader64);

        default:
            throw runtime_error("Invalid optional header magic.");
    }
}

template decltype(sha1_hasher{}.finalize()) authenticode<sha1_hasher>(span<const uint8_t> file);
template decltype(sha256_hasher{}.finalize()) authenticode<sha256_hasher>(span<const uint8_t> file);

template<typename T, typename Hasher>
static hash_type<Hasher> get_first_hash(span<const uint8_t> file, const T& opthead) {
    Hasher ctx;

    ctx.update(file.data(), (uintptr_t)&opthead.CheckSum - (uintptr_t)file.data());
    ctx.update((const uint8_t*)&opthead.Subsystem, offsetof(T, DataDirectory) - offsetof(T, Subsystem));

    span dd(opthead.DataDirectory, opthead.NumberOfRvaAndSizes);

    ctx.update((const uint8_t*)dd.data(),
               min(dd.size(), IMAGE_DIRECTORY_ENTRY_CERTIFICATE) * sizeof(IMAGE_DATA_DIRECTORY));

    const uint8_t* ptr;

    if (opthead.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_CERTIFICATE)
        ptr = (const uint8_t*)&dd[IMAGE_DIRECTORY_ENTRY_CERTIFICATE + 1];
    else
        ptr = (const uint8_t*)&dd[opthead.NumberOfRvaAndSizes];

    ctx.update(ptr, file.data() + opthead.SizeOfHeaders - ptr);

    if (opthead.SizeOfHeaders < opthead.SectionAlignment) {
        vector<uint8_t> padding(opthead.SectionAlignment - opthead.SizeOfHeaders, 0);

        ctx.update(padding.data(), padding.size());
    }

    return ctx.finalize();
}

template<typename Hasher>
vector<pair<uint32_t, hash_type<Hasher>>> get_page_hashes(span<const uint8_t> file) {
    vector<pair<uint32_t, hash_type<Hasher>>> ret;

    if (file.size() < sizeof(IMAGE_DOS_HEADER))
        throw runtime_error("File too short for IMAGE_DOS_HEADER.");

    auto& dos_header = *(const IMAGE_DOS_HEADER*)file.data();

    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE)
        throw runtime_error("Invalid DOS signature.");

    auto& nt_header = *(const IMAGE_NT_HEADERS*)(file.data() + dos_header.e_lfanew);

    if (file.size() < dos_header.e_lfanew + sizeof(IMAGE_NT_HEADERS))
        throw runtime_error("File too short for IMAGE_NT_HEADERS.");

    if (nt_header.Signature != IMAGE_NT_SIGNATURE)
        throw runtime_error("Incorrect PE signature.");

    span<const IMAGE_SECTION_HEADER> sections;
    uint32_t page_size;

    switch (nt_header.OptionalHeader32.Magic) {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:
            ret.emplace_back(0, get_first_hash<IMAGE_OPTIONAL_HEADER32, Hasher>(file, nt_header.OptionalHeader32));
            page_size = nt_header.OptionalHeader32.SectionAlignment;
            sections = span((const IMAGE_SECTION_HEADER*)((uint8_t*)nt_header.OptionalHeader32.DataDirectory + (nt_header.OptionalHeader32.NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY))),
                            nt_header.FileHeader.NumberOfSections);
            break;

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            ret.emplace_back(0, get_first_hash<IMAGE_OPTIONAL_HEADER64, Hasher>(file, nt_header.OptionalHeader64));
            page_size = nt_header.OptionalHeader64.SectionAlignment;
            sections = span((const IMAGE_SECTION_HEADER*)((uint8_t*)nt_header.OptionalHeader64.DataDirectory + (nt_header.OptionalHeader64.NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY))),
                            nt_header.FileHeader.NumberOfSections);
            break;

        default:
            throw runtime_error("Invalid optional header magic.");
    }

    for (const auto& sect : sections) {
        if (sect.SizeOfRawData == 0)
            continue;

        uint64_t off = 0;
        while (off < sect.SizeOfRawData) {
            Hasher ctx;

            if (off + page_size <= sect.SizeOfRawData)
                ctx.update(file.data() + sect.PointerToRawData + off, page_size);
            else {
                ctx.update(file.data() + sect.PointerToRawData + off, sect.SizeOfRawData - off);

                vector<uint8_t> padding(page_size - (sect.SizeOfRawData - off), 0);

                ctx.update(padding.data(), padding.size());
            }

            ret.emplace_back(sect.PointerToRawData + off, ctx.finalize());

            off += page_size;
        }
    }

    hash_type<Hasher> zero_hash;

    memset(zero_hash.data(), 0, sizeof(zero_hash));

    ret.emplace_back(sections.back().PointerToRawData + sections.back().SizeOfRawData, zero_hash);

    return ret;
}

template vector<pair<uint32_t, decltype(sha1_hasher{}.finalize())>> get_page_hashes<sha1_hasher>(span<const uint8_t> file);
template vector<pair<uint32_t, decltype(sha256_hasher{}.finalize())>> get_page_hashes<sha256_hasher>(span<const uint8_t> file);

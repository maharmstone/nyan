#include <stdint.h>
#include <span>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include "pe.h"
#include "authenticode.h"
#include "sha1.h"
#include "sha256.h"

using namespace std;

template<typename T, typename Hasher>
static decltype(Hasher{}.finalize()) authenticode2(span<const uint8_t> file, uint16_t num_sections,
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

    vector<const IMAGE_SECTION_HEADER*> sections;

    sections.reserve(num_sections);

    auto sectspan = span((const IMAGE_SECTION_HEADER*)((uint8_t*)opthead.DataDirectory + (opthead.NumberOfRvaAndSizes * sizeof(IMAGE_DATA_DIRECTORY))),
                         num_sections);
    for (const auto& s : sectspan) {
        if (s.SizeOfRawData == 0)
            continue;

        sections.push_back(&s);
    }

    sort(sections.begin(), sections.end(), [](const auto& a, const auto& b) {
        return a->PointerToRawData < b->PointerToRawData;
    });

    for (auto s : sections) {
        if (s->PointerToRawData + s->SizeOfRawData > file.size())
            throw runtime_error("Section out of bounds.");

        ctx.update(file.data() + s->PointerToRawData, s->SizeOfRawData);
        bytes_hashed += s->SizeOfRawData;
    }

    if (file.size() > bytes_hashed)
        ctx.update(file.data() + bytes_hashed, file.size() - bytes_hashed - cert_size);

    return ctx.finalize();
}

template<typename Hasher>
decltype(Hasher{}.finalize()) authenticode(span<const uint8_t> file) {
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

template decltype(SHA1{}.finalize()) authenticode<SHA1>(span<const uint8_t> file);
template decltype(SHA256{}.finalize()) authenticode<SHA256>(span<const uint8_t> file);

#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <iostream>
#include <span>
#include <format>
#include <vector>
#include <algorithm>
#include "pe.h"
#include "sha1.h"

using namespace std;

template<typename T>
static void authenticode2(span<const uint8_t> file, uint16_t num_sections, const T& opthead) {
    SHA1 ctx;
    size_t bytes_hashed;

    ctx.update(file.data(), (uint32_t)((uintptr_t)&opthead.CheckSum - (uintptr_t)file.data()));
    ctx.update((const uint8_t*)&opthead.Subsystem, offsetof(T, DataDirectory) - offsetof(T, Subsystem));

    span dd(opthead.DataDirectory, opthead.NumberOfRvaAndSizes);

    ctx.update((const uint8_t*)dd.data(),
               (uint32_t)min(dd.size(), IMAGE_DIRECTORY_ENTRY_CERTIFICATE) * sizeof(IMAGE_DATA_DIRECTORY));

    const uint8_t* ptr;
    uint32_t cert_size;

    if (opthead.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_CERTIFICATE) {
        ptr = (const uint8_t*)&dd[IMAGE_DIRECTORY_ENTRY_CERTIFICATE + 1];
        cert_size = dd[IMAGE_DIRECTORY_ENTRY_CERTIFICATE].Size;
    } else {
        ptr = (const uint8_t*)&dd[opthead.NumberOfRvaAndSizes];
        cert_size = 0;
    }

    ctx.update(ptr, (uint32_t)(file.data() + opthead.SizeOfHeaders - ptr));
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
        ctx.update(file.data() + bytes_hashed, (uint32_t)(file.size() - bytes_hashed - cert_size));

    auto digest = ctx.finalize();

    string hash;

    for (auto b : digest) {
        hash += format("{:02x}", b);
    }

    // FIXME - include file name, like sha1sum

    cout << format("{}\n", hash);
}

static void authenticode(span<const uint8_t> file) {
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
            authenticode2(file, nt_header.FileHeader.NumberOfSections,
                          nt_header.OptionalHeader32);
            break;

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            authenticode2(file, nt_header.FileHeader.NumberOfSections,
                          nt_header.OptionalHeader64);
            break;

        default:
            throw runtime_error("Invalid optional header magic.");
    }
}

static void calc_authenticode(const char* fn) {
    int fd = open(fn, O_RDONLY);

    if (fd == -1)
        throw runtime_error("open failed (errno " + to_string(errno) + ")");

    struct stat st;

    if (fstat(fd, &st) == -1) {
        auto err = errno;
        close(fd);
        throw runtime_error("fstat failed (errno " + to_string(err) + ")");
    }

    size_t length = st.st_size;

    void* addr = mmap(nullptr, length, PROT_READ, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED) {
        auto err = errno;
        close(fd);
        throw runtime_error("mmap failed (errno " + to_string(err) + ")");
    }

    try {
        authenticode(span((uint8_t*)addr, length));
    } catch (...) {
        munmap(addr, length);
        close(fd);
        throw;
    }

    munmap(addr, length);
    close(fd);
}

int main() {
    // FIXME - parse arguments

    try {
        calc_authenticode("/home/nobackup/btrfs-package/1.9/release/amd64/mkbtrfs.exe");
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }

    return 0;
}


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
#include "sha256.h"

using namespace std;

template<typename T, typename Hasher>
static void authenticode2(span<const uint8_t> file, uint16_t num_sections,
                          const T& opthead, string_view fn) {
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

    auto digest = ctx.finalize();

    string hash;

    for (auto b : digest) {
        hash += format("{:02x}", b);
    }

    cout << format("{}  {}\n", hash, fn);
}

template<typename Hasher>
static void authenticode(span<const uint8_t> file, string_view fn) {
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
            authenticode2<IMAGE_OPTIONAL_HEADER32, Hasher>(file, nt_header.FileHeader.NumberOfSections,
                                                           nt_header.OptionalHeader32, fn);
            break;

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            authenticode2<IMAGE_OPTIONAL_HEADER64, Hasher>(file, nt_header.FileHeader.NumberOfSections,
                                                           nt_header.OptionalHeader64, fn);
            break;

        default:
            throw runtime_error("Invalid optional header magic.");
    }
}

template<typename Hasher>
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
        authenticode<Hasher>(span((uint8_t*)addr, length), fn);
    } catch (...) {
        munmap(addr, length);
        close(fd);
        throw;
    }

    munmap(addr, length);
    close(fd);
}

enum class hash_type {
    sha1,
    sha256
};

int main(int argc, char* argv[]) {
    if (argc < 2 || !strcmp(argv[1], "--help")) {
        cerr << format(R"(Usage: {} [--sha1 | --sha256] [FILE]...
Print the Authenticode hash of PE files.

      --sha1        output SHA1 hash
      --sha256      output SHA256 hash
      --help        display this help and exit
)", argv[0]);

        return 1;
    }

    enum hash_type type;

    if (!strcmp(argv[1], "--sha1"))
        type = hash_type::sha1;
    else if (!strcmp(argv[1], "--sha256"))
        type = hash_type::sha256;
    else {
        cerr << argv[0] << ": first argument must be either --sha1 or --sha256." << endl;
        return 1;
    }

    // FIXME - reading from stdin

    for (int i = 2; i < argc; i++) {
        try {
            switch (type) {
                case hash_type::sha1:
                    calc_authenticode<SHA1>(argv[i]);
                break;

                case hash_type::sha256:
                    calc_authenticode<SHA256>(argv[i]);
                break;
            }
        } catch (const exception& e) {
            cerr << "Exception: " << e.what() << endl;
        }
    }

    return 0;
}


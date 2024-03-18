#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <iostream>
#include <span>
#include "pe.h"

using namespace std;

template<typename T>
static void authenticode2(span<const uint8_t> file, const T& opthead) {
    // FIXME
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
            authenticode2(file, nt_header.OptionalHeader32);
            break;

        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:
            authenticode2(file, nt_header.OptionalHeader64);
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


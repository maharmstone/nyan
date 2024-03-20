#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <iostream>
#include <format>
#include <string.h>
#include "sha1.h"
#include "sha256.h"
#include "config.h"
#include "authenticode.h"

using namespace std;

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
        auto digest = authenticode<Hasher>(span((uint8_t*)addr, length));

        string hash;

        for (auto b : digest) {
            hash += format("{:02x}", b);
        }

        cout << format("{}  {}\n", hash, fn);
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
        cerr << format(R"(Usage: {} [--sha1 | --sha256] FILE...
Print the Authenticode hash of PE files.

      --sha1        output SHA1 hash
      --sha256      output SHA256 hash
      --help        display this help and exit
      --version     output version information and exit
)", argv[0]);

        return 1;
    }

    if (!strcmp(argv[1], "--version")) {
        cerr << "authenticode " << PROJECT_VERSION_MAJOR << endl;
        cerr << "Copyright (c) Mark Harmstone 2024" << endl;
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

    if (argc < 3) {
        cerr << argv[0] << ": at least one file must be specified." << endl;
        return 1;
    }

    for (int i = 2; i < argc; i++) {
        try {
            switch (type) {
                case hash_type::sha1:
                    calc_authenticode<sha1_hasher>(argv[i]);
                break;

                case hash_type::sha256:
                    calc_authenticode<sha256_hasher>(argv[i]);
                break;
            }
        } catch (const exception& e) {
            cerr << format("{}: {}: {}\n", argv[0], argv[i], e.what());
        }
    }

    return 0;
}

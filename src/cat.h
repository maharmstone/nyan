#pragma once

#include <string>
#include <filesystem>
#include <vector>

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
    cat(std::string_view identifier, time_t time) : identifier(identifier), time(time) {
    }

    std::vector<uint8_t> write(bool do_page_hashes);

    std::vector<cat_entry> entries;
    std::vector<cat_extension> extensions;

private:
    std::string identifier;
    time_t time;
};

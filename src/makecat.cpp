#include <filesystem>
#include <iostream>
#include <fstream>
#include <charconv>
#include <vector>
#include <unordered_map>
#include <random>
#include <format>
#include "cat.h"
#include "sha1.h"
#include "sha256.h"
#include "config.h"

using namespace std;

enum class cdf_section {
    none,
    CatalogHeader,
    CatalogFiles
};

enum class cdf_algorithm {
    none,
    SHA1,
    SHA256
};

static constexpr size_t utf8_to_utf16_len(string_view sv) noexcept {
    size_t ret = 0;

    while (!sv.empty()) {
        if ((uint8_t)sv[0] < 0x80) {
            ret++;
            sv = sv.substr(1);
        } else if (((uint8_t)sv[0] & 0xe0) == 0xc0 && (uint8_t)sv.length() >= 2 && ((uint8_t)sv[1] & 0xc0) == 0x80) {
            ret++;
            sv = sv.substr(2);
        } else if (((uint8_t)sv[0] & 0xf0) == 0xe0 && (uint8_t)sv.length() >= 3 && ((uint8_t)sv[1] & 0xc0) == 0x80 && ((uint8_t)sv[2] & 0xc0) == 0x80) {
            ret++;
            sv = sv.substr(3);
        } else if (((uint8_t)sv[0] & 0xf8) == 0xf0 && (uint8_t)sv.length() >= 4 && ((uint8_t)sv[1] & 0xc0) == 0x80 && ((uint8_t)sv[2] & 0xc0) == 0x80 && ((uint8_t)sv[3] & 0xc0) == 0x80) {
            char32_t cp = (char32_t)(((uint8_t)sv[0] & 0x7) << 18) | (char32_t)(((uint8_t)sv[1] & 0x3f) << 12) | (char32_t)(((uint8_t)sv[2] & 0x3f) << 6) | (char32_t)((uint8_t)sv[3] & 0x3f);

            if (cp > 0x10ffff) {
                ret++;
                sv = sv.substr(4);
                continue;
            }

            ret += 2;
            sv = sv.substr(4);
        } else {
            ret++;
            sv = sv.substr(1);
        }
    }

    return ret;
}

template<typename T>
requires (ranges::output_range<T, char16_t> && is_same_v<ranges::range_value_t<T>, char16_t>) ||
    (sizeof(wchar_t) == 2 && ranges::output_range<T, wchar_t> && is_same_v<ranges::range_value_t<T>, wchar_t>)
static constexpr void utf8_to_utf16_range(string_view sv, T& t) noexcept {
    auto ptr = t.begin();

    if (ptr == t.end())
        return;

    while (!sv.empty()) {
        if ((uint8_t)sv[0] < 0x80) {
            *ptr = (uint8_t)sv[0];
            ptr++;

            if (ptr == t.end())
                return;

            sv = sv.substr(1);
        } else if (((uint8_t)sv[0] & 0xe0) == 0xc0 && (uint8_t)sv.length() >= 2 && ((uint8_t)sv[1] & 0xc0) == 0x80) {
            char16_t cp = (char16_t)(((uint8_t)sv[0] & 0x1f) << 6) | (char16_t)((uint8_t)sv[1] & 0x3f);

            *ptr = cp;
            ptr++;

            if (ptr == t.end())
                return;

            sv = sv.substr(2);
        } else if (((uint8_t)sv[0] & 0xf0) == 0xe0 && (uint8_t)sv.length() >= 3 && ((uint8_t)sv[1] & 0xc0) == 0x80 && ((uint8_t)sv[2] & 0xc0) == 0x80) {
            char16_t cp = (char16_t)(((uint8_t)sv[0] & 0xf) << 12) | (char16_t)(((uint8_t)sv[1] & 0x3f) << 6) | (char16_t)((uint8_t)sv[2] & 0x3f);

            if (cp >= 0xd800 && cp <= 0xdfff) {
                *ptr = 0xfffd;
                ptr++;

                if (ptr == t.end())
                    return;

                sv = sv.substr(3);
                continue;
            }

            *ptr = cp;
            ptr++;

            if (ptr == t.end())
                return;

            sv = sv.substr(3);
        } else if (((uint8_t)sv[0] & 0xf8) == 0xf0 && (uint8_t)sv.length() >= 4 && ((uint8_t)sv[1] & 0xc0) == 0x80 && ((uint8_t)sv[2] & 0xc0) == 0x80 && ((uint8_t)sv[3] & 0xc0) == 0x80) {
            char32_t cp = (char32_t)(((uint8_t)sv[0] & 0x7) << 18) | (char32_t)(((uint8_t)sv[1] & 0x3f) << 12) | (char32_t)(((uint8_t)sv[2] & 0x3f) << 6) | (char32_t)((uint8_t)sv[3] & 0x3f);

            if (cp > 0x10ffff) {
                *ptr = 0xfffd;
                ptr++;

                if (ptr == t.end())
                    return;

                sv = sv.substr(4);
                continue;
            }

            cp -= 0x10000;

            *ptr = (char16_t)(0xd800 | (cp >> 10));
            ptr++;

            if (ptr == t.end())
                return;

            *ptr = (char16_t)(0xdc00 | (cp & 0x3ff));
            ptr++;

            if (ptr == t.end())
                return;

            sv = sv.substr(4);
        } else {
            *ptr = 0xfffd;
            ptr++;

            if (ptr == t.end())
                return;

            sv = sv.substr(1);
        }
    }
}

static constexpr u16string utf8_to_utf16(string_view sv) {
    if (sv.empty())
        return u"";

    u16string ret(utf8_to_utf16_len(sv), 0);

    utf8_to_utf16_range(sv, ret);

    return ret;
}

struct string_hash {
    using hash_type = hash<string_view>;
    using is_transparent = void;

    size_t operator()(const char* str) const {
        return hash_type{}(str);
    }

    size_t operator()(string_view str) const {
        return hash_type{}(str);
    }

    size_t operator()(const string& str) const {
        return hash_type{}(str);
    }
};

static void parse_attribute(vector<cat_extension>& attributes, string_view value, unsigned int line_no) {
    string_view type, oid, val;
    unsigned int type_num;

    if (auto colon = value.find(':'); colon != string::npos) {
        type = value.substr(0, colon);
        oid = value.substr(colon + 1);
    } else
        throw runtime_error("Line " + to_string(line_no) + ": ATTR value must have form {type}:{oid}:{value}.");

    if (auto colon = oid.find(':'); colon != string::npos) {
        val = oid.substr(colon + 1);
        oid = oid.substr(0, colon);
    } else
        throw runtime_error("Line " + to_string(line_no) + ": ATTR value must have form {type}:{oid}:{value}.");

    if (type.substr(0, 2) == "0x") {
        auto [ptr, ec] = from_chars(type.begin() + 2, type.end(), type_num, 16);

        if (ptr != type.end())
            throw runtime_error("Line " + to_string(line_no) + ": could not parse type " + string(type) + " as integer.");
    } else {
        auto [ptr, ec] = from_chars(type.begin(), type.end(), type_num);

        if (ptr != value.end())
            throw runtime_error("Line " + to_string(line_no) + ": could not parse type " + string(type) + " as integer.");
    }

    if (type_num & 0x00020000)
        throw runtime_error("Line " + to_string(line_no) + ": base64 values not yet supported.");

    if (type_num & 0x00000002)
        throw runtime_error("Line " + to_string(line_no) + ": OIDs not yet supported.");

    attributes.emplace_back(oid, type_num, utf8_to_utf16(val));
}

// FIXME - is this actually random, or should it be a hash? (Does it matter?)
static vector<uint8_t> create_identifier() {
    random_device dev;
    mt19937 rng(dev());
    uniform_int_distribution<mt19937::result_type> dist(0, 0xffffffff);
    vector<uint8_t> ret;

    ret.reserve(16);

    for (unsigned int i = 0; i < 4; i++) {
        auto v = (uint32_t)dist(rng);

        auto sp = span((uint8_t*)&v, sizeof(uint32_t));

        ret.insert(ret.end(), sp.begin(), sp.end());
    }

    return ret;
}

static void make_cat(const filesystem::path& fn) {
    ifstream f(fn);

    // FIXME - throw more descriptive error message (not found, access denied, etc.)
    if (!f.is_open())
        throw runtime_error("Could not open " + fn.string() + " for reading.");

    enum cdf_section sect = cdf_section::none;
    unsigned int line_no = 0;
    string cat_name, result_dir;
    unsigned int catalogue_version = 0;
    enum cdf_algorithm algo = cdf_algorithm::none;
    bool do_page_hashes = false;
    unsigned int encoding_type = 0x00010001; // PKCS_7_ASN_ENCODING | X509_ASN_ENCODING
    vector<cat_extension> attributes;
    unordered_map<string, cat_entry, string_hash, equal_to<>> entries;

    while (!f.eof()) {
        string line;

        getline(f, line);
        line_no++;

        if (line.empty())
            continue;

        if (line.front() == '[') {
            auto end = line.find(']');

            if (end == string::npos)
                throw runtime_error("Line " + to_string(line_no) + ": square brackets not terminated.");

            auto sectname = string_view(line.data() + 1, end - 1);

            if (sectname == "CatalogHeader")
                sect = cdf_section::CatalogHeader;
            else if (sectname == "CatalogFiles")
                sect = cdf_section::CatalogFiles;
            else
                throw runtime_error("Line " + to_string(line_no) + ": unrecognized section name " + string(sectname) + ".");

            continue;
        }

        auto sv = string_view(line);

        while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) {
            sv = sv.substr(1);
        }

        while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r')) {
            sv = sv.substr(0, sv.size() - 1);
        }

        if (sv.empty())
            continue;

        // FIXME - can we have comments?

        auto eq = sv.find('=');

        if (eq == string::npos)
            throw runtime_error("Line " + to_string(line_no) + ": error while parsing.");

        auto name = sv.substr(0, eq);
        auto value = sv.substr(eq + 1);

        switch (sect) {
            case cdf_section::none:
                throw runtime_error("Line " + to_string(line_no) + ": name-value pair outside of section.");

            case cdf_section::CatalogHeader:
                if (name == "Name")
                    cat_name = value;
                else if (name == "ResultDir")
                    result_dir = value;
                else if (name == "CatalogVersion") {
                    if (value.empty())
                        break;

                    auto [ptr, ec] = from_chars(value.begin(), value.end(), catalogue_version);

                    if (ptr != value.end())
                        throw runtime_error("Line " + to_string(line_no) + ": could not parse " + string(value) + " as integer.");

                    if (catalogue_version != 1 && catalogue_version != 2)
                        throw runtime_error("Line " + to_string(line_no) + ": invalid value " + to_string(catalogue_version) + " for CatalogVersion.");
                } else if (name == "HashAlgorithms") {
                    if (value.empty())
                        algo = cdf_algorithm::none;
                    else if (value == "SHA1")
                        algo = cdf_algorithm::SHA1;
                    else if (value == "SHA256")
                        algo = cdf_algorithm::SHA256;
                    else
                        throw runtime_error("Line " + to_string(line_no) + ": invalid value " + string(value) + " for HashAlgorithms.");
                } else if (name == "PageHashes") {
                    if (value == "true")
                        do_page_hashes = true;
                    else if (value == "false")
                        do_page_hashes = false;
                    else
                        throw runtime_error("Line " + to_string(line_no) + ": invalid value " + string(value) + " for PageHashes.");
                } else if (name == "EncodingType") {
                    if (value.substr(0, 2) == "0x") {
                        auto [ptr, ec] = from_chars(value.begin() + 2, value.end(), encoding_type, 16);

                        if (ptr != value.end())
                            throw runtime_error("Line " + to_string(line_no) + ": could not parse " + string(value) + " as integer.");
                    } else {
                        auto [ptr, ec] = from_chars(value.begin(), value.end(), encoding_type);

                        if (ptr != value.end())
                            throw runtime_error("Line " + to_string(line_no) + ": could not parse " + string(value) + " as integer.");
                    }

                    if (encoding_type != 0x00010001)
                        throw runtime_error("Line " + to_string(line_no) + ": unsupported value " + string(value) + " for EncodingType.");
                } else if (name.substr(0, 7) == "CATATTR")
                    parse_attribute(attributes, value, line_no);
                else
                    throw runtime_error("Line " + to_string(line_no) + ": unrecognized option " + string(name) + " in CatalogHeader section.");
            break;

            case cdf_section::CatalogFiles:
                if (name.size() > 8 && name.substr(name.size() - 8) == "ALTSIPID")
                    throw runtime_error("Line " + to_string(line_no) + ": ALTSIPID not yet supported.");

                if (auto attr = name.find("ATTR"); attr != string::npos) {
                    auto [ptr, ec] = from_chars(name.begin() + attr + 4, name.end(), encoding_type, 16);

                    if (ptr == name.end() && entries.count(name.substr(0, attr)) != 0) {
                        auto it = entries.find(name.substr(0, attr));
                        auto& ent = it->second;

                        parse_attribute(ent.extensions, value, line_no);
                        break;
                    }
                }

                if (entries.count(name) != 0)
                    throw runtime_error("Line " + to_string(line_no) + ": file " + string(name) + " already set.");

                if constexpr (filesystem::path::preferred_separator != '\\') {
                    string value2;

                    value2.reserve(value.size());

                    for (auto c : value) {
                        if (c == '\\')
                            value2 += filesystem::path::preferred_separator;
                        else
                            value2 += c;
                    }

                    entries.emplace(make_pair(name, value2));
                } else
                    entries.emplace(make_pair(name, value));
            break;
        }
    }

    switch (catalogue_version) {
        case 0:
            switch (algo) {
                case cdf_algorithm::SHA1:
                    catalogue_version = 1;
                break;

                case cdf_algorithm::SHA256:
                    catalogue_version = 2;
                break;

                case cdf_algorithm::none:
                    catalogue_version = 1;
                    algo = cdf_algorithm::SHA1;
                break;
            }
        break;

        case 1:
            if (algo == cdf_algorithm::SHA256)
                throw runtime_error("CatalogVersion must be 2 if HashAlgorithms is SHA256.");
            algo = cdf_algorithm::SHA1;
        break;

        case 2:
            if (algo == cdf_algorithm::SHA1)
                throw runtime_error("CatalogVersion must be 1 if HashAlgorithms is SHA1.");
            algo = cdf_algorithm::SHA256;
        break;
    }

    if (cat_name.empty())
        throw runtime_error("No value specified for Name.");

    vector<uint8_t> v;

    auto identifier = create_identifier();

    auto lambda = [&]<typename Hasher>() {
        cat<Hasher> c(identifier, time(nullptr));

        for (const auto& ent : entries) {
            if (ent.first.substr(0, 6) != "<HASH>")
                throw runtime_error("Only catalogue files with identifiers beginning <HASH> are supported.");

            c.entries.emplace_back(ent.second);
        }

        c.extensions = attributes;

        v = c.write(do_page_hashes);
    };

    switch (algo) {
        case cdf_algorithm::SHA1:
            lambda.template operator()<sha1_hasher>();
        break;

        case cdf_algorithm::SHA256:
            lambda.template operator()<sha256_hasher>();
        break;

        default:
        break;
    }

    filesystem::path outfn;

    // FIXME - Microsoft makecat creates result_dir if it doesn't already exist
    if (!result_dir.empty())
        outfn = filesystem::path{result_dir} / cat_name;
    else
        outfn = cat_name;

    {
        ofstream out(outfn, ios::binary);

        // FIXME - better error messages
        if (!out.is_open())
            throw runtime_error("Could not open " + outfn.string() + " for writing.");

        out.write((char*)v.data(), v.size());
    }
}

int main(int argc, char* argv[]) {
    // FIXME - reading from STDIN and writing to STDOUT

    if (argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-?")) {
        cerr << format(R"(Usage: {} FILE
Creates a catalogue file from a CDF file.

      --help, -?    display this help and exit
      --version     output version information and exit
)", argv[0]);

        return 1;
    }

    if (!strcmp(argv[1], "--version")) {
        cerr << "makecat " << PROJECT_VERSION_MAJOR << endl;
        cerr << "Copyright (c) Mark Harmstone 2024" << endl;
        return 1;
    }

    // FIXME - parse options (-v, -r, -n)

    try {
        make_cat(argv[1]);
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}

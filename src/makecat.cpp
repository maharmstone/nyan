#include <filesystem>
#include <iostream>
#include <fstream>
#include <charconv>
#include <vector>
#include "cat.h"
#include "sha1.h"
#include "sha256.h"

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
    vector<tuple<unsigned int, string, string>> attributes;

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
                } else if (name.substr(0, 7) == "CATATTR") {
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

                    attributes.emplace_back(type_num, oid, val);
                } else
                    throw runtime_error("Line " + to_string(line_no) + ": unrecognized option " + string(name) + " in CatalogHeader section.");
            break;
        }

        // FIXME - CatalogFiles
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
            algo = cdf_algorithm::SHA1;
        break;
    }

    if (cat_name.empty())
        throw runtime_error("No value specified for Name.");

    vector<uint8_t> v;

    auto lambda = [&]<typename Hasher>() {
        cat<Hasher> c("C8D7FC7596D61245B5B59565B67D8573", 1710345480); // 2024-03-13 15:58:00 (FIXME)

        // c.entries.emplace_back("/home/nobackup/btrfs-package/1.9/release/amd64/mkbtrfs.exe");
        // c.entries.back().extensions.emplace_back("File", 0x10010001, u"mkbtrfs.exe");
        // c.entries.back().extensions.emplace_back("OSAttr", 0x10010001, u"2:5.1,2:5.2,2:6.0,2:6.1,2:6.2,2:6.3,2:10.0");

        for (const auto& att : attributes) {
            c.extensions.emplace_back(get<1>(att), get<0>(att), utf8_to_utf16(get<2>(att)));
        }

        v = c.write();
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

    cout << "Succeeded" << endl;
}

int main() {
    // FIXME - parse options (-?, -v, -r, -n, filename)

    try {
        make_cat("/tmp/cat/cat.cdf");
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }
}

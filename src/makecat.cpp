#include <filesystem>
#include <iostream>
#include <fstream>
#include <charconv>
#include <vector>

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
    // FIXME
}

int main() {
    // FIXME

    try {
        make_cat("/tmp/cat/cat.cdf");
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }
}

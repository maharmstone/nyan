#include <iostream>
#include <filesystem>
#include <chrono>
#include <optional>
#include <fstream>
#include <format>
#include <string.h>
#include "config.h"

using namespace std;

struct version {
    uint16_t major;
    uint16_t minor;
    uint16_t build;
    uint16_t revision;
};

static string lcstring(string_view sv) {
    string ret;

    ret.reserve(sv.size());

    for (auto c : sv) {
        ret += (char)tolower(c);
    }

    return ret;
}

static bool is_whitespace(string_view sv) {
    for (auto c : sv) {
        if (c != ' ' && c != '\t' && c != '\r')
            return false;
    }

    return true;
}

static void stampinf(const filesystem::path& fn, string_view ver_section,
                     const optional<chrono::year_month_day>& date,
                     const optional<version>& ver) {
    ifstream f(fn);

    // FIXME - throw more descriptive error message (not found, access denied, etc.)
    if (!f.is_open())
        throw runtime_error("Could not open " + fn.string() + " for reading.");

    unsigned int line_no = 0;
    string section;
    vector<string> lines;
    bool changed_driverver = false;

    while (!f.eof()) {
        string line;
        line_no++;

        getline(f, line);

        if (line.front() == '[') {
            auto end = line.find(']');

            if (end == string::npos)
                throw runtime_error("Line " + to_string(line_no) + ": square brackets not terminated.");

            if (!changed_driverver && date.has_value() && section == ver_section) {
                vector<string> ws_lines;

                while (!lines.empty() && is_whitespace(lines.back())) {
                    ws_lines.emplace_back(lines.back());
                    lines.pop_back();
                }

                lines.emplace_back(format("DriverVer = {:02}/{:02}/{:04},{}.{}.{}.{}", (unsigned int)date->month(), (unsigned int)date->day(), (int)date->year(),
                                          ver->major, ver->minor, ver->build, ver->revision));

                while (!ws_lines.empty()) {
                    lines.push_back(ws_lines.back());
                    ws_lines.pop_back();
                }
            }

            section = lcstring(string_view(line.data() + 1, end - 1));
        }

        auto sv = string_view(line);

        while (!sv.empty() && (sv.front() == ' ' || sv.front() == '\t')) {
            sv = sv.substr(1);
        }

        bool in_quotes = false;
        for (size_t i = 0; i < sv.size(); i++) {
            if (sv[i] == '"')
                in_quotes = !in_quotes;
            else if (sv[i] == ';' && !in_quotes) {
                sv = sv.substr(0, i);
                break;
            }
        }

        while (!sv.empty() && (sv.back() == ' ' || sv.back() == '\t' || sv.back() == '\r')) {
            sv = sv.substr(0, sv.size() - 1);
        }

        if (sv.empty()) {
            lines.emplace_back(line);
            continue;
        }

        // FIXME - backslash can be used as line continuator

        auto eq = sv.find('=');

        if (eq == string::npos) {
            lines.emplace_back(line);
            continue;
        }

        string_view name, value;

        name = sv.substr(0, eq);
        value = sv.substr(eq + 1);

        while (!name.empty() && (name.back() == ' ' || name.back() == '\t')) {
            name = name.substr(0, name.size() - 1);
        }

        while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
            value = value.substr(1);
        }

        if (date.has_value() && section == ver_section) {
            auto namelc = lcstring(name);

            if (namelc == "driverver") {
                lines.emplace_back(format("DriverVer = {:02}/{:02}/{:04},{}.{}.{}.{}", (unsigned int)date->month(), (unsigned int)date->day(), (int)date->year(),
                                          ver->major, ver->minor, ver->build, ver->revision));
                changed_driverver = true;
                continue;
            }
        }

        lines.emplace_back(line);
    }

    if (!changed_driverver && date.has_value() && section == ver_section) {
        vector<string> ws_lines;

        while (!lines.empty() && is_whitespace(lines.back())) {
            ws_lines.emplace_back(lines.back());
            lines.pop_back();
        }

        lines.emplace_back(format("DriverVer = {:02}/{:02}/{:04},{}.{}.{}.{}", (unsigned int)date->month(), (unsigned int)date->day(), (int)date->year(),
                                  ver->major, ver->minor, ver->build, ver->revision));

        while (!ws_lines.empty()) {
            lines.push_back(ws_lines.back());
            ws_lines.pop_back();
        }
    }

    // FIXME - write to file
    for (const auto& l : lines) {
        cout << l << endl;
    }
}

int main(int argc, char* argv[]) {
    // FIXME - reading from STDIN and writing to STDOUT
    // FIXME - STAMPINF_DATE and STAMPINF_VERSION environment variables

    if (argc < 2 || !strcmp(argv[1], "--help") || !strcmp(argv[1], "-?")) {
        cerr << format(R"(Usage: {} -f FILE [OPTION]...
Stamp an INF file to update its directives.

      --help, -?    display this help and exit
      --version     output version information and exit
      -f FILE       INF file to modify
)", argv[0]);

        return 1;
    }

    if (!strcmp(argv[1], "--version")) {
        cerr << "stampinf " << PROJECT_VERSION_MAJOR << endl;
        cerr << "Copyright (c) Mark Harmstone 2024" << endl;
        return 1;
    }

    optional<filesystem::path> filename;
    string section;

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-f")) {
            if (i == argc - 1) {
                cerr << format("{}: no filename provided to -f option\n", argv[0]);
                return 1;
            }

            filename = argv[i + 1];
            i++;
        } else if (!strcmp(argv[i], "-s")) {
            if (i == argc - 1) {
                cerr << format("{}: no section name provided to -s option\n", argv[0]);
                return 1;
            }

            section = argv[i + 1];
            i++;
        } else {
            cerr << format("{}: unrecognized option '{}'\n", argv[0], argv[i]);
            return 1;
        }
    }

    if (section == "")
        section = "version";
    else
        section = lcstring(section);

    // FIXME - -d
    // FIXME - -v

    if (!filename.has_value()) {
        cerr << format("{}: no INF filename specified (-f option)\n", argv[0]);
        return 1;
    }

    // FIXME - -a (architecture)
    // FIXME - -c (CatalogFile)
    // FIXME - -k (KMDF version)
    // FIXME - -u (UMDF version)
    // FIXME - -p (Provider)
    // FIXME - -i (ntverp.h)
    // FIXME - -n (verbose)
    // FIXME - -x (remove coinstaller tag)

    try {
        stampinf(filename.value(), section, chrono::year_month_day{2024y, chrono::March, 20d}, version{1, 2, 3, 4}); // FIXME
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}

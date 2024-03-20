#include <iostream>
#include <filesystem>
#include <chrono>
#include <optional>
#include <fstream>
#include <format>

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

int main() {
    // FIXME - parse command line

    // FIXME - reading from STDIN and writing to STDOUT
    // FIXME - STAMPINF_DATE and STAMPINF_VERSION environment variables

    // FIXME - -f
    // FIXME - -s
    // FIXME - -d
    // FIXME - -a
    // FIXME - -c
    // FIXME - -v
    // FIXME - -k
    // FIXME - -u
    // FIXME - -i
    // FIXME - -n

    try {
        stampinf("/tmp/cat/btrfs.inf", "version", chrono::year_month_day{2024y, chrono::March, 20d}, version{1, 2, 3, 4}); // FIXME
    } catch (const exception& e) {
        cerr << "Exception: " << e.what() << endl;
        return 1;
    }

    return 0;
}

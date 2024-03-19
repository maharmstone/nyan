#include <filesystem>
#include <iostream>

using namespace std;

static void make_cat(const filesystem::path& fn) {
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

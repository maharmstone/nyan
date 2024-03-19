#include <iostream>
#include "sha1.h"
#include "sha256.h"
#include "cat.h"

using namespace std;

int main() {
    cat<sha1_hasher> c("C8D7FC7596D61245B5B59565B67D8573", 1710345480); // 2024-03-13 15:58:00

    c.entries.emplace_back("/home/nobackup/btrfs-package/1.9/release/amd64/mkbtrfs.exe");
    c.entries.back().extensions.emplace_back("File", 0x10010001, u"mkbtrfs.exe");
    c.entries.back().extensions.emplace_back("OSAttr", 0x10010001, u"2:5.1,2:5.2,2:6.0,2:6.1,2:6.2,2:6.3,2:10.0");

    c.extensions.emplace_back("OS", 0x10010001, u"XPX86,XPX64,VistaX86,VistaX64,7X86,7X64,8X86,8X64,8ARM,_v63,_v63_X64,_v63_ARM,_v100,_v100_X64,_v100_X64_22H2,_v100_ARM64_22H2");
    c.extensions.emplace_back("HWID2", 0x10010001, u"root\\btrfs");
    c.extensions.emplace_back("HWID1", 0x10010001, u"btrfsvolume");

    auto v = c.write();

    cout << "len = " << v.size() << endl;

    for (size_t i = 0; i < v.size(); i++) {
        if (i % 16 == 0 && i != 0)
            printf("\n");

        printf("%02x ", v[i]);
    }

    printf("\n");

    auto f = fopen("out.cat", "wb");
    fwrite(v.data(), v.size(), 1, f);
    fclose(f);

    return 0;
}

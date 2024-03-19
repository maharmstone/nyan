#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <openssl/objects.h>
#include <openssl/pkcs12.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <string>
#include <vector>
#include <span>
#include <filesystem>
#include "sha1.h"
#include "sha256.h"
#include "authenticode.h"
#include "cat.h"

using namespace std;

#define szOID_CTL "1.3.6.1.4.1.311.10.1"
#define szOID_CATALOG_LIST "1.3.6.1.4.1.311.12.1.1"
#define szOID_CATALOG_LIST_MEMBER "1.3.6.1.4.1.311.12.1.2"
#define CAT_NAMEVALUE_OBJID "1.3.6.1.4.1.311.12.2.1"
#define CAT_MEMBERINFO_OBJID "1.3.6.1.4.1.311.12.2.2"
#define SPC_INDIRECT_DATA_OBJID "1.3.6.1.4.1.311.2.1.4"
#define SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID "1.3.6.1.4.1.311.2.3.1"
#define SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID "1.3.6.1.4.1.311.2.3.2"
#define SPC_PE_IMAGE_DATA_OBJID "1.3.6.1.4.1.311.2.1.15"
#define szOID_OIWSEC_sha1 "1.3.14.3.2.26"
#define szOID_NIST_sha256 "2.16.840.1.101.3.4.2.1"

static const uint8_t page_hashes_guid[] = { 0xa6, 0xb5, 0x86, 0xd5, 0xb4, 0xa1, 0x24, 0x66, 0xae, 0x05, 0xa2, 0x17, 0xda, 0x8e, 0x60, 0xd6 };

struct SpcAttributeTypeAndOptionalValue {
    ASN1_OBJECT* type;
    ASN1_TYPE* value;
};

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
    ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
    ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

struct cat_name_value {
    ASN1_BMPSTRING* tag;
    uint32_t flags;
    ASN1_OCTET_STRING value;
};

ASN1_SEQUENCE(cat_name_value) = {
    ASN1_SIMPLE(cat_name_value, tag, ASN1_BMPSTRING),
    ASN1_EMBED(cat_name_value, flags, INT32),
    ASN1_EMBED(cat_name_value, value, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(cat_name_value)

IMPLEMENT_ASN1_FUNCTIONS(cat_name_value)

struct cat_member_info {
    ASN1_BMPSTRING* guid;
    uint32_t cert_version;
};

ASN1_SEQUENCE(cat_member_info) = {
    ASN1_SIMPLE(cat_member_info, guid, ASN1_BMPSTRING),
    ASN1_EMBED(cat_member_info, cert_version, INT32)
} ASN1_SEQUENCE_END(cat_member_info)

IMPLEMENT_ASN1_FUNCTIONS(cat_member_info)

struct spc_digest {
    SpcAttributeTypeAndOptionalValue algorithm;
    ASN1_OCTET_STRING hash;
};

ASN1_SEQUENCE(spc_digest) = {
    ASN1_EMBED(spc_digest, algorithm, SpcAttributeTypeAndOptionalValue),
    ASN1_EMBED(spc_digest, hash, ASN1_OCTET_STRING),
} ASN1_SEQUENCE_END(spc_digest)

IMPLEMENT_ASN1_FUNCTIONS(spc_digest)

struct spc_indirect_data_content {
    SpcAttributeTypeAndOptionalValue data;
    spc_digest digest;
};

ASN1_SEQUENCE(spc_indirect_data_content) = {
    ASN1_EMBED(spc_indirect_data_content, data, SpcAttributeTypeAndOptionalValue),
    ASN1_EMBED(spc_indirect_data_content, digest, spc_digest)
} ASN1_SEQUENCE_END(spc_indirect_data_content)

IMPLEMENT_ASN1_FUNCTIONS(spc_indirect_data_content)

struct SpcSerializedObject {
    ASN1_OCTET_STRING classId;
    ASN1_OCTET_STRING serializedData;
};

ASN1_SEQUENCE(SpcSerializedObject) = {
    ASN1_EMBED(SpcSerializedObject, classId, ASN1_OCTET_STRING),
    ASN1_EMBED(SpcSerializedObject, serializedData, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(SpcSerializedObject)

IMPLEMENT_ASN1_FUNCTIONS(SpcSerializedObject)

struct SpcString {
    int type;
    union {
        ASN1_BMPSTRING unicode;
        ASN1_IA5STRING ascii;
    };
};

ASN1_CHOICE(SpcString) = {
    ASN1_IMP_EMBED(SpcString, unicode, ASN1_BMPSTRING, 0),
    ASN1_IMP_EMBED(SpcString, ascii, ASN1_IA5STRING, 1),
} ASN1_CHOICE_END(SpcString)

IMPLEMENT_ASN1_FUNCTIONS(SpcString)

struct SpcLink {
    int type;
    union {
        ASN1_IA5STRING url;
        SpcSerializedObject moniker;
        SpcString file;
    };
};

ASN1_CHOICE(SpcLink) = {
    ASN1_IMP_EMBED(SpcLink, url, ASN1_IA5STRING, 0),
    ASN1_IMP_EMBED(SpcLink, moniker, SpcSerializedObject, 1),
    ASN1_EXP_EMBED(SpcLink, file, SpcString, 2)
} ASN1_CHOICE_END(SpcLink)

IMPLEMENT_ASN1_FUNCTIONS(SpcLink)

struct SpcPeImageData {
    ASN1_BIT_STRING flags;
    SpcLink* file;
};

ASN1_SEQUENCE(SpcPeImageData) = {
    ASN1_EMBED(SpcPeImageData, flags, ASN1_BIT_STRING),
    ASN1_EXP_OPT(SpcPeImageData, file, SpcLink, 0)
} ASN1_SEQUENCE_END(SpcPeImageData)

IMPLEMENT_ASN1_FUNCTIONS(SpcPeImageData)

struct cat_attr {
    int type;
    union {
        cat_name_value name_value;
        cat_member_info member_info;
        spc_indirect_data_content spcidc;
    };
};

ASN1_CHOICE(cat_attr) = {
    ASN1_EMBED(cat_attr, name_value, cat_name_value),
    ASN1_EMBED(cat_attr, member_info, cat_member_info),
    ASN1_EMBED(cat_attr, spcidc, spc_indirect_data_content)
} ASN1_CHOICE_END(cat_attr)

DEFINE_STACK_OF(cat_attr)
IMPLEMENT_ASN1_FUNCTIONS(cat_attr)

struct CatalogAuthAttr {
    ASN1_OBJECT* type;
    STACK_OF(cat_attr)* contents;
};

ASN1_SEQUENCE(CatalogAuthAttr) = {
    ASN1_SIMPLE(CatalogAuthAttr, type, ASN1_OBJECT),
    ASN1_SET_OF(CatalogAuthAttr, contents, cat_attr)
} ASN1_SEQUENCE_END(CatalogAuthAttr)

DEFINE_STACK_OF(CatalogAuthAttr)
IMPLEMENT_ASN1_FUNCTIONS(CatalogAuthAttr)

struct CatalogInfo {
    ASN1_OCTET_STRING digest;
    STACK_OF(CatalogAuthAttr)* attributes;
};

ASN1_SEQUENCE(CatalogInfo) = {
    ASN1_EMBED(CatalogInfo, digest, ASN1_OCTET_STRING),
    ASN1_SET_OF(CatalogInfo, attributes, CatalogAuthAttr)
} ASN1_SEQUENCE_END(CatalogInfo)

DEFINE_STACK_OF(CatalogInfo)
IMPLEMENT_ASN1_FUNCTIONS(CatalogInfo)

struct cert_extension {
    ASN1_OBJECT* type;
    ASN1_OCTET_STRING blob;
};

ASN1_SEQUENCE(cert_extension) = {
    ASN1_SIMPLE(cert_extension, type, ASN1_OBJECT),
    ASN1_EMBED(cert_extension, blob, ASN1_OCTET_STRING)
} ASN1_SEQUENCE_END(cert_extension)

DEFINE_STACK_OF(cert_extension)
IMPLEMENT_ASN1_FUNCTIONS(cert_extension)

struct MsCtlContent {
    SpcAttributeTypeAndOptionalValue type;
    ASN1_OCTET_STRING* identifier;
    ASN1_UTCTIME* time;
    SpcAttributeTypeAndOptionalValue version;
    STACK_OF(CatalogInfo)* header_attributes;
    STACK_OF(cert_extension)* extensions;
};

ASN1_SEQUENCE(MsCtlContent) = {
    ASN1_EMBED(MsCtlContent, type, SpcAttributeTypeAndOptionalValue),
    ASN1_SIMPLE(MsCtlContent, identifier, ASN1_OCTET_STRING),
    ASN1_SIMPLE(MsCtlContent, time, ASN1_UTCTIME),
    ASN1_EMBED(MsCtlContent, version, SpcAttributeTypeAndOptionalValue),
    ASN1_SEQUENCE_OF(MsCtlContent, header_attributes, CatalogInfo),
    ASN1_EXP_SEQUENCE_OF(MsCtlContent, extensions, cert_extension, 0)
} ASN1_SEQUENCE_END(MsCtlContent)

IMPLEMENT_ASN1_FUNCTIONS(MsCtlContent)

static void populate_cat_name_value(cat_name_value& cnv, string_view tag, uint32_t flags,
                                    const char16_t* value) {
    int unilen;
    auto uni = OPENSSL_utf82uni(tag.data(), (int)tag.size(), nullptr, &unilen);

    ASN1_STRING_set(cnv.tag, uni,
                    (int)(unilen - sizeof(char16_t))); // we don't want the trailing null

    OPENSSL_free(uni);

    cnv.flags = flags;

    auto value_len = char_traits<char16_t>::length(value) + 1; // include trailing null
    ASN1_OCTET_STRING_set(&cnv.value, (uint8_t*)value, (int)(value_len * sizeof(char16_t)));
}

static void add_cat_name_value(STACK_OF(CatalogAuthAttr)* attributes, string_view tag,
                               uint32_t flags, const char16_t* value) {
    auto attr = CatalogAuthAttr_new();
    attr->type = OBJ_txt2obj(CAT_NAMEVALUE_OBJID, 1);

    auto ca = cat_attr_new();
    ca->type = 0;

    ca->name_value.tag = ASN1_STRING_new();
    populate_cat_name_value(ca->name_value, tag, flags, value);

    sk_cat_attr_push(attr->contents, ca);

    sk_CatalogAuthAttr_push(attributes, attr);
}

static void add_cat_member_info(STACK_OF(CatalogAuthAttr)* attributes, string_view guid,
                                uint32_t cert_version) {
    auto attr = CatalogAuthAttr_new();
    attr->type = OBJ_txt2obj(CAT_MEMBERINFO_OBJID, 1);

    auto ca = cat_attr_new();
    ca->type = 1;

    int unilen;
    auto uni = OPENSSL_utf82uni(guid.data(), (int)guid.size(), nullptr, &unilen);

    ca->member_info.guid = ASN1_STRING_new();
    ASN1_STRING_set(ca->member_info.guid, uni, unilen);

    OPENSSL_free(uni);

    ca->member_info.cert_version = cert_version;

    sk_cat_attr_push(attr->contents, ca);

    sk_CatalogAuthAttr_push(attributes, attr);
}

template<size_t N>
static vector<uint8_t> page_hashes_data(span<const pair<uint32_t, array<uint8_t, N>>> page_hashes) {
    vector<uint8_t> ret;

    ret.reserve(page_hashes.size() * (sizeof(uint32_t) + page_hashes[0].second.size()));

    for (const auto& ph : page_hashes) {
        ret.insert(ret.end(), (uint8_t*)&ph.first, (uint8_t*)&ph.first + sizeof(uint32_t));
        ret.insert(ret.end(), ph.second.begin(), ph.second.end());
    }

    return ret;
}

template<typename Hasher>
static void add_spc_indirect_data_context(STACK_OF(CatalogAuthAttr)* attributes,
                                          span<const uint8_t> hash,
                                          span<const pair<uint32_t, decltype(Hasher{}.finalize())>> page_hashes) {
    auto attr = CatalogAuthAttr_new();
    attr->type = OBJ_txt2obj(SPC_INDIRECT_DATA_OBJID, 1);

    auto ca = cat_attr_new();
    ca->type = 2;

    auto& spcidc = ca->spcidc;

    auto pid = SpcPeImageData_new();
    ASN1_BIT_STRING_set_bit(&pid->flags, 0, 1);
    ASN1_BIT_STRING_set_bit(&pid->flags, 1, 0);
    ASN1_BIT_STRING_set_bit(&pid->flags, 2, 1);
    pid->file = SpcLink_new();

    if (page_hashes.empty())
        pid->file->type = 2;
    else {
        pid->file->type = 1;

        ASN1_OCTET_STRING_set(&pid->file->moniker.classId, page_hashes_guid, sizeof(page_hashes_guid));

        auto val = SpcAttributeTypeAndOptionalValue_new();

        if constexpr (is_same_v<Hasher, sha1_hasher>)
            val->type = OBJ_txt2obj(SPC_PE_IMAGE_PAGE_HASHES_V1_OBJID, 1);
        else if constexpr (is_same_v<Hasher, sha256_hasher>)
            val->type = OBJ_txt2obj(SPC_PE_IMAGE_PAGE_HASHES_V2_OBJID, 1);

        auto str = page_hashes_data(page_hashes);

        auto os = ASN1_TYPE_new();
        ASN1_TYPE_set(os, V_ASN1_OCTET_STRING, ASN1_OCTET_STRING_new());
        ASN1_OCTET_STRING_set(os->value.octet_string, str.data(), (int)str.size());

        auto set = sk_ASN1_TYPE_new_null();
        sk_ASN1_TYPE_push(set, os);

        {
            uint8_t* out = nullptr;

            int len = i2d_ASN1_SET_ANY(set, &out);

            val->value = ASN1_TYPE_new();
            ASN1_TYPE_set(val->value, V_ASN1_SET, ASN1_STRING_new());
            ASN1_STRING_set(val->value->value.set, out, len);

            OPENSSL_free(out);
        }

        sk_ASN1_TYPE_free(set);
        ASN1_TYPE_free(os);

        {
            uint8_t* out = nullptr;
            int len = i2d_SpcAttributeTypeAndOptionalValue(val, &out);

            SpcAttributeTypeAndOptionalValue_free(val);

            ASN1_OCTET_STRING_set(&pid->file->moniker.serializedData, out, len);

            OPENSSL_free(out);
        }
    }

    auto oct = ASN1_item_pack(pid, SpcPeImageData_it(), nullptr);

    SpcPeImageData_free(pid);

    spcidc.data.type = OBJ_txt2obj(SPC_PE_IMAGE_DATA_OBJID, 1);
    spcidc.data.value = ASN1_TYPE_new();
    ASN1_TYPE_set(spcidc.data.value, V_ASN1_SEQUENCE, oct);

    if constexpr (is_same_v<Hasher, sha1_hasher>)
        spcidc.digest.algorithm.type = OBJ_txt2obj(szOID_OIWSEC_sha1, 1);
    else if constexpr (is_same_v<Hasher, sha256_hasher>)
        spcidc.digest.algorithm.type = OBJ_txt2obj(szOID_NIST_sha256, 1);

    spcidc.digest.algorithm.value = ASN1_TYPE_new();
    spcidc.digest.algorithm.value->type = V_ASN1_NULL;
    ASN1_OCTET_STRING_set(&spcidc.digest.hash, hash.data(), (int)hash.size());

    sk_cat_attr_push(attr->contents, ca);

    sk_CatalogAuthAttr_push(attributes, attr);
}

static uint8_t hex_char(uint8_t val) {
    if (val < 0xa)
        return val + '0';
    else
        return val - 0xa + 'A';
}

static vector<uint8_t> make_hash_string(span<const uint8_t> hash) {
    vector<uint8_t> ret;

    ret.resize((hash.size() + 1) * 2 * sizeof(char16_t));

    auto ptr = ret.data();

    while (!hash.empty()) {
        *ptr = hex_char(hash.front() >> 4);
        ptr++;
        *ptr = 0;
        ptr++;

        *ptr = hex_char(hash.front() & 0xf);
        ptr++;
        *ptr = 0;
        ptr++;

        hash = hash.subspan(1);
    }

    *ptr = 0;
    ptr++;
    *ptr = 0;
    ptr++;

    return ret;
}

static void add_extension(STACK_OF(cert_extension)* extensions, string_view name, uint32_t flags,
                          const char16_t* value) {
    auto ext = cert_extension_new();
    ext->type = OBJ_txt2obj(CAT_NAMEVALUE_OBJID, 1);

    auto cnv = cat_name_value_new();

    populate_cat_name_value(*cnv, name, flags, value);

    uint8_t* out = nullptr;
    int len = i2d_cat_name_value(cnv, &out);

    cat_name_value_free(cnv);

    ASN1_OCTET_STRING_set(&ext->blob, out, len);

    OPENSSL_free(out);

    sk_cert_extension_push(extensions, ext);
}

static vector<uint8_t> do_pkcs(MsCtlContent* c) {
    auto p7 = PKCS7_new();
    auto p7s = PKCS7_SIGNED_new();

    p7->type = OBJ_nid2obj(NID_pkcs7_signed);
    p7->d.sign = p7s;

    p7s->contents->type = OBJ_txt2obj(szOID_CTL, 1);
    ASN1_INTEGER_set(p7s->version, 1);

    auto oct = ASN1_item_pack(c, MsCtlContent_it(), nullptr);

    p7s->contents->d.other = ASN1_TYPE_new();
    ASN1_TYPE_set(p7s->contents->d.other, V_ASN1_SEQUENCE, oct);

    unsigned char* out = nullptr;
    int len = i2d_PKCS7(p7, &out);

    if (len == -1)
        throw runtime_error("i2d_PKCS7 failed");

    vector<uint8_t> ret;

    ret.assign(out, out + len);

    OPENSSL_free(out);

    PKCS7_free(p7);

    return ret;
}

template<typename Hasher>
static decltype(Hasher{}.finalize()) do_authenticode(const filesystem::path& fn, vector<pair<uint32_t, decltype(Hasher{}.finalize())>>& page_hashes) {
    int fd = open(fn.string().c_str(), O_RDONLY);

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

    decltype(Hasher{}.finalize()) digest;

    try {
        digest = authenticode<Hasher>(span((uint8_t*)addr, length));
        page_hashes = get_page_hashes<Hasher>(span((uint8_t*)addr, length));
    } catch (...) {
        munmap(addr, length);
        close(fd);
        throw;
    }

    munmap(addr, length);
    close(fd);

    return digest;
}

template<typename Hasher>
vector<uint8_t> cat<Hasher>::write() {
    unique_ptr<MsCtlContent, decltype(&MsCtlContent_free)> c{MsCtlContent_new(), MsCtlContent_free};

    c->type.type = OBJ_txt2obj(szOID_CATALOG_LIST, 1);
    c->type.value = nullptr;

    ASN1_OCTET_STRING_set(c->identifier, (uint8_t*)identifier.data(), (int)identifier.size());
    ASN1_UTCTIME_set(c->time, time);

    c->version.type = OBJ_txt2obj(szOID_CATALOG_LIST_MEMBER, 1);
    c->version.value = ASN1_TYPE_new();
    ASN1_TYPE_set(c->version.value, V_ASN1_NULL, nullptr);

    for (const auto& ent : entries) {
        auto catinfo = CatalogInfo_new();

        try {
            vector<pair<uint32_t, decltype(Hasher{}.finalize())>> page_hashes;

            // FIXME - detect if PE file

            // FIXME - normal hash if not PE
            auto hash = do_authenticode<Hasher>(ent.fn, page_hashes);

            auto hash_str = make_hash_string(hash);

            ASN1_OCTET_STRING_set(&catinfo->digest, hash_str.data(), (int)hash_str.size());

            for (const auto& ce : ent.extensions) {
                add_cat_name_value(catinfo->attributes, ce.name, ce.flags, ce.value.c_str());
            }

            // FIXME - or "{DE351A42-8E59-11D0-8C47-00C04FC295EE}" if not PE
            add_cat_member_info(catinfo->attributes, "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", 512);

            // FIXME - only if PE
            add_spc_indirect_data_context<Hasher>(catinfo->attributes, hash, page_hashes);
        } catch (...) {
            CatalogInfo_free(catinfo);
            throw;
        }

        sk_CatalogInfo_push(c->header_attributes, catinfo);
    }

    for (const auto& ce : extensions) {
        add_extension(c->extensions, ce.name, ce.flags, ce.value.c_str());
    }

    return do_pkcs(c.get());
}

template class cat<sha1_hasher>;
template class cat<sha256_hasher>;

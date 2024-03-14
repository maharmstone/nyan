#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <openssl/objects.h>
#include <openssl/pkcs12.h>
#include <string.h>
#include <string>

using namespace std;

#define szOID_CTL "1.3.6.1.4.1.311.10.1"
#define szOID_CATALOG_LIST "1.3.6.1.4.1.311.12.1.1"
#define szOID_CATALOG_LIST_MEMBER "1.3.6.1.4.1.311.12.1.2"
#define CAT_NAMEVALUE_OBJID "1.3.6.1.4.1.311.12.2.1"

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

struct cat_attr {
    int type;
    union {
        cat_name_value name_value;
        cat_member_info member_info;
    };
};

ASN1_CHOICE(cat_attr) = {
    ASN1_EMBED(cat_attr, name_value, cat_name_value),
    ASN1_EMBED(cat_attr, member_info, cat_member_info)
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

struct MsCtlContent {
    SpcAttributeTypeAndOptionalValue type;
    ASN1_OCTET_STRING* identifier;
    ASN1_UTCTIME* time;
    SpcAttributeTypeAndOptionalValue version;
    STACK_OF(CatalogInfo)* header_attributes;
    ASN1_TYPE* filename;
};

ASN1_SEQUENCE(MsCtlContent) = {
    ASN1_EMBED(MsCtlContent, type, SpcAttributeTypeAndOptionalValue),
    ASN1_SIMPLE(MsCtlContent, identifier, ASN1_OCTET_STRING),
    ASN1_SIMPLE(MsCtlContent, time, ASN1_UTCTIME),
    ASN1_EMBED(MsCtlContent, version, SpcAttributeTypeAndOptionalValue),
    ASN1_SEQUENCE_OF(MsCtlContent, header_attributes, CatalogInfo)
} ASN1_SEQUENCE_END(MsCtlContent)

IMPLEMENT_ASN1_FUNCTIONS(MsCtlContent)

static void add_cat_name_value(STACK_OF(CatalogAuthAttr)* attributes, string_view tag,
                               uint32_t flags, u16string_view value) {
    auto attr = CatalogAuthAttr_new();
    attr->type = OBJ_txt2obj(CAT_NAMEVALUE_OBJID, 1);

    auto ca = cat_attr_new();
    ca->type = 0;

    int unilen;
    auto uni = OPENSSL_utf82uni(tag.data(), (int)tag.size(), nullptr, &unilen);

    ca->name_value.tag = ASN1_STRING_new();
    ASN1_STRING_set(ca->name_value.tag, uni, unilen);

    OPENSSL_free(uni);

    ca->name_value.flags = flags;
    ASN1_OCTET_STRING_set(&ca->name_value.value, (uint8_t*)value.data(), (int)(value.size() * sizeof(char16_t)));

    sk_cat_attr_push(attr->contents, ca);

    sk_CatalogAuthAttr_push(attributes, attr);
}

static void add_cat_member_info(STACK_OF(CatalogAuthAttr)* attributes, string_view guid,
                                uint32_t cert_version) {
    auto attr = CatalogAuthAttr_new();
    attr->type = OBJ_txt2obj(CAT_NAMEVALUE_OBJID, 1);

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

int main() {
    MsCtlContent c;

    static const char identifier[] = "C8D7FC7596D61245B5B59565B67D8573";

    // SpcAttributeTypeAndOptionalValue s;

    // const char* name = "Fletch";
    // ASN1_OCTET_STRING* asn1_name = ASN1_OCTET_STRING_new();
    // ASN1_OCTET_STRING_set(asn1_name, (const unsigned char*)name, strlen(name));

    // auto oid = ASN1_OBJECT_new();

    c.type.type = OBJ_txt2obj(szOID_CATALOG_LIST, 1);
    // c.type.value = ASN1_TYPE_new();
    // c.type.value->type = V_ASN1_NULL;
    c.type.value = nullptr;

    c.identifier = ASN1_OCTET_STRING_new();
    ASN1_OCTET_STRING_set(c.identifier, (uint8_t*)identifier, strlen(identifier));
    // ASN1_OCTET_STRING_set(&c.identifier, (uint8_t*)"", 0);

    c.time = ASN1_UTCTIME_new();
    ASN1_UTCTIME_set(c.time, 1710345480); // 2024-03-13 15:58:00

    c.version.type = OBJ_txt2obj(szOID_CATALOG_LIST_MEMBER, 1);
    c.version.value = ASN1_TYPE_new();
    c.version.value->type = V_ASN1_NULL;

    c.header_attributes = sk_CatalogInfo_new_null();
    auto catinfo = CatalogInfo_new();

    ASN1_OCTET_STRING_set(&catinfo->digest, (uint8_t*)u"2C9546DF01047D0D74D6FF7259D3ABCDEEF513B5", strlen("2C9546DF01047D0D74D6FF7259D3ABCDEEF513B5") * sizeof(char16_t));

    add_cat_name_value(catinfo->attributes, "File", 0x10010001, u"btrfs.sys"); // FIXME - trailing nulls
    add_cat_member_info(catinfo->attributes, "{C689AAB8-8E78-11D0-8C47-00C04FC295EE}", 512);
    add_cat_name_value(catinfo->attributes, "OSAttr", 0x10010001, u"2:5.1,2:5.2,2:6.0,2:6.1,2:6.2,2:6.3,2:10.0");
    // FIXME - spcIndirectDataContext

    sk_CatalogInfo_push(c.header_attributes, catinfo);

    unsigned char* out = nullptr;
    // int len = i2d_SpcAttributeTypeAndOptionalValue(&c.type, &out);
    int len = i2d_MsCtlContent(&c, &out);

    ASN1_TYPE_free(c.type.value);
    ASN1_OBJECT_free(c.type.type);
    ASN1_OCTET_STRING_free(c.identifier);
    ASN1_UTCTIME_free(c.time);
    ASN1_OBJECT_free(c.version.type);
    ASN1_TYPE_free(c.version.value);

    sk_CatalogInfo_pop_free(c.header_attributes, [](auto cat) {
        while (sk_CatalogAuthAttr_num(cat->attributes) > 0) {
            auto attr = sk_CatalogAuthAttr_pop(cat->attributes);

            while (sk_cat_attr_num(attr->contents) > 0) {
                cat_attr_free(sk_cat_attr_pop(attr->contents));
            }

            CatalogAuthAttr_free(attr);
        }

        CatalogInfo_free(cat);
    });

    printf("len = %i\n", len);

    for (int i = 0; i < len; i++) {
        if (i % 16 == 0 && i != 0)
            printf("\n");

        printf("%02x ", out[i]);
    }

    printf("\n");

    OPENSSL_free(out);

    return 0;
}

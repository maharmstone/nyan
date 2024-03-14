#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <openssl/err.h>
#include <openssl/types.h>
#include <openssl/objects.h>
#include <string.h>

#define szOID_CTL "1.3.6.1.4.1.311.10.1"
#define szOID_CATALOG_LIST "1.3.6.1.4.1.311.12.1.1"
#define szOID_CATALOG_LIST_MEMBER "1.3.6.1.4.1.311.12.1.2"

struct SpcAttributeTypeAndOptionalValue {
    ASN1_OBJECT* type;
    ASN1_TYPE* value;
};

ASN1_SEQUENCE(SpcAttributeTypeAndOptionalValue) = {
    ASN1_SIMPLE(SpcAttributeTypeAndOptionalValue, type, ASN1_OBJECT),
    ASN1_OPT(SpcAttributeTypeAndOptionalValue, value, ASN1_ANY)
} ASN1_SEQUENCE_END(SpcAttributeTypeAndOptionalValue)

IMPLEMENT_ASN1_FUNCTIONS(SpcAttributeTypeAndOptionalValue)

struct CatalogAuthAttr {
    ASN1_OBJECT* type;
    ASN1_TYPE* contents;
};

ASN1_SEQUENCE(CatalogAuthAttr) = {
    ASN1_SIMPLE(CatalogAuthAttr, type, ASN1_OBJECT),
    ASN1_OPT(CatalogAuthAttr, contents, ASN1_ANY)
} ASN1_SEQUENCE_END(CatalogAuthAttr)

IMPLEMENT_ASN1_FUNCTIONS(CatalogAuthAttr)

struct CatalogInfo {
    ASN1_OCTET_STRING* digest;
    STACK_OF(CatalogAuthAttr)* attributes;
};

ASN1_SEQUENCE(CatalogInfo) = {
    ASN1_SIMPLE(CatalogInfo, digest, ASN1_OCTET_STRING),
    ASN1_SET_OF(CatalogInfo, attributes, CatalogAuthAttr)
} ASN1_SEQUENCE_END(CatalogInfo)

// DECLARE_STACK_OF(CatalogInfo)
// DECLARE_ASN1_SET_OF(CatalogInfo)
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
    
    // FIXME
    
    sk_CatalogInfo_push(c.header_attributes, catinfo);
    // sk_CatalogInfo_push(c.header_attributes, CatalogInfo_new());
    
    unsigned char* out = nullptr;
    // int len = i2d_SpcAttributeTypeAndOptionalValue(&c.type, &out);
    int len = i2d_MsCtlContent(&c, &out);
    
    ASN1_TYPE_free(c.type.value);
    ASN1_OBJECT_free(c.type.type);
    ASN1_OCTET_STRING_free(c.identifier);
    ASN1_UTCTIME_free(c.time);
    ASN1_OBJECT_free(c.version.type);
    ASN1_TYPE_free(c.version.value);
    sk_CatalogInfo_pop_free(c.header_attributes, CatalogInfo_free);
    
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

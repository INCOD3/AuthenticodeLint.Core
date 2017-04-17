using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public static class CmsAttributeDecoder
    {
        public static CmsGenericAttribute Decode(AsnSequence sequence)
        {
            var (identifier, contents) = AsnReader.Read<AsnObjectIdentifier, AsnSet>(sequence);
            var attributeId = identifier.Value;
            switch (attributeId.Value)
            {
                case KnownOids.CmsPkcs9AttributeIds.messageDigest:
                    return new CmsMessageDigestAttibute(attributeId, contents);
                case KnownOids.CmsPkcs9AttributeIds.opusInfo:
                    return new CmsOpusAttribute(attributeId, contents);
                case KnownOids.CmsPkcs9AttributeIds.nested_signature:
                    return new CmsNestedSignatureAttribute(attributeId, contents);
                case KnownOids.CmsPkcs9AttributeIds.rsa_authenticode_timestamp:
                    return new CmsPkcsAuthenticodeTimestampAttribute(attributeId, contents);
                case KnownOids.CmsPkcs9AttributeIds.rfc3161_timestamp:
                    return new CmsPkcsRfc3161TimestampAttribute(attributeId, contents);
                case KnownOids.CmsPkcs9AttributeIds.signing_time:
                    return new CmsSigningTimeAttribute(attributeId, contents);
                case KnownOids.CmsPkcs9AttributeIds.signing_certificate:
                    return new CmsSigningCertificateAttribute(attributeId, contents);
                case KnownOids.CmsPkcs9AttributeIds.contentType:
                    return new CmsContentTypeAttribute(attributeId, contents);
                default:
                    return new CmsGenericAttribute(attributeId, contents);
            }
        }
    }
}
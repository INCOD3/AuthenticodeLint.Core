using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public static class CmsAttributeDecoder
    {
        public static CmsGenericAttribute Decode(AsnSequence sequence)
        {
            var properties = AsnReader.Read<AsnObjectIdentifier, AsnSet>(sequence);
            var attributeId = properties.Item1.Value;
            switch (attributeId)
            {
                case KnownOids.CmsPkcs9AttributeIds.messageDigest:
                    return new CmsMessageDigestAttibute(attributeId, properties.Item2);
                case KnownOids.CmsPkcs9AttributeIds.opusInfo:
                    return new CmsOpusAttribute(attributeId, properties.Item2);
                case KnownOids.CmsPkcs9AttributeIds.nested_signature:
                    return new CmsNestedSignatureAttribute(attributeId, properties.Item2);
                case KnownOids.CmsPkcs9AttributeIds.rsa_authenticode_timestamp:
                    return new CmsPkcsAuthenticodeTimestampAttribute(attributeId, properties.Item2);
                case KnownOids.CmsPkcs9AttributeIds.rfc3161_timestamp:
                    return new CmsPkcsRfc3161TimestampAttribute(attributeId, properties.Item2);
                case KnownOids.CmsPkcs9AttributeIds.signing_time:
                    return new CmsSigningTimeAttribute(attributeId, properties.Item2);
                case KnownOids.CmsPkcs9AttributeIds.signing_certificate:
                    return new CmsSigningCertificateAttribute(attributeId, properties.Item2);
                default:
                    return new CmsGenericAttribute(attributeId, properties.Item2);
            }
        }
    }
}
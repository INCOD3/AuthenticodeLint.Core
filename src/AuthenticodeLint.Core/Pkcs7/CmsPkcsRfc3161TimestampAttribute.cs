using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsPkcsRfc3161TimestampAttribute : CmsGenericAttribute, ICmsSignatureAttribute
    {
        public CmsSignature Signature { get; }

        public CmsPkcsRfc3161TimestampAttribute(Oid attributeId, AsnSet content) : base(attributeId, content)
        {
            var signerContent = AsnReader.Read<AsnSequence>(content);
            var signature = new CmsSignature(signerContent);
            Signature = signature;
        }
    }
}
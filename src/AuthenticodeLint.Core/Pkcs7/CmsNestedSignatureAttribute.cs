using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsNestedSignatureAttribute : CmsGenericAttribute, ICmsSignatureAttribute
    {
        public CmsSignature Signature { get; }

        public CmsNestedSignatureAttribute(Oid attributeId, AsnSet content) : base(attributeId, content)
        {
            var nestedSignature = AsnReader.Read<AsnSequence>(content);
            Signature = new CmsSignature(nestedSignature);
        }
    }
}
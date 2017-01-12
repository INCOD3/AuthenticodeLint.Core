using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsContentTypeAttribute : CmsGenericAttribute
    {
        public CmsContentTypeAttribute(string attributeId, AsnSet content) : base(attributeId, content)
        {
            var contentType = AsnReader.Read<AsnObjectIdentifier>(content);
            ContentType = contentType.Value;
        }

        public string ContentType { get; }
    }
}
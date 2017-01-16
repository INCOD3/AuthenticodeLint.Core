using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsSigningCertificateAttribute : CmsGenericAttribute
    {
        public CmsSigningCertificate SigningCertificate { get; }

        public CmsSigningCertificateAttribute(Oid attributeId, AsnSet content) : base(attributeId, content)
        {
            var signerContent = AsnReader.Read<AsnSequence>(content);
            var signingCertificate = new CmsSigningCertificate(signerContent);
            SigningCertificate = signingCertificate;
        }
    }
}
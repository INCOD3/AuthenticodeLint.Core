using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsPkcsAuthenticodeTimestampAttribute : CmsGenericAttribute
    {
        public CmsSignerInfo SignerInfo { get; }

        public CmsPkcsAuthenticodeTimestampAttribute(string attributeId, AsnSet content) : base(attributeId, content)
        {
            var signerContent = AsnReader.Read<AsnSequence>(content).Item1;
            var signerInfo = new CmsSignerInfo(signerContent);
            SignerInfo = signerInfo;
        }
    }
}
using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsMessageDigestAttibute : CmsGenericAttribute
    {
        public CmsMessageDigestAttibute(string attributeId, AsnSet content) : base(attributeId, content)
        {
            var digest = AsnReader.Read<AsnOctetString>(content);
            Digest = digest.Value;
        }

        public ArraySegment<byte> Digest { get; }
    }
}
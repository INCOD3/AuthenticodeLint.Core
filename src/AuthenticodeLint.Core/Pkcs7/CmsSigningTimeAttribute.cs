using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsSigningTimeAttribute : CmsGenericAttribute
    {
        public DateTimeOffset SigningTime { get; }

        public CmsSigningTimeAttribute(string attributeId, AsnSet content) : base(attributeId, content)
        {
            var signingTime = AsnReader.Read<IAsnDateTime>(content);
            SigningTime = signingTime.Value;
        }
    }
}
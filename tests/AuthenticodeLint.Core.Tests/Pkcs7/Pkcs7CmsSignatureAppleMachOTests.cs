using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class Pkcs7CmsSignatureAppleMachOTests
    {
        [Fact]
        public void DecodeAppleMachOSignature()
        {
            var signature = System.IO.File.ReadAllBytes(PathHelper.CombineWithProjectPath("files/apple-sig.pkcs7"));
            AsnDecoder.Decode(signature);
        }
    }
}
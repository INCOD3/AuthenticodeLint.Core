using System;
using AuthenticodeLint.Core.Pkcs7;
using AuthenticodeLint.Core.Asn;
using Xunit;

using DNC = System.Collections.Generic.Dictionary<string, string>;
using static AuthenticodeLint.Core.Asn.KnownOids.DistinguishedName;

namespace AuthenticodeLint.Core.Tests
{
    public class CmsIssuerAndSerialNumberTests
    {
        [Fact]
        public void ShouldConstructFromAsn1Data()
        {
            var issuer = ConstructTestIssuer();
            var number = AsnDecoder.Decode(new byte[] { 0x02, 0x01, 0x01});
            var asnData = AsnHelper.ConstructSequence(issuer, number);
            var issuerAndSerial = new CmsIssuerAndSerialNumber(asnData);
            Assert.Equal("CN=Kevin Jones, C=US", issuerAndSerial.Name.ToString());
            Assert.Equal(new ArraySegment<byte>(new byte[] {1}), issuerAndSerial.SerialNumber);
        }

        private static AsnSequence ConstructTestIssuer()
        {
            var data = DNHelper.TestDN(new DNC
            {
                [id_at_commonName] = "Kevin Jones"
            }, new DNC
            {
                [id_at_countryName] = "US"
            });
            return data;
        }
    }
}
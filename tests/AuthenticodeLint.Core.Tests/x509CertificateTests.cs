using AuthenticodeLint.Core.x509;
using Xunit;

using DNC = System.Collections.Generic.Dictionary<string, string>;
using static AuthenticodeLint.Core.Asn.KnownOids.DistinguishedName;
using System;

namespace AuthenticodeLint.Core.Tests
{
    public class x509CertificateTests
    {
        [Fact]
        public void ShouldDecodeSimpleCertificate()
        {
            var certificate = new x509Certificate("files/vcsjones.com.crt");
            var expectedSerial = new byte[] { 0x00, 0x83, 0xE1, 0x89, 0x30, 0x1A, 0x8F, 0xF6, 0xA5, 0x52, 0x2A, 0x50, 0x09, 0x7E, 0xCA, 0x43, 0x44 };
            Assert.Equal(expectedSerial, certificate.SerialNumber);
            Assert.Equal("1.2.840.10045.4.3.2", certificate.AlgorithmIdentifier.Algorithm);
            Assert.Null(certificate.AlgorithmIdentifier.Parameters);
            Assert.Equal(2, certificate.Version);
            Assert.Equal(5, certificate.Issuer.Count);
            Assert.Equal("C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO ECC Domain Validation Secure Server CA", certificate.Issuer.ToString());
            Assert.Equal(new DateTimeOffset(2016, 7, 30, 0, 0, 0, TimeSpan.Zero), certificate.NotBefore);
            Assert.Equal(new DateTimeOffset(2018, 7, 30, 23, 59, 59, TimeSpan.Zero), certificate.NotAfter);
            Assert.Equal("OU=Domain Control Validated, OU=COMODO SSL, CN=vcsjones.com", certificate.Subject.ToString());
        }

        [Fact]
        public void ShouldDecodeASingleX500Component()
        {
            var data = DNHelper.TestDN(new DNC
            {
                [id_at_commonName] = "Kevin Jones"
            });
            var dn = new x500DistinguishedName(data);
            Assert.Equal(1, dn.Count);
            Assert.Equal(1, dn[0].Count);
            Assert.Equal(id_at_commonName, dn[0][0].ObjectIdentifier);
            Assert.Equal("Kevin Jones", dn[0][0].Value);
            Assert.Equal("CN=Kevin Jones", dn.ToString());
        }

        [Fact]
        public void ShouldDecodeMultipleComponents()
        {
            var data = DNHelper.TestDN(new DNC
            {
                [id_at_commonName] = "Kevin Jones"
            }, new DNC
            {
                [id_at_countryName] = "US"
            });
            var dn = new x500DistinguishedName(data);
            Assert.Equal(2, dn.Count);
            Assert.Equal(1, dn[0].Count);
            Assert.Equal(1, dn[1].Count);
            Assert.Equal(id_at_commonName, dn[0][0].ObjectIdentifier);
            Assert.Equal("Kevin Jones", dn[0][0].Value);
            Assert.Equal(id_at_countryName, dn[1][0].ObjectIdentifier);
            Assert.Equal("US", dn[1][0].Value);
            Assert.Equal("CN=Kevin Jones, C=US", dn.ToString());
        }



        [Fact]
        public void ShouldDecodeMultiComponentRDNAndRegularComponents()
        {
            var data = DNHelper.TestDN(new DNC
            {
                [id_at_commonName] = "Kevin Jones",
                [id_at_countryName] = "US"
            },
            new DNC
            {
                [id_at_commonName] = "Turtle",
            });
            var dn = new x500DistinguishedName(data);
            Assert.Equal(2, dn.Count);
            Assert.Equal(2, dn[0].Count);
            Assert.Equal(id_at_commonName, dn[0][0].ObjectIdentifier);
            Assert.Equal(id_at_countryName, dn[0][1].ObjectIdentifier);
            Assert.Equal("Kevin Jones", dn[0][0].Value);
            Assert.Equal("US", dn[0][1].Value);
            Assert.Equal("CN=Kevin Jones + C=US, CN=Turtle", dn.ToString());
        }
    }
}

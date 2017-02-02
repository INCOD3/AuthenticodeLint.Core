using AuthenticodeLint.Core.x509;
using Xunit;

using DNC = System.Collections.Generic.Dictionary<string, string>;
using static AuthenticodeLint.Core.Asn.KnownOids.DistinguishedName;
using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.IO;
using System.Linq;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Tests
{
    public class x509CertificateTests
    {
        [Fact]
        public void ShouldValidateSignatureSuccessfully()
        {
            var certificate = new x509Certificate(PathHelper.CombineWithProjectPath("files/vcsjones.com.crt"));
            var signer = new x509Certificate(PathHelper.CombineWithProjectPath("files/vcsjones.com-issuer.crt"));
            Assert.True(certificate.ValidateSignature(signer));
        }

        [Fact]
        public void ShouldNotValidateSignatureWithUnreleatedAlgorithms()
        {
            //This tries to validate an ECDSA certificate with an RSA key. This shouldn't
            //work.
            var certificate = new x509Certificate(PathHelper.CombineWithProjectPath("files/vcsjones.com.crt"));
            var signer = new x509Certificate(PathHelper.CombineWithProjectPath("files/thycotic.com.crt"));
            Assert.False(certificate.ValidateSignature(signer));
        }

        [Fact]
        public void ShouldDecodeSimpleCertificate()
        {
            var certificate = new x509Certificate(PathHelper.CombineWithProjectPath("files/vcsjones.com.crt"));
            var expectedSerial = new byte[] { 0x00, 0x83, 0xE1, 0x89, 0x30, 0x1A, 0x8F, 0xF6, 0xA5, 0x52, 0x2A, 0x50, 0x09, 0x7E, 0xCA, 0x43, 0x44 };
            var expectedSha1Thumbprint = new byte[] {
                0x73, 0xBA, 0x68, 0x4B, 0x21, 0x76, 0x44, 0xD4, 0x4A, 0x67,
                0x62, 0xAB, 0xFC, 0xC7, 0x57, 0x38, 0x77, 0x62, 0x72, 0xB3,
                };
            Assert.Equal(expectedSerial, certificate.SerialNumber);
            Assert.Equal(expectedSha1Thumbprint, certificate.Thumbprint);
            Assert.Equal("1.2.840.10045.4.3.2", certificate.AlgorithmIdentifier.Algorithm.Value);
            Assert.Equal("1.2.840.10045.4.3.2", certificate.SignatureAlgorithmIdentifier.Algorithm.Value);
            Assert.Null(certificate.AlgorithmIdentifier.Parameters);
            Assert.Equal(2, certificate.Version);
            Assert.Equal(5, certificate.Issuer.Count);
            Assert.Equal("C=GB, ST=Greater Manchester, L=Salford, O=COMODO CA Limited, CN=COMODO ECC Domain Validation Secure Server CA", certificate.Issuer.ToString());
            Assert.Equal(new DateTimeOffset(2016, 7, 30, 0, 0, 0, TimeSpan.Zero), certificate.NotBefore);
            Assert.Equal(new DateTimeOffset(2018, 7, 30, 23, 59, 59, TimeSpan.Zero), certificate.NotAfter);
            Assert.Equal("OU=Domain Control Validated, OU=COMODO SSL, CN=vcsjones.com", certificate.Subject.ToString());
            Assert.Equal(9, certificate.Extensions.Count);
        }

        [Fact]
        public void RawSPKIDataShouldProduceCorrectHash()
        {
            var certificate = new x509Certificate(PathHelper.CombineWithProjectPath("files/vcsjones.com.crt"));
            var expectedPkp = "jV54RY1EPxNKwrQKIa5QMGDNPSbj3VwLPtXaHiEE8y8=";
            using (var sha = SHA256.Create())
            {
                var digest = sha.ComputeHash(certificate.PublicKey.RawData.Array, certificate.PublicKey.RawData.Offset, certificate.PublicKey.RawData.Count);
                var base64Digest = Convert.ToBase64String(digest);
                Assert.Equal(expectedPkp, base64Digest);
            }
        }

        [Fact]
        public void ShouldDecodeBasicConstraintExtension()
        {
            var certificate = new x509Certificate(PathHelper.CombineWithProjectPath("files/vcsjones.com.crt"));
            var basicConstraintsExtension = (BasicConstraintsExtension)certificate.Extensions.Single(ext => ext.Oid == KnownOids.CertificateExtensions.id_ce_basicConsraints);
            Assert.False(basicConstraintsExtension.CA);
            Assert.Equal(0, basicConstraintsExtension.PathLengthConstraint);
            Assert.True(basicConstraintsExtension.Critical);
        }

        [Fact]
        public void ShouldDecodeEKUExtension()
        {
            var certificate = new x509Certificate(PathHelper.CombineWithProjectPath("files/vcsjones.com.crt"));
            var ekuExtension = (ExtendedKeyUsageExtension)certificate.Extensions.Single(ext => ext.Oid == KnownOids.CertificateExtensions.id_ce_extKeyUsage);
            Assert.Equal(2, ekuExtension.KeyPurposeIds.Count);
            Assert.Equal(new [] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" }, ekuExtension.KeyPurposeIds.Select(kp => kp.Value));
            Assert.False(ekuExtension.Critical);
        }

        [Fact]
        public async Task ShouldExportCertificateToStream()
        {
            var certificate = new x509Certificate(PathHelper.CombineWithProjectPath("files/vcsjones.com.crt"));
            var ms = new MemoryStream();
            await certificate.ExportAsync(ms);
            ms.Position = 0;
            Assert.Equal(0x30, ms.ReadByte());
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
            Assert.Equal(id_at_commonName, dn[0][0].ObjectIdentifier.Value);
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
            Assert.Equal(id_at_commonName, dn[0][0].ObjectIdentifier.Value);
            Assert.Equal("Kevin Jones", dn[0][0].Value);
            Assert.Equal(id_at_countryName, dn[1][0].ObjectIdentifier.Value);
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
            Assert.Equal(id_at_commonName, dn[0][0].ObjectIdentifier.Value);
            Assert.Equal(id_at_countryName, dn[0][1].ObjectIdentifier.Value);
            Assert.Equal("Kevin Jones", dn[0][0].Value);
            Assert.Equal("US", dn[0][1].Value);
            Assert.Equal("CN=Kevin Jones + C=US, CN=Turtle", dn.ToString());
        }

        [
            Theory,
            InlineData("files/vcsjones.com.crt", "files/vcsjones.com.crt", true),
            InlineData("files/vcsjones.com.crt", "files/thycotic.com.crt", false),
        ]
        public void ShouldCheckThumbprints(string path1, string path2, bool isZero)
        {
            var cert1 = new x509Certificate(PathHelper.CombineWithProjectPath(path1));
            var cert2 = new x509Certificate(PathHelper.CombineWithProjectPath(path2));
            if (isZero)
            {
                Assert.Equal(0, cert1.CompareTo(cert2, x509Certificate.ThumbprintComparer.Instance));
            }
            else
            {
                Assert.NotEqual(0, cert1.CompareTo(cert2, x509Certificate.ThumbprintComparer.Instance));
            }
        }

        [
            Theory,
            InlineData("files/vcsjones.com.crt", "files/vcsjones.com.crt", true),
            InlineData("files/vcsjones.com.crt", "files/thycotic.com.crt", false),
        ]
        public void ShouldCheckIssuerAndSerial(string path1, string path2, bool isZero)
        {
            var cert1 = new x509Certificate(PathHelper.CombineWithProjectPath(path1));
            var cert2 = new x509Certificate(PathHelper.CombineWithProjectPath(path2));
            if (isZero)
            {
                Assert.Equal(0, cert1.CompareTo(cert2, x509Certificate.IssuerAndSerialComparer.Instance));
            }
            else
            {
                Assert.NotEqual(0, cert1.CompareTo(cert2, x509Certificate.IssuerAndSerialComparer.Instance));
            }
        }

        [
            Theory,
            InlineData("files/vcsjones.com.crt", "files/vcsjones.com.crt", true),
            InlineData("files/vcsjones.com.crt", "files/thycotic.com.crt", false),
        ]
        public void ShouldCheckByteEquality(string path1, string path2, bool isZero)
        {
            var cert1 = new x509Certificate(PathHelper.CombineWithProjectPath(path1));
            var cert2 = new x509Certificate(PathHelper.CombineWithProjectPath(path2));
            if (isZero)
            {
                Assert.Equal(0, cert1.CompareTo(cert2, x509Certificate.IdenticalCertificateComparer.Instance));
            }
            else
            {
                Assert.NotEqual(0, cert1.CompareTo(cert2, x509Certificate.IdenticalCertificateComparer.Instance));
            }
        }
    }
}

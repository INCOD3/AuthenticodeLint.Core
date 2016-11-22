
using System;
using AuthenticodeLint.Core.x509;
using Xunit;

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
			Console.WriteLine(certificate.Issuer.ToString());
		}
	}
}

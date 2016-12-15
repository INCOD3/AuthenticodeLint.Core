using System;
using System.IO;
using System.Threading.Tasks;
using AuthenticodeLint.Core.Asn;
using AuthenticodeLint.Core.PE;
using AuthenticodeLint.Core.Pkcs7;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class Pkcs7CmsSignatureTests
    {
        [Fact]
        public async Task ShouldLoadFromPe()
        {
            PathHelper.CombineWithProjectPath("");
            var rawPkcs7 = await GetCmsForAuthenticodeFile(PathHelper.CombineWithProjectPath("files/authlint.exe"));
            var decoded = new CmsSignature(rawPkcs7);
            Assert.Equal(ContentType.SignedData, decoded.ContentType);
            var content = Assert.IsType<CmsSignedData>(decoded.Content);
            Assert.Equal(4, content.Certificates.Count);
            Assert.Equal(1, content.SignerInfos.Count);
            var signerInfo = content.SignerInfos[0];
            Assert.NotNull(signerInfo.IssuerAndSerialNumber);
            Assert.Equal(1, signerInfo.Version);
            Assert.Equal("1.3.14.3.2.26", signerInfo.DigestAlgorithm.Algorithm);
            Assert.Equal("1.2.840.10045.2.1", signerInfo.EncryptionAlgorithm.Algorithm);
            Assert.Equal(4, signerInfo.AuthenticatedAttributes.Count);
        }

        [Fact]
        public async Task ShouldLoadAuthenticatedAttributes()
        {
            var rawPkcs7 = await GetCmsForAuthenticodeFile(PathHelper.CombineWithProjectPath("files/authlint.exe"));
            var decoded = new CmsSignature(rawPkcs7);
            Assert.Equal(ContentType.SignedData, decoded.ContentType);
            var content = Assert.IsType<CmsSignedData>(decoded.Content);
            var signerInfo = content.SignerInfos[0];

            var opus = Assert.IsType<CmsOpusAttribute>(signerInfo.AuthenticatedAttributes[3]);
            Assert.Equal("Authenticode Lint", opus.ProgramName);
            var moreInfoUrl = Assert.IsType<SpcMoreInfoString>(opus.MoreInfo);
            Assert.Equal("https://vcsjones.com/authlint\u0020", moreInfoUrl.Value);

            var digestAttribute = Assert.IsType<CmsMessageDigestAttibute>(signerInfo.AuthenticatedAttributes[2]);
            var expectedDigest = new byte[] { 0x1D, 0xC0, 0x36, 0x8A, 0xA7, 0xDC, 0x96, 0xE4, 0xAC, 0x57, 0x90, 0xBC, 0x3A, 0x4E, 0xEE, 0x35, 0x6A, 0x85, 0x2C, 0xCF };
            Assert.Equal(new ArraySegment<byte>(expectedDigest), digestAttribute.Digest);
        }


        [Fact]
        public async Task ShouldLoadUnauthenticatedAttributes()
        {
            var rawPkcs7 = await GetCmsForAuthenticodeFile(PathHelper.CombineWithProjectPath("files/authlint.exe"));
            var decoded = new CmsSignature(rawPkcs7);
            Assert.Equal(ContentType.SignedData, decoded.ContentType);
            var content = Assert.IsType<CmsSignedData>(decoded.Content);
            var signerInfo = content.SignerInfos[0];
            //expecting timestamp and nested signature
            Assert.Equal(2, signerInfo.UnauthenticatedAttributes.Count);

            var nestedSignature = Assert.IsType<CmsNestedSignatureAttribute>(signerInfo.UnauthenticatedAttributes[1]);
            Assert.Equal(ContentType.SignedData, nestedSignature.Signature.ContentType);
        }

        private static async Task<byte[]> GetCmsForAuthenticodeFile(string path)
        {
            using (var pe = new PortableExecutable(path))
            {
                var header = await pe.GetDosHeaderAsync();
                var peHeader = await pe.GetPeHeaderAsync(header);
                var securityHeader = peHeader.DataDirectories[ImageDataDirectoryEntry.IMAGE_DIRECTORY_ENTRY_SECURITY];
                using (var file = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read))
                {
                    SecuritySection section;
                    var result = SecuritySection.ReadSection(file, securityHeader, out section);
                    Assert.True(result);
                    return section.Data;
                }
            }
        }
    }
}
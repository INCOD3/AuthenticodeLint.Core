using System.IO;
using System.Threading.Tasks;
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
            var rawPkcs7 = await GetCmsForAuthenticodeFile("files/authlint.exe");
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
        }

        private static async Task<byte[]> GetCmsForAuthenticodeFile(string path)
        {
            using (var pe = new PortableExecutable(path))
            {
                var header = await pe.GetDosHeader();
                var peHeader = await pe.GetPeHeader(header);
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
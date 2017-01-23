using AuthenticodeLint.Core.PE;
using System.IO;

using Xunit;
using System.Threading.Tasks;
using System.Security.Cryptography;
using AuthenticodeLint.Core.Pkcs7;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Tests
{
    public class PortableExecutableDigestProcessorTests
    {
        [Fact]
        public async Task ShouldCalculateImageHash()
        {
            var rawPkcs7 = await GetCmsForAuthenticodeFile(PathHelper.CombineWithProjectPath("files/authlint.exe"));
            var decoded = new CmsSignature(rawPkcs7);
            Assert.Equal(ContentType.SignedData, decoded.ContentType);
            var content = Assert.IsType<CmsSignedData>(decoded.Content);
            var contentSequence = (AsnSequence)content.ContentInfo.Content;
            var spc = new SpcIndirectDataContent(contentSequence);
            Assert.Equal(KnownOids.Algorithms.Digest.sha1, spc.DigestInfo.AlgorithmIdentifier.Algorithm.Value);
            var theRealDigest = spc.DigestInfo.Digest;
            using (var pe = new PortableExecutable(PathHelper.CombineWithProjectPath("files/authlint.exe")))
            {
                using (var sha1 = SHA1.Create())
                {
                    var digest = await PortableExecutableDigestProcessor.Calculate(pe, sha1);
                    Assert.Equal(0, ArraySegmentHelpers.Compare(theRealDigest, digest));
                }
            }
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
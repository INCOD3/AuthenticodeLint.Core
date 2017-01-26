using AuthenticodeLint.Core.PE;
using System.IO;

using Xunit;
using System.Threading.Tasks;
using System.Security.Cryptography;
using AuthenticodeLint.Core.Pkcs7;
using AuthenticodeLint.Core.Asn;
using System.Runtime.InteropServices;

namespace AuthenticodeLint.Core.Tests
{
    public class PortableExecutableDigestProcessorTests
    {
        /*
        [Fact]
        public async Task ShouldCalculateImageHash()
        {
            var path = PathHelper.CombineWithProjectPath("files/authlint.exe");
            var rawPkcs7 = await GetCmsForAuthenticodeFile(path);
            var decoded = new CmsSignature(rawPkcs7);
            Assert.Equal(ContentType.SignedData, decoded.ContentType);
            var content = Assert.IsType<CmsSignedData>(decoded.Content);
            var contentSequence = (AsnSequence)content.ContentInfo.Content;
            var spc = new SpcIndirectDataContent(contentSequence);
            Assert.Equal(KnownOids.Algorithms.Digest.sha1, spc.DigestInfo.AlgorithmIdentifier.Algorithm.Value);
            var theRealDigest = spc.DigestInfo.Digest;


            var digest = PortableExecutableDigestProcessor.Calculate(path, HashAlgorithmName.SHA1);
            Assert.Equal(0, ArraySegmentHelpers.Compare(theRealDigest, digest));
        }
        */

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        private struct Foo
        {
            public byte a1;
            public uint ignore;
            public byte a2;
        }

        [Fact]
        public void ShouldSkipUInt32StructField()
        {
            var foo = new Foo { a1 = 1, ignore = 0xFFFFFFFF, a2 = 2 };
            using (var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                PortableExecutableDigestProcessor.WriteStructAndSkipUInt32Field(ih, foo, "ignore");
                var expectedDigest = new byte[] {
                    0x0c, 0xa6, 0x23, 0xe2, 0x85, 0x5f, 0x2c, 0x75, 0xc8, 0x42,
                    0xad, 0x30, 0x2f, 0xe8, 0x20, 0xe4, 0x1b, 0x4d, 0x19, 0x7d };
                var digest = ih.GetHashAndReset();
                Assert.Equal(expectedDigest, digest);
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
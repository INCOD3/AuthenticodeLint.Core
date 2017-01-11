using System.IO;
using System.Threading.Tasks;
using AuthenticodeLint.Core.PE;
using AuthenticodeLint.Core.Pkcs7;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class CmsMessageSignatureTests
    {
        [Fact]
        public async Task ShouldVerifySignature()
        {
            var rawPkcs7 = await GetCmsForAuthenticodeFile(PathHelper.CombineWithProjectPath("files/authlint.exe"));
            var decoded = new CmsSignature(rawPkcs7);
            var verify = await decoded.VerifySignature();
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
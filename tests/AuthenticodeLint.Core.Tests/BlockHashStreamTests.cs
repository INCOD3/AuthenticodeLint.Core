using System.IO;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class HashStreamTests
    {
        [Fact]
        public async Task ShouldHashTwoSimpleBytes()
        {
            for (var i = 0; i < 1000; i++)
            {
                using (var sha1 = SHA1.Create())
                using (var bhs = new BlockHashStream(sha1))
                {
                    bhs.WriteByte(1);
                    bhs.WriteByte(2);
                    var digest = await bhs.Digest();
                    var expectedDigest = new byte[] {
                    0x0c, 0xa6, 0x23, 0xe2, 0x85, 0x5f, 0x2c, 0x75, 0xc8, 0x42,
                    0xad, 0x30, 0x2f, 0xe8, 0x20, 0xe4, 0x1b, 0x4d, 0x19, 0x7d };
                    Assert.Equal(expectedDigest, digest);
                }
            }
        }


        [Fact]
        public async Task ShouldHash32KFile()
        {
            for (var i = 0; i < 1000; i++)
            {
                using (var sha1 = SHA1.Create())
                using (var bhs = new BlockHashStream(sha1))
                using (var fs = new FileStream(PathHelper.CombineWithProjectPath("files/random.bin"), FileMode.Open))
                {
                    await fs.CopyToAsync(bhs, bhs.BufferSize);
                    var digest = await bhs.Digest();
                    var expectedDigest = new byte[] {
                        0x51, 0x88, 0x43, 0x18, 0x49, 0xb4, 0x61, 0x31, 0x52, 0xfd,
                        0x7b, 0xdb, 0xa6, 0xa3, 0xff, 0x0a, 0x4f, 0xd6, 0x42, 0x4b
                    };
                    Assert.Equal(expectedDigest, digest);
                }
            }
        }

        [Fact]
        public async Task ShouldAllowEmptyHash()
        {
            for (var i = 0; i < 1000; i++)
            {
                using (var sha1 = SHA1.Create())
                using (var bhs = new BlockHashStream(sha1))
                {
                    var digest = await bhs.Digest();
                    var expectedDigest = new byte[] {
                        0xda, 0x39, 0xa3, 0xee, 0x5e, 0x6b, 0x4b, 0x0d, 0x32, 0x55,
                        0xbf, 0xef, 0x95, 0x60, 0x18, 0x90, 0xaf, 0xd8, 0x07, 0x09
                    };
                    Assert.Equal(expectedDigest, digest);
                }
            }
        }
    }
}
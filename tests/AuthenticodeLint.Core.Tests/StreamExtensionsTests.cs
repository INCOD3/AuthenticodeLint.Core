using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class StreamExtensionsTests
    {
        [Fact]
        public async Task ShouldCopyStreamsBelowBufferSize()
        {
            using (var src = new MemoryStream(new byte[] { 1, 2, 3 }))
            {
                using (var dst = new MemoryStream())
                {
                    await StreamExtensions.CopyUpToAsync(src, dst, 2);
                    var result = dst.ToArray();
                    Assert.Equal(new byte[] { 1, 2 }, result);
                }
            }
        }

        [Fact]
        public async Task ShouldCopyStreamsExactlyBufferSize()
        {
            using (var src = new MemoryStream(new byte[] { 1, 2, 3, 4 }))
            {
                using (var dst = new MemoryStream())
                {
                    await StreamExtensions.CopyUpToAsync(src, dst, 4, bufferSize: 4);
                    var result = dst.ToArray();
                    Assert.Equal(new byte[] { 1, 2, 3, 4 }, result);
                }
            }
        }

        [Fact]
        public async Task ShouldCopyStreamsExactlyBufferSizeWithMultipleBlocks()
        {
            using (var src = new MemoryStream(new byte[] { 1, 2, 3, 4 }))
            {
                using (var dst = new MemoryStream())
                {
                    await StreamExtensions.CopyUpToAsync(src, dst, 4, bufferSize: 2);
                    var result = dst.ToArray();
                    Assert.Equal(new byte[] { 1, 2, 3, 4 }, result);
                }
            }
        }

        [Fact]
        public async Task ShouldCopyStreamsAboveBufferSizeWithMultipleBlocks()
        {
            using (var src = new MemoryStream(new byte[] { 1, 2, 3, 4 }))
            {
                using (var dst = new MemoryStream())
                {
                    await StreamExtensions.CopyUpToAsync(src, dst, 3, bufferSize: 2);
                    var result = dst.ToArray();
                    Assert.Equal(new byte[] { 1, 2, 3 }, result);
                }
            }
        }

        [Fact]
        public async Task ShouldCopyStreamsAboveBufferSizeMoreThanAvailable()
        {
            using (var src = new MemoryStream(new byte[] { 1, 2, 3, 4 }))
            {
                using (var dst = new MemoryStream())
                {
                    await StreamExtensions.CopyUpToAsync(src, dst, 9000, bufferSize: 2);
                    var result = dst.ToArray();
                    Assert.Equal(new byte[] { 1, 2, 3, 4 }, result);
                }
            }
        }
    }
}
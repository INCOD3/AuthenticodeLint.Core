using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class HashStreamTests
    {
        private void WithNativeMemory(byte[] contents, Action<SafeHandle> wrapper)
        {
            LocalMemorySafeHandle handle = null;
            try
            {
                var ptr = Marshal.AllocHGlobal(contents.Length);
                Marshal.Copy(contents, 0, ptr, contents.Length);
                handle = new LocalMemorySafeHandle(ptr);
                wrapper(handle);
            }
            finally
            {
                handle?.Dispose();
            }
        }

        private class LocalMemorySafeHandle : SafeHandle
        {
            public LocalMemorySafeHandle() : base(IntPtr.Zero, true)
            {
            }

            public LocalMemorySafeHandle(IntPtr handle) : base(IntPtr.Zero, true)
            {
                SetHandle(handle);
            }

            public override bool IsInvalid => handle == IntPtr.Zero;

            protected override bool ReleaseHandle()
            {
                Marshal.FreeHGlobal(handle);
                return true;
            }
        }

        [Fact]
        public async Task ShouldHashNativeMemory()
        {
            using (var sha1 = SHA1.Create())
            using (var bhs = new BlockHashStream(sha1))
            {
                WithNativeMemory(new byte[] { 1, 2 }, ptr => {
                    bhs.Write(ptr, 0, 2);
                });
                var expectedDigest = new byte[] {
                    0x0c, 0xa6, 0x23, 0xe2, 0x85, 0x5f, 0x2c, 0x75, 0xc8, 0x42,
                    0xad, 0x30, 0x2f, 0xe8, 0x20, 0xe4, 0x1b, 0x4d, 0x19, 0x7d };
                var digest = await bhs.Digest();
                Assert.Equal(expectedDigest, digest);
            }
        }

        [Fact]
        public async Task ShouldHashNativeMemoryWithOffsets()
        {
            using (var sha1 = SHA1.Create())
            using (var bhs = new BlockHashStream(sha1))
            {
                WithNativeMemory(new byte[] { 1, 2, 3, 4, 1, 2 }, ptr => {
                    bhs.Write(ptr, 4, 2);
                });
                var expectedDigest = new byte[] {
                    0x0c, 0xa6, 0x23, 0xe2, 0x85, 0x5f, 0x2c, 0x75, 0xc8, 0x42,
                    0xad, 0x30, 0x2f, 0xe8, 0x20, 0xe4, 0x1b, 0x4d, 0x19, 0x7d };
                var digest = await bhs.Digest();
                Assert.Equal(expectedDigest, digest);
            }
        }

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
        public async Task ShouldHashMemoryMapped32KFile()
        {
            var file = PathHelper.CombineWithProjectPath("files/random.bin");
            for (var i = 0; i < 30; i++)
            {
                using (var sha1 = SHA1.Create())
                using (var bhs = new BlockHashStream(sha1))
                using (var mmf = MemoryMappedFile.CreateFromFile(file))
                using (var va = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
                {
                    bhs.Write(va.SafeMemoryMappedViewHandle, 0, 32768);
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
        public async Task ShouldHashNativeMemoryOddFromBufferSize()
        {
            using (var sha1 = SHA1.Create())
            using (var bhs = new BlockHashStream(sha1, 4))
            {
                WithNativeMemory(new byte[] { 1, 2, 3, 4, 5 }, ptr => {
                    bhs.Write(ptr, 0, 5);
                });
                var expectedDigest = new byte[] {
                    0x11, 0x96, 0x6a, 0xb9, 0xc0, 0x99, 0xf8, 0xfa, 0xbe, 0xfa,
                    0xc5, 0x4c, 0x08, 0xd5, 0xbe, 0x2b, 0xd8, 0xc9, 0x03, 0xaf };
                var digest = await bhs.Digest();
                Assert.Equal(expectedDigest, digest);
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
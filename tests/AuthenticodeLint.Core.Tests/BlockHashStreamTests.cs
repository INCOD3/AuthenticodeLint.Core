using System;
using System.IO.MemoryMappedFiles;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class HashStreamTests
    {
        [Fact]
        public void ShouldBlowUpWhenTryingToWriteAnAutoLayoutStruct()
        {
            using (var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                var badStruct = new BadStruct {
                    b1 = 1
                };
                Assert.Throws<InvalidOperationException>(() => ih.WriteStruct(badStruct));
            }
        }

        [Fact]
        public void ShouldHashAStruct()
        {
            using (var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                ih.WriteStruct(new SimpleStruct {
                    b1 = 1,
                    b2 = 2
                });
                var expectedDigest = new byte[] {
                    0x0c, 0xa6, 0x23, 0xe2, 0x85, 0x5f, 0x2c, 0x75, 0xc8, 0x42,
                    0xad, 0x30, 0x2f, 0xe8, 0x20, 0xe4, 0x1b, 0x4d, 0x19, 0x7d };
                var digest = ih.GetHashAndReset();
                Assert.Equal(expectedDigest, digest);
            }
        }

        [Fact]
        public void ShouldHashAStructWithPaddingAndMarshalCorrectly()
        {
            using (var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                ih.WriteStruct(new PaddedStruct {
                    b1 = 1,
                    b2 = 2
                });
                var expectedDigest = new byte[] {
                   0x0c, 0xf1, 0x69, 0xa9, 0x5b, 0xd3, 0x2a, 0x9a, 0x1d, 0xc4,
                   0xc3, 0x49, 0x9a, 0xde, 0x20, 0x7d, 0x30, 0xab, 0x88, 0x95 };
                var digest = ih.GetHashAndReset();
                Assert.Equal(expectedDigest, digest);
            }
        }

        [Fact]
        public void ShouldHashNativeMemory()
        {
            using (var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                WithNativeMemory(new byte[] { 1, 2 }, ptr => {
                    ih.Write(ptr, 0, 2);
                });
                var expectedDigest = new byte[] {
                    0x0c, 0xa6, 0x23, 0xe2, 0x85, 0x5f, 0x2c, 0x75, 0xc8, 0x42,
                    0xad, 0x30, 0x2f, 0xe8, 0x20, 0xe4, 0x1b, 0x4d, 0x19, 0x7d };
                var digest = ih.GetHashAndReset();
                Assert.Equal(expectedDigest, digest);
            }
        }

        [Fact]
        public void ShouldHashNativeMemoryWithOffsets()
        {
            using (var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                WithNativeMemory(new byte[] { 1, 2, 3, 4, 1, 2 }, ptr => {
                    ih.Write(ptr, 4, 2);
                });
                var expectedDigest = new byte[] {
                    0x0c, 0xa6, 0x23, 0xe2, 0x85, 0x5f, 0x2c, 0x75, 0xc8, 0x42,
                    0xad, 0x30, 0x2f, 0xe8, 0x20, 0xe4, 0x1b, 0x4d, 0x19, 0x7d };
                var digest = ih.GetHashAndReset();
                Assert.Equal(expectedDigest, digest);
            }
        }


        [Fact]
        public void ShouldHashMemoryMapped32KFile()
        {
            var file = PathHelper.CombineWithProjectPath("files/random.bin");
            for (var i = 0; i < 30; i++)
            {
                using (var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
                using (var mmf = MemoryMappedFile.CreateFromFile(file))
                using (var va = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
                {
                    ih.Write(va.SafeMemoryMappedViewHandle, 0, 32768);
                    var digest = ih.GetHashAndReset();
                    var expectedDigest = new byte[] {
                        0x51, 0x88, 0x43, 0x18, 0x49, 0xb4, 0x61, 0x31, 0x52, 0xfd,
                        0x7b, 0xdb, 0xa6, 0xa3, 0xff, 0x0a, 0x4f, 0xd6, 0x42, 0x4b
                    };
                    Assert.Equal(expectedDigest, digest);
                }
            }
        }

        [Fact]
        public void ShouldHashNativeMemoryOddFromBufferSize()
        {
            using (var ih = IncrementalHash.CreateHash(HashAlgorithmName.SHA1))
            {
                WithNativeMemory(new byte[] { 1, 2, 3, 4, 5 }, ptr => {
                    ih.Write(ptr, 0, 5, bufferSize: 4);
                });
                var expectedDigest = new byte[] {
                    0x11, 0x96, 0x6a, 0xb9, 0xc0, 0x99, 0xf8, 0xfa, 0xbe, 0xfa,
                    0xc5, 0x4c, 0x08, 0xd5, 0xbe, 0x2b, 0xd8, 0xc9, 0x03, 0xaf };
                var digest = ih.GetHashAndReset();
                Assert.Equal(expectedDigest, digest);
            }
        }


        private void WithNativeMemory(byte[] contents, Action<IntPtr> wrapper)
        {
            var ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.AllocHGlobal(contents.Length);
                Marshal.Copy(contents, 0, ptr, contents.Length);
                wrapper(ptr);
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct SimpleStruct
        {
            public byte b1;
            public byte b2;
        }

        [StructLayout(LayoutKind.Sequential, Size = 4)]
        private struct PaddedStruct
        {
            public byte b1;
            public byte b2;
        }

        [StructLayout(LayoutKind.Auto)]
        public struct BadStruct
        {
            public byte b1;
        }
    }
}
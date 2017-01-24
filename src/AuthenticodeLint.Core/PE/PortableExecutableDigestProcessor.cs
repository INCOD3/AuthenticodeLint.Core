using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;

namespace AuthenticodeLint.Core.PE
{
    public static class PortableExecutableDigestProcessor
    {
        public static ArraySegment<byte> Calculate(
            string path,
            HashAlgorithmName algorithm,
            PortableExecutableDigestKinds kinds = PortableExecutableDigestKinds.IncludeEverything)
        {
            using (var mmf = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read))
            using (var processor = IncrementalHash.CreateHash(algorithm))
            {
                using (var va = mmf.CreateViewAccessor(0, 0, MemoryMappedFileAccess.Read))
                {
                    var dosHeader = va.ReadStruct<DosHeaderMap>();
                    if (dosHeader.e_magic != MagicValues.DOS_MAGIC)
                    {
                        throw new InvalidOperationException("Not a valid DOS application.");
                    }
                    processor.Write(va.SafeMemoryMappedViewHandle, 0, dosHeader.e_lfanew);
                }
                var digest = processor.GetSegmentHashAndReset();
                return digest;
            }
        }

        private static void WriteSection()
        {

        }
    }

    [Flags]
    public enum PortableExecutableDigestKinds : byte
    {
        IncludeResources = 0x01,
        IncludeDebugInfo = 0x02,
        IncludeImportAddressTable = 0x04,
        IncludeEverything = 0xFF
    }
}
using System;
using System.IO.MemoryMappedFiles;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace AuthenticodeLint.Core.PE
{
    ///<code>Hello<T></code>
    public static class PortableExecutableDigestProcessor
    {
        public static async Task<ArraySegment<byte>> Calculate(
            this PortableExecutable pe,
            HashAlgorithm algorithm,
            PortableExecutableDigestKinds kinds = PortableExecutableDigestKinds.IncludeEverything)
        {
            using (var processor = new BlockHashStream(algorithm))
            {
                var dosHeader = await pe.GetDosHeaderAsync();
                var peHeader = await pe.GetPeHeaderAsync(dosHeader);
                using (var stream = pe.file.CreateViewStream(0, 0, MemoryMappedFileAccess.Read))
                {
                    //Copy from the beginning of the file and the DOS header up to the address of the
                    //NT PE header.
                    await stream.CopyUpToAsync(processor, dosHeader.ExeFileHeaderAddress, processor.BufferSize);
                }
                var digest = await processor.Digest();
                var totalDigested = processor.Length;
                return digest;
            }
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
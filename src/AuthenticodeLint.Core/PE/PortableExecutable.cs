using System;
using System.Collections.Generic;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Text;
using System.Threading.Tasks;
using static AuthenticodeLint.Core.PE.MagicValues;
using ImageDirectories = System.Collections.Generic.IReadOnlyDictionary<AuthenticodeLint.Core.PE.ImageDataDirectoryEntry, AuthenticodeLint.Core.PE.ImageDataDirectory>;

namespace AuthenticodeLint.Core.PE
{
    public class PortableExecutable : IDisposable
    {
        private readonly MemoryMappedFile _file;

        public PortableExecutable(string path)
        {
            _file = MemoryMappedFile.CreateFromFile(path, FileMode.Open, null, 0, MemoryMappedFileAccess.Read);
        }

        /// <summary>
        /// Gets the DOS header from the image.
        /// </summary>
        public async Task<DosHeader> GetDosHeaderAsync()
        {
            using (var stream = _file.CreateViewStream(0, 0, MemoryMappedFileAccess.Read))
            {
                var header = await stream.ReadStructAsync<DosHeaderMap>();
                if (header.e_magic != DOS_MAGIC)
                {
                    throw new InvalidOperationException("File does not have a valid DOS header.");
                }
                var dosHeader = new DosHeader();
                dosHeader.ExeFileHeaderAddress = header.e_lfanew;
                return dosHeader;
            }
        }

        /// <summary>
        /// Gets the PE or PE+ header from the image.
        /// </summary>
        /// <returns>The pe header.</returns>
        /// <param name="dosHeader">The DOS header. The header is used to know where the PE section is located.</param>
        public async Task<PeHeader> GetPeHeaderAsync(DosHeader dosHeader)
        {
            using (var stream = _file.CreateViewStream(dosHeader.ExeFileHeaderAddress, 0, MemoryMappedFileAccess.Read))
            {
                uint peMagicValue;
                using (var reader = new BinaryReader(stream, Encoding.ASCII, true))
                {
                    peMagicValue = reader.ReadUInt32();
                }
                if (peMagicValue != IMAGE_NT_SIGNATURE)
                {
                    throw new InvalidOperationException("File does not have a valid PE header.");
                }
                var header = await stream.ReadStructAsync<ImageFileHeaderMap>();
                var peHeader = new PeHeader();
                if (header.Machine == IMAGE_FILE_MACHINE_AMD64)
                {
                    peHeader.Architecture = MachineArchitecture.x8664;
                    var header64 = await stream.ReadStructAsync<ImageOptionHeader64Map>();
                    if (header64.Magic != PE32_64)
                    {
                        throw new InvalidOperationException("File is x86-64 but has a image type other than PE32+.");
                    }
                }
                else if (header.Machine == IMAGE_FILE_MACHINE_I386)
                {
                    peHeader.Architecture = MachineArchitecture.x86;
                    var header32 = await stream.ReadStructAsync<ImageOptionHeader32Map>();
                    if (header32.Magic != PE32_32)
                    {
                        throw new InvalidOperationException("File is x86 but has a image type other than PE32.");
                    }
                }
                else
                {
                    throw new InvalidOperationException("Architecture is not supported.");
                }
                peHeader.DataDirectories = await ReadDirectoryEntriesAsync(stream, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
                return peHeader;
            }
        }

        /// <summary>
        /// Reads a directory's contents as a stream. The caller is responsible for closing the stream when complete.
        /// </summary>
        public Stream ReadDataDirectory(ImageDataDirectory directory)
        {
            if (directory == null)
            {
                throw new ArgumentNullException(nameof(directory));
            }
            if (directory.VirtualAddress == 0 || directory.Size == 0)
            {
                throw new ArgumentOutOfRangeException(nameof(directory), "Directory does not contain data.");
            }
            return _file.CreateViewStream(directory.VirtualAddress, directory.Size, MemoryMappedFileAccess.Read);
        }

        private static async Task<ImageDirectories> ReadDirectoryEntriesAsync(MemoryMappedViewStream stream, int count)
        {
            var dictionary = new Dictionary<ImageDataDirectoryEntry, ImageDataDirectory>();
            var directories = await stream.ReadStructArrayAsync<ImageDataDirectoryMap>(count);
            for (var i = 0; i < count; i++)
            {
                var entry = new ImageDataDirectory
                {
                    Size = directories[i].Size,
                    VirtualAddress = directories[i].VirtualAddress
                };
                dictionary.Add((ImageDataDirectoryEntry)i, entry);
            }
            return dictionary;
        }

        public void Dispose()
        {
            _file.Dispose();
        }
    }

    public sealed class DosHeader
    {
        public int ExeFileHeaderAddress { get; internal set; }
    }

    public sealed class PeHeader
    {
        public MachineArchitecture Architecture { get; internal set; }
        public ImageDirectories DataDirectories { get; internal set; }
    }

    public sealed class ImageDataDirectory
    {
        public long VirtualAddress { get; internal set; }
        public long Size { get; internal set; }
    }

    public enum MachineArchitecture
    {
        x86,
        x8664
    }

    public enum ImageDataDirectoryEntry
    {
        IMAGE_DIRECTORY_ENTRY_EXPORT = 0,
        IMAGE_DIRECTORY_ENTRY_IMPORT = 1,
        IMAGE_DIRECTORY_ENTRY_RESOURCE = 2,
        IMAGE_DIRECTORY_ENTRY_EXCEPTION = 3,
        IMAGE_DIRECTORY_ENTRY_SECURITY = 4,
        IMAGE_DIRECTORY_ENTRY_BASERELOC = 5,
        IMAGE_DIRECTORY_ENTRY_DEBUG = 6,
        IMAGE_DIRECTORY_ENTRY_ARCHITECTURE = 7,
        IMAGE_DIRECTORY_ENTRY_GLOBALPTR = 8,
        IMAGE_DIRECTORY_ENTRY_TLS = 9,
        IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10,
        IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11,
        IMAGE_DIRECTORY_ENTRY_IAT = 12,
        IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13,
        IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14,
    }
}

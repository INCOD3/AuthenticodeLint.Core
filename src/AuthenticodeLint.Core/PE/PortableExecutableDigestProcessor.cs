using System;
using System.IO;
using System.IO.MemoryMappedFiles;
using System.Linq;
using System.Runtime.InteropServices;
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
                    var header = va.ReadStruct<ImageNtHeadersAny>(dosHeader.e_lfanew);
                    if (header.Signature != MagicValues.IMAGE_NT_SIGNATURE)
                    {
                        throw new InvalidOperationException("Not a valid NT header: " + header.Signature.ToString("X"));
                    }
                    ImageDataDirectoryMap[] dataDirectories;
                    int numberOfSections;
                    int sectionOffset;

                    //write the non-specific platform headers first.
                    processor.WriteStruct(header.Signature);
                    processor.WriteStruct(header.FileHeader);

                    if (header.FileHeader.Machine == MagicValues.IMAGE_FILE_MACHINE_I386)
                    {
                        var fullHeader = va.ReadStruct<ImageNtHeaders32>(dosHeader.e_lfanew);
                        WriteStructAndSkipUInt32Field(processor, fullHeader.OptionalHeader, nameof(fullHeader.OptionalHeader.CheckSum));

                        //we haven't written the DataDirectories yet because they aren't
                        //part of our optional header.
                        var directoriesLocation = dosHeader.e_lfanew + Marshal.SizeOf<ImageNtHeaders32>();


                        var directoriesTableSize = MagicValues.IMAGE_NUMBEROF_DIRECTORY_ENTRIES * Marshal.SizeOf<ImageDataDirectoryMap>();
                        var size = fullHeader.FileHeader.SizeOfOptionalHeader;
                        if (directoriesTableSize + Marshal.SizeOf<ImageOptionHeader32Map>() != size)
                        {
                            //Since we have to do goofy slicing of structs due to marshalling limitations,
                            //we want to verify that the struct sizes are correct.
                            throw new InvalidOperationException("Header sizes do not match.");
                        }
                        dataDirectories = va.ReadStructArray<ImageDataDirectoryMap>(MagicValues.IMAGE_NUMBEROF_DIRECTORY_ENTRIES, directoriesLocation);
                        numberOfSections = fullHeader.FileHeader.NumberOfSections;
                        sectionOffset = directoriesLocation + directoriesTableSize;
                    }
                    else if (header.FileHeader.Machine == MagicValues.IMAGE_FILE_MACHINE_AMD64)
                    {
                        var fullHeader = va.ReadStruct<ImageNtHeaders64>(dosHeader.e_lfanew);
                        WriteStructAndSkipUInt32Field(processor, fullHeader.OptionalHeader, nameof(fullHeader.OptionalHeader.CheckSum));

                        //we haven't written the DataDirectories yet because they aren't
                        //part of our optional header.
                        var directoriesLocation = dosHeader.e_lfanew + Marshal.SizeOf<ImageNtHeaders64>();


                        var directoriesTableSize = MagicValues.IMAGE_NUMBEROF_DIRECTORY_ENTRIES * Marshal.SizeOf<ImageDataDirectoryMap>();
                        var size = fullHeader.FileHeader.SizeOfOptionalHeader;
                        if (directoriesTableSize + Marshal.SizeOf<ImageOptionHeader64Map>() != size)
                        {
                            //Since we have to do goofy slicing of structs due to marshalling limitations,
                            //we want to verify that the struct sizes are correct.
                            throw new InvalidOperationException("Header sizes do not match.");
                        }
                        dataDirectories = va.ReadStructArray<ImageDataDirectoryMap>(MagicValues.IMAGE_NUMBEROF_DIRECTORY_ENTRIES, directoriesLocation);
                        numberOfSections = fullHeader.FileHeader.NumberOfSections;
                        sectionOffset = directoriesLocation + directoriesTableSize;
                    }
                    else
                    {
                        throw new PlatformNotSupportedException();
                    }
                    //Write all of the directories, minus the "security" section.
                    for (var i = 0; i < dataDirectories.Length; i++)
                    {
                        //directories are always ordered, so we know the one at the security index
                        //can be skipped.
                        //Windows skips the security section because that contains the signature itself,
                        //and not skipping it would cause the the act of storing the signature to invalidate
                        //itself.
                        if (i == (int)ImageDataDirectoryEntry.IMAGE_DIRECTORY_ENTRY_SECURITY)
                        {
                            continue;
                        }
                        processor.WriteStruct(dataDirectories[i]);
                    }

                    //Write all of the sections
                    var headers = va.ReadStructArray<IMAGE_SECTION_HEADER>(numberOfSections, sectionOffset);
                    var sortedHeaders = headers.OrderBy(h => h.PointerToRawData).ToArray();
                    for (var i = 0; i < numberOfSections; i++)
                    {
                        var sectionHeader = sortedHeaders[i];
                        unsafe
                        {
                            //It's not clear if Win32 will ever use anything other than "do it all"
                            //but we can support omitting sections if it turns out to be a real thing.
                            var name = System.Text.Encoding.UTF8.GetString(sectionHeader.Name, 8);
                            if (name == SectionNames.DEBUG && (kinds & PortableExecutableDigestKinds.IncludeDebugInfo) == 0)
                            {
                                continue;
                            }
                            if (name == SectionNames.RESOURCES && (kinds & PortableExecutableDigestKinds.IncludeResources) == 0)
                            {
                                continue;
                            }
                            if (name == SectionNames.IMPORT_TABLE && (kinds & PortableExecutableDigestKinds.IncludeImportAddressTable) == 0)
                            {
                                continue;
                            }
                            if (sectionHeader.SizeOfRawData == 0)
                            {
                                continue;
                            }
                        }
                        processor.Write(va.SafeMemoryMappedViewHandle, (int)sectionHeader.PointerToRawData, (int)sectionHeader.SizeOfRawData);
                    }
                }
                var digest = processor.GetSegmentHashAndReset();
                return digest;
            }
        }

        public static void WriteStructAndSkipUInt32Field<T>(IncrementalHash ih, T val, string fieldName)
            where T : struct
        {
            var fieldOffset = Marshal.OffsetOf<T>(fieldName);
            var size = Marshal.SizeOf<T>();
            var ptr = IntPtr.Zero;
            try
            {
                ptr = Marshal.AllocHGlobal(size);
                Marshal.StructureToPtr<T>(val, ptr, false);
                ih.Write(ptr, 0, fieldOffset.ToInt32());
                ih.Write(ptr, fieldOffset.ToInt32() + Marshal.SizeOf<uint>(), size - 1 - Marshal.SizeOf<uint>());
            }
            finally
            {
                Marshal.FreeHGlobal(ptr);
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

    public static class SectionNames
    {
        public const string RESOURCES = ".rsrc\0\0\0";
        public const string DEBUG = ".debug\0\0";
        public const string TEXT = ".text\0\0\0";
        public const string IMPORT_TABLE = ".idata\0\0";
    }
}
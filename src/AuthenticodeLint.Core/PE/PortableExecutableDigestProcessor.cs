using System;
using System.IO;
using System.IO.MemoryMappedFiles;
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
                    if (header.FileHeader.Machine == MagicValues.IMAGE_FILE_MACHINE_I386)
                    {
                        var fullHeader = va.ReadStruct<ImageNtHeaders32>(dosHeader.e_lfanew);
                        fullHeader.OptionalHeader.SizeOfInitializedData = 0;
                        fullHeader.OptionalHeader.CheckSum = 0;
                        fullHeader.OptionalHeader.SizeOfImage = 0;
                        processor.WriteStruct(fullHeader);

                        //we haven't written the DataDirectories yet because they aren't
                        //part of our optional header.
                        var directoriesLocation = dosHeader.e_lfanew + Marshal.SizeOf<ImageNtHeaders32>();

                        //we want to hash the directory table verbatim
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
                        processor.Write(va.SafeMemoryMappedViewHandle, directoriesLocation, directoriesTableSize);
                    }
                    else if (header.FileHeader.Machine == MagicValues.IMAGE_FILE_MACHINE_AMD64)
                    {
                        var fullHeader = va.ReadStruct<ImageNtHeaders64>(dosHeader.e_lfanew);
                        fullHeader.OptionalHeader.SizeOfInitializedData = 0;
                        fullHeader.OptionalHeader.CheckSum = 0;
                        fullHeader.OptionalHeader.SizeOfImage = 0;
                        processor.WriteStruct(fullHeader);

                        //we haven't written the DataDirectories yet because they aren't
                        //part of our optional header.
                        var directoriesLocation = dosHeader.e_lfanew + Marshal.SizeOf<ImageNtHeaders64>();

                        //we want to hash the directory table verbatim
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
                        processor.Write(va.SafeMemoryMappedViewHandle, directoriesLocation, directoriesTableSize);
                    }
                    else
                    {
                        throw new PlatformNotSupportedException();
                    }
                    var headers = va.ReadStructArray<IMAGE_SECTION_HEADER>(numberOfSections, sectionOffset);
                    unsafe
                    {
                        for (var i = 0; i < headers.Length; i++)
                        {
                            var h = headers[i];
                            var name = h.Name;
                            var str = System.Text.Encoding.UTF8.GetString(name, 8);
                            Console.WriteLine(str);
                        }
                    }
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
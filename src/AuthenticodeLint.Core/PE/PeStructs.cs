using System.Runtime.InteropServices;

namespace AuthenticodeLint.Core.PE
{
    [type: StructLayout(LayoutKind.Sequential)]
    public struct DosHeaderMap
    {
        public ushort e_magic;
        public ushort e_cblp;
        public ushort e_cp;
        public ushort e_crlc;
        public ushort e_cparhdr;
        public ushort e_minalloc;
        public ushort e_maxalloc;
        public ushort e_ss;
        public ushort e_sp;
        public ushort e_csum;
        public ushort e_ip;
        public ushort e_cs;
        public ushort e_lfarlc;
        public ushort e_ovno;
        public unsafe fixed ushort e_res[4];
        public ushort e_oemid;
        public ushort e_oeminfo;
        public unsafe fixed ushort e_res2[10];
        public int e_lfanew;
    }

    [type: StructLayout(LayoutKind.Sequential, Size = 20, Pack = 1)]
    internal struct ImageFileHeaderMap
    {
        public ushort Machine;
        public ushort NumberOfSections;
        public uint TimeDateStamp;
        public uint PointerToSymbolTable;
        public uint NumberOfSymbols;
        public ushort SizeOfOptionalHeader;
        public ushort Characteristics;
    }

    [type: StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct ImageOptionHeader32Map
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public uint BaseOfData;
        public uint ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public uint SizeOfStackReserve;
        public uint SizeOfStackCommit;
        public uint SizeOfHeapReserve;
        public uint SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        //Remove data directory.
    }

    [type: StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct ImageOptionHeader64Map
    {
        public ushort Magic;
        public byte MajorLinkerVersion;
        public byte MinorLinkerVersion;
        public uint SizeOfCode;
        public uint SizeOfInitializedData;
        public uint SizeOfUninitializedData;
        public uint AddressOfEntryPoint;
        public uint BaseOfCode;
        public ulong ImageBase;
        public uint SectionAlignment;
        public uint FileAlignment;
        public ushort MajorOperatingSystemVersion;
        public ushort MinorOperatingSystemVersion;
        public ushort MajorImageVersion;
        public ushort MinorImageVersion;
        public ushort MajorSubsystemVersion;
        public ushort MinorSubsystemVersion;
        public uint Win32VersionValue;
        public uint SizeOfImage;
        public uint SizeOfHeaders;
        public uint CheckSum;
        public ushort Subsystem;
        public ushort DllCharacteristics;
        public ulong SizeOfStackReserve;
        public ulong SizeOfStackCommit;
        public ulong SizeOfHeapReserve;
        public ulong SizeOfHeapCommit;
        public uint LoaderFlags;
        public uint NumberOfRvaAndSizes;
        //Remove data directory.
    }

    [type: StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct ImageDataDirectoryMap
    {
        public uint VirtualAddress;
        public uint Size;
    }

    [type: StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct ImageNtHeadersAny
    {
        public uint Signature;
        public ImageFileHeaderMap FileHeader;
    }

    [type: StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct ImageNtHeaders32
    {
        public uint Signature;
        public ImageFileHeaderMap FileHeader;
        public ImageOptionHeader32Map OptionalHeader;
    }

    [type: StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct ImageNtHeaders64
    {
        public uint Signature;
        public ImageFileHeaderMap FileHeader;
        public ImageOptionHeader64Map OptionalHeader;
    }

    [type: StructLayout(LayoutKind.Sequential, Pack = 1)]
    public struct IMAGE_SECTION_HEADER
    {
        public unsafe fixed byte Name[MagicValues.IMAGE_SIZEOF_SHORT_NAME];
        public IMAGE_SECTION_HEADER_UNION Misc;
        public uint VirtualAddress;
        public uint SizeOfRawData;
        public uint PointerToRawData;
        public uint PointerToRelocations;
        public uint PointerToLinenumbers;
        public ushort NumberOfRelocations;
        public ushort NumberOfLinenumbers;
        public uint Characteristics;
    }

    [type: StructLayout(LayoutKind.Explicit)]
    public struct IMAGE_SECTION_HEADER_UNION
    {
        [FieldOffset(0)]
        public uint PhysicalAddress;
        [FieldOffset(0)]
        public uint VirtualSize;
    }
}
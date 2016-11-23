using System;
namespace AuthenticodeLint.Core.PE
{
    internal static class MagicValues
    {
        public const ushort DOS_MAGIC = 0x5a4d;
        public const uint IMAGE_NT_SIGNATURE = 0x4550;
        public const ushort PE32_64 = 0x20b;
        public const ushort PE32_32 = 0x10b;
        public const int IMAGE_NUMBEROF_DIRECTORY_ENTRIES = 16;
        public const ushort IMAGE_FILE_MACHINE_I386 = 0x014c;
        public const ushort IMAGE_FILE_MACHINE_AMD64 = 0x8664;
    }
}
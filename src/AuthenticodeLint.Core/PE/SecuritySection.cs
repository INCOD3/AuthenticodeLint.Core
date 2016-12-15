using System.IO;

namespace AuthenticodeLint.Core.PE
{
    /// <summary>
    /// Reads a security section.
    /// </summary>
    public class SecuritySection
    {
        public uint WinCertificateLength { get; }
        public ushort WinCertificateRevision { get; }
        public ushort WinCertificateType { get; }
        public byte[] Data { get; }

        private SecuritySection(uint winCertificateLength, ushort winCertificateRevision, ushort winCertificateType, byte[] data)
        {
            WinCertificateLength = winCertificateLength;
            WinCertificateRevision = winCertificateRevision;
            WinCertificateType = winCertificateType;
            Data = data;
        }

        /// <summary>
        /// Reads the section from a file stream stream.
        /// </summary>
        /// <param name="stream">A stream of the file.</param>
        /// <param name="directory">A data directory of the contents. This should be the security directory.</param>
        /// <param name="section">If successful, will return the section's contents.</param>
        /// <returns>True if the security section was read, otherwise false.</returns>
        public static bool ReadSection(Stream stream, ImageDataDirectory directory, out SecuritySection section)
        {
            stream.Seek(directory.VirtualAddress, SeekOrigin.Begin);
            using (var reader = new BinaryReader(stream))
            {
                var winCertLength = reader.ReadUInt32();
                var winCertRevision = reader.ReadUInt16();
                var winCertType = reader.ReadUInt16();
                //We don't support v1 authenticode signatures. They are ancient and unlikely to appear in the wild.
                //They aren't documented, either.
                if (winCertRevision != 0x200 && winCertRevision != 0x100)
                {
                    section = null;
                    return false;
                }
                if (winCertType != 0x0002)
                {
                    section = null;
                    return false;
                }
                var data = new byte[winCertLength];
                reader.Read(data, 0, checked((int)winCertLength));
                section = new SecuritySection(winCertLength, winCertRevision, winCertType, data);
                return true;
            }
        }
    }
}
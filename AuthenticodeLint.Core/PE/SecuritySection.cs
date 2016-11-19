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

		public static bool ReadSection(Stream stream, ImageDataDirectory directory, out SecuritySection section)
		{
			stream.Seek(directory.VirtualAddress, SeekOrigin.Begin);
			using (var reader = new BinaryReader(stream))
			{
				var winCertLength = reader.ReadUInt32();
				var winCertRevision = reader.ReadUInt16();
				var winCertType = reader.ReadUInt16();
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
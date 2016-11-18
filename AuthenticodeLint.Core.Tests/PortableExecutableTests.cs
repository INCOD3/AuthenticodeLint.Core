using System;
using Xunit;
using AuthenticodeLint.Core.PE;
using System.Threading.Tasks;

namespace AuthenticodeLint.Core.Tests
{
	public class Tests
	{
		[Fact]
		public async Task ShouldReadSimpleAttributesOfPE()
		{
			using (var pe = new PortableExecutable("files/authlint.exe"))
			{
				var header = await pe.GetDosHeader();
				Assert.NotEqual(0, header.ExeFileHeaderAddress);

				var peHeader = await pe.GetPeHeader(header);
				Assert.Equal(MachineArchitecture.x86, peHeader.Architecture);
				Assert.Equal(16, peHeader.DataDirectories.Count);

				var securityHeader = peHeader.DataDirectories[ImageDataDirectoryEntry.IMAGE_DIRECTORY_ENTRY_SECURITY];
				Assert.NotEqual(0, securityHeader.Size);
				Assert.NotEqual(0, securityHeader.VirtualAddress);
			}
		}
	}
}

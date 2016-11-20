using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
	public class AsnDecoderTests
	{
		[Fact]
		public void ShouldDecodeSimpleInteger()
		{
			var data = new byte[]
			{
				0x02, //Integer tag
				0x02, //Has a content length of "2",
				0x00, //Big-endian zero so the number is positive since we care about sign
				0x86, //With a value of 134.
			};
			var decoded = AsnDecoder.Decode(data);
			Assert.IsType<AsnInteger>(decoded);
			var integer = (AsnInteger)decoded;
			Assert.Equal(0x86, integer.Value);
			Assert.Equal(0x00, integer.Data.Array[integer.Data.Offset]);
			Assert.Equal(0x86, integer.Data.Array[integer.Data.Offset+1]);
		}

		[Fact]
		public void ShouldDecodeMultiByteInteger()
		{
			var data = new byte[]
			{
				0x02, //Integer tag
				0x02, //Has a content length of "2",
				0x02, //Big-endian zero so the number is positive since we care about sign
				0x0E, //With a value of 134.
			};
			var decoded = AsnDecoder.Decode(data);
			Assert.IsType<AsnInteger>(decoded);
			var integer = (AsnInteger)decoded;
			Assert.Equal(526, integer.Value);
		}
	}
}
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
	public class AsnIntegerTests
	{
		[Fact]
		public void ShouldDecodeSimpleInteger()
		{
			var data = new byte[]
			{
				0x02, //Integer tag
				0x02, //Has a content length of "2",
				0x00, 0x86, //With a value of 134.
			};
			var decoded = AsnDecoder.Decode(data);
			var integer = Assert.IsType<AsnInteger>(decoded);
			Assert.Equal(0x86, integer.Value);
			Assert.Equal(0x00, integer.Data.Array[integer.Data.Offset]);
			Assert.Equal(0x86, integer.Data.Array[integer.Data.Offset + 1]);
		}

		[Fact]
		public void ShouldDecodeMultiByteInteger()
		{
			var data = new byte[]
			{
				0x02, //Integer tag
				0x02, //Has a content length of "2",
				0x02, 0x0E, //With a value of 134.
			};
			var decoded = AsnDecoder.Decode(data);
			var integer = Assert.IsType<AsnInteger>(decoded);
			Assert.Equal(526, integer.Value);
		}

		[Fact]
		public void ShouldDecodeSimpleIntegerWithNoSignOctet()
		{
			var data = new byte[]
			{
				0x02, //Integer tag
				0x01, //Has a content length of "1",
				0x2A, //With a value of 42.
			};
			var decoded = AsnDecoder.Decode(data);
			var integer = Assert.IsType<AsnInteger>(decoded);
			Assert.Equal(42, integer.Value);
		}

		[Fact]
		public void ShouldNotDecodeBeyondSpecifiedLength()
		{
			var data = new byte[]
			{
				0x02, //Integer tag
				0x01, //Has a content length of "1",
				0x2A, //With a value of 42.
				0x01,0x02, 0x03, 0x04, 0x05, 0x06 //Data beyond the specified encoded length.
			};
			var decoded = AsnDecoder.Decode(data);
			var integer = Assert.IsType<AsnInteger>(decoded);
			Assert.Equal(42, integer.Value);
			Assert.Equal(1, integer.Data.Count);
		}

		[
			Theory,
			InlineData(new byte[] { 0x02, 0x01, 0x2A }, new byte[] { 0x02, 0x01, 0x2A }, true),
			InlineData(new byte[] { 0x02, 0x01, 0x2A }, new byte[] { 0x02, 0x01, 0x2B }, false),
			InlineData(new byte[] { 0x02, 0x02, 0x02, 0x0E }, new byte[] { 0x02, 0x02, 0x02, 0x0E }, true),
			InlineData(new byte[] { 0x02, 0x02, 0x02, 0x0E }, new byte[] { 0x02, 0x02, 0x02, 0x0F }, false),
			InlineData(new byte[] { 0x02, 0x02, 0x02, 0x0E, 0x01 }, new byte[] { 0x02, 0x02, 0x02, 0x0E, 0x02 }, true),
		]
		public void EqualityTests(byte[] data1, byte[] data2, bool equal)
		{
			var decoded1 = AsnDecoder.Decode(data1);
			var integer1 = Assert.IsType<AsnInteger>(decoded1);

			var decoded2 = AsnDecoder.Decode(data2);
			var integer2 = Assert.IsType<AsnInteger>(decoded2);
			if (equal)
			{
				Assert.Equal(integer1, integer2);
			}
			else
			{
				Assert.NotEqual(integer1, integer2);
			}
		}
	}
}

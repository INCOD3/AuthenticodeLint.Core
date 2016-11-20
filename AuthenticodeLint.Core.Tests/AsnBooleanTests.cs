using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
	public class AsnBooleanTests
	{
		[
			Theory,
			InlineData(new byte[] { 0x01, 0x01, 0x00 }, false),
			InlineData(new byte[] { 0x01, 0x01, 0x01 }, true),
			InlineData(new byte[] { 0x01, 0x01, 0x80 }, true),
			InlineData(new byte[] { 0x01, 0x02, 0x80, 0x00 }, true),
			InlineData(new byte[] { 0x01, 0x02, 0x00, 0x80 }, true),
			InlineData(new byte[] { 0x01, 0x02, 0x00, 0x00 }, false),
		]
		public void ShouldDecodeAsnBooleanValues(byte[] data, bool expected)
		{
			var decoded = AsnDecoder.Decode(data);
			var asnBoolean = Assert.IsType<AsnBoolean>(decoded);
			Assert.Equal(expected, asnBoolean.Value);
		}

		[
			Theory,
			InlineData(new byte[] { 0x01, 0x01, 0x00 }, new byte[] { 0x01, 0x01, 0x00 }, true),
			InlineData(new byte[] { 0x01, 0x01, 0x01 }, new byte[] { 0x01, 0x01, 0x01 }, true),
			InlineData(new byte[] { 0x01, 0x01, 0x01 }, new byte[] { 0x01, 0x01, 0xFF }, true),
			InlineData(new byte[] { 0x01, 0x01, 0x00 }, new byte[] { 0x01, 0x01, 0xFF }, false),
		]
		public void EqualityTests(byte[] data1, byte[] data2, bool equal)
		{
			var decoded1 = AsnDecoder.Decode(data1);
			var decoded2 = AsnDecoder.Decode(data2);

			var asnBoolean1 = Assert.IsType<AsnBoolean>(decoded1);
			var asnBoolean2 = Assert.IsType<AsnBoolean>(decoded2);
			if (equal)
			{
				Assert.Equal(asnBoolean1, asnBoolean2);
			}
			else
			{
				Assert.NotEqual(asnBoolean1, asnBoolean2);
			}
		}
	}
}

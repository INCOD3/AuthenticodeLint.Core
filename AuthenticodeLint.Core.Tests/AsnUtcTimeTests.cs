using System;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
	public class AsnUtcTimeTests
	{
		[Fact]
		public void ShouldDecodeSimpleWithSecondsOrOffset()
		{
			var data = new byte[]
			{
				0x17, //UTCTime tag
				0xD, //with a length of 13
				0x31, 0x38, 0x30, 0x37, 0x33, 0x30,
					0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A //ASCII encoding for 180730235959Z
			};
			var decoded = AsnDecoder.Decode(data);
			var utcTime = Assert.IsType<AsnUtcTime>(decoded);
			var expected = new DateTimeOffset(2018, 07, 30, 23, 59, 59, TimeSpan.Zero);
			Assert.Equal(expected, utcTime.Value);
		}

		[Fact]
		public void ShouldDecodeSimpleWithNoSecondsOrOffset()
		{
			var data = new byte[]
			{
				0x17, //UTCTime tag
				0xB, //with a length of 11
				0x31, 0x38, 0x30, 0x37, 0x33, 0x30,
					0x32, 0x33, 0x35, 0x39, 0x5A //ASCII encoding for 1807302359Z
			};
			var decoded = AsnDecoder.Decode(data);
			var utcTime = Assert.IsType<AsnUtcTime>(decoded);
			var expected = new DateTimeOffset(2018, 07, 30, 23, 59, 00, TimeSpan.Zero);
			Assert.Equal(expected, utcTime.Value);
		}

		[Fact]
		public void ShouldDecodeSimpleWithSecondsAndPositiveOffset()
		{
			var data = new byte[]
			{
				0x17, //UTCTime tag
				0x11, //with a length of 17
				0x31, 0x38, 0x30, 0x37, 0x33, 0x30, 0x32, 0x33,
				0x35, 0x39, 0x35, 0x39, 0x2B, 0x30, 0x35, 0x31, 0x32 //ASCII encoding for 180730235959+0512
			};
			var decoded = AsnDecoder.Decode(data);
			var utcTime = Assert.IsType<AsnUtcTime>(decoded);
			var expected = new DateTimeOffset(2018, 07, 30, 23, 59, 59, new TimeSpan(05, 12, 0));
			Assert.Equal(expected, utcTime.Value);
		}


		[Fact]
		public void ShouldDecodeSimpleWithNoSecondsWithPositiveOffset()
		{
			var data = new byte[]
			{
				0x17, //UTCTime tag
				0x0F, //with a length of 15
				0x31, 0x38, 0x30, 0x37, 0x33, 0x30, 0x32, 0x33,
				0x35, 0x39, 0x2B, 0x30, 0x35, 0x31, 0x32 //ASCII encoding for 1807302359+0512
			};
			var decoded = AsnDecoder.Decode(data);
			var utcTime = Assert.IsType<AsnUtcTime>(decoded);
			var expected = new DateTimeOffset(2018, 07, 30, 23, 59, 00, new TimeSpan(05, 12, 0));
			Assert.Equal(expected, utcTime.Value);
		}

		[Fact]
		public void ShouldDecodeSimpleWithSecondsAndNegativeOffset()
		{
			var data = new byte[]
			{
				0x17, //UTCTime tag
				0x11, //with a length of 17
				0x31, 0x38, 0x30, 0x37, 0x33, 0x30, 0x32, 0x33,
				0x35, 0x39, 0x35, 0x39, 0x2D, 0x30, 0x35, 0x31, 0x32 //ASCII encoding for 180730235959-0512
			};
			var decoded = AsnDecoder.Decode(data);
			var utcTime = Assert.IsType<AsnUtcTime>(decoded);
			var expected = new DateTimeOffset(2018, 07, 30, 23, 59, 59, -new TimeSpan(05, 12, 0));
			Assert.Equal(expected, utcTime.Value);
		}


		[Fact]
		public void ShouldDecodeSimpleWithNoSecondsWithNegativeOffset()
		{
			var data = new byte[]
			{
				0x17, //UTCTime tag
				0x0F, //with a length of 15
				0x31, 0x38, 0x30, 0x37, 0x33, 0x30, 0x32, 0x33,
				0x35, 0x39, 0x2D, 0x30, 0x35, 0x31, 0x32 //ASCII encoding for 1807302359-0512
			};
			var decoded = AsnDecoder.Decode(data);
			var utcTime = Assert.IsType<AsnUtcTime>(decoded);
			var expected = new DateTimeOffset(2018, 07, 30, 23, 59, 00, -new TimeSpan(05, 12, 0));
			Assert.Equal(expected, utcTime.Value);
		}
	}
}

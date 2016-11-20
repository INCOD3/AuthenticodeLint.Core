using System;
using System.Linq;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
	public class AsnDecoderTests
	{
		[Fact]
		public void ShouldDecodeRawTagType()
		{
			var data = new byte[]
			{
				0x1F, //Unimplemented tag
				0x05, //Content length is "5",
				0x01, 0x02, 0x03, 0x04, 0x05
			};
			var decoded = AsnDecoder.Decode(data);
			var asnRaw = Assert.IsType<AsnRaw>(decoded);
			Assert.Equal((AsnTagType)31, asnRaw.Tag);
			var tagData = SerializeArraySegement(asnRaw.Data);
			Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, tagData);
		}

		[Fact]
		public void ShouldDecodeBitStringWithNoUnusedBits()
		{
			var data = new byte[]
			{
				0x03, //BitString tag
				0x02, //with a content length of 2,
				0x03, //With 3 unused bits,
				0x0A, //With a value of 0101
			};
			var decoded = AsnDecoder.Decode(data);
			var asnBitString = Assert.IsType<AsnBitString>(decoded);
			Assert.Equal(3, asnBitString.UnusedBits);
			Assert.Equal(10, asnBitString.Value.Array[asnBitString.Value.Offset]);
		}

		[Fact]
		public void ShouldDecodeOctetString()
		{
			var data = new byte[]
			{
				0x04, //OctetString tag
				0x05, //with a content length of 5
				0x01, 0x02, 0x03, 0x04, 0x05, //with content
			};
			var decoded = AsnDecoder.Decode(data);
			var octetString = Assert.IsType<AsnOctetString>(decoded);
			var tagData = SerializeArraySegement(octetString.Data);
			Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, tagData);
		}

		[Fact]
		public void ShouldDecodeOctetStringOver127Bytes()
		{

			var data = new byte[]
			{
				0x04, //OctetString tag
				0x81, 0x80, //with a content length of 128
			};
			var expected = Enumerable.Range(0, 128).Select(b => (byte)b).ToArray();
			data = data.Concat(expected).ToArray();
			Assert.Equal(131, data.Length);
			var decoded = AsnDecoder.Decode(data);
			var octetString = Assert.IsType<AsnOctetString>(decoded);
			Assert.Equal(128, octetString.Value.Count);
			Assert.Equal(expected, SerializeArraySegement(octetString.Value));
		}

		[Fact]
		public void ShouldDecodeIA5String()
		{
			var data = new byte[]
			{
				0x16, //IA5String tag
				0x05, //with a content length of 5
				0x68, 0x65, 0x6c, 0x6c, 0x6f //ascii "hello"
			};
			var decoded = AsnDecoder.Decode(data);
			var ia5String = Assert.IsType<AsnIA5String>(decoded);
			Assert.Equal("hello", ia5String.Value);
		}

		[Fact]
		public void ShouldDecodeSimpleSequence()
		{
			var data = new byte[]
			{
				0x30, //sequence tag
				0x06, //with a length of 6
				0x02, //first item in sequence is an integer
				0x01, //first item has a length of 1
				0x10, //first item has a value of 16
				0x02, //second item in sequence is an integer
				0x01, //second item has a length of 1
				0x20, //second item has a value of 32
			};
			var decoded = AsnDecoder.Decode(data);
			var sequence = Assert.IsType<AsnSequence>(decoded);
			var elements = sequence.Elements().ToArray();
			Assert.Equal(2, elements.Length);
			Assert.All(elements, (obj) => Assert.IsType<AsnInteger>(obj));
			var integerOne = (AsnInteger)elements[0];
			var integerTwo = (AsnInteger)elements[1];
			Assert.Equal(16, integerOne.Value);
			Assert.Equal(32, integerTwo.Value);
		}

		private static T[] SerializeArraySegement<T>(ArraySegment<T> segement)
		{
			var arr = new T[segement.Count];
			for (var i = 0; i < segement.Count; i++)
			{
				arr[i] = segement.Array[segement.Offset + i];
			}
			return arr;
		}
	}
}
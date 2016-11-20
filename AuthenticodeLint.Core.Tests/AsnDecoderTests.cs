using System;
using System.Linq;
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
				0x00, 0x86, //With a value of 134.
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
				0x02, 0x0E, //With a value of 134.
			};
			var decoded = AsnDecoder.Decode(data);
			Assert.IsType<AsnInteger>(decoded);
			var integer = (AsnInteger)decoded;
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
			Assert.IsType<AsnInteger>(decoded);
			var integer = (AsnInteger)decoded;
			Assert.Equal(42, integer.Value);
		}

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
			Assert.IsType<AsnRaw>(decoded);
			var asnRaw = (AsnRaw)decoded;
			Assert.Equal((AsnTagType)31, asnRaw.TagType);
			var tagData = SerializeArraySegement(asnRaw.Data);
			Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, tagData);
		}

		[
			Theory,
			InlineData(new byte[] { 0x01, 0x01, 0x00 }, false),
			InlineData(new byte[] { 0x01, 0x01, 0x01 }, true),
			InlineData(new byte[] { 0x01, 0x01, 0x80 }, true),
			InlineData(new byte[] { 0x01, 0x02, 0x80, 0x00 }, true),
			InlineData(new byte[] { 0x01, 0x02, 0x00, 0x80 }, true),
		]
		public void ShouldDecodeAsnBooleanValues(byte[] data, bool expected)
		{
			var decoded = AsnDecoder.Decode(data);
			Assert.IsType<AsnBoolean>(decoded);
			var asnBoolean = (AsnBoolean)decoded;
			Assert.Equal(expected, asnBoolean.Value);
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
			Assert.IsType<AsnBitString>(decoded);
			var asnBitString = (AsnBitString)decoded;
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
			Assert.IsType<AsnOctetString>(decoded);
			var octetString = (AsnOctetString)decoded;
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
			Assert.IsType<AsnOctetString>(decoded);
			var octetString = (AsnOctetString)decoded;
			Assert.Equal(128, octetString.Value.Count);
			Assert.Equal(expected, SerializeArraySegement(octetString.Value));
		}

		[Fact]
		public void ShouldDecodeObjectIdentifier()
		{
			var data = new byte[]
			{
				0x06, //ObjectIdentifier tag
				0x08, //with a content lengh of 8
				42, 134, 72, 206, 61, 3, 1, 7 //oid
			};
			var decoded = AsnDecoder.Decode(data);
			Assert.IsType<AsnObjectIdentifier>(decoded);
			var objectIdentifier = (AsnObjectIdentifier)decoded;
			Assert.Equal("1.2.840.10045.3.1.7", objectIdentifier.Value);
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
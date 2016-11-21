using System;
using System.Linq;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
	public class AsnSequenceTests
	{
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

		[Fact]
		public void ShouldThrowWhenSequenceChildDataIsGreaterThanSequenceData()
		{
			var data = new byte[]
			{
				0x30, //sequence tag
				0x05, //with a length of 5. This actual data is 6 octets though, so it bleeds outside the sequence.
				0x02, //first item in sequence is an integer
				0x01, //first item has a length of 1
				0x10, //first item has a value of 16
				0x02, //second item in sequence is an integer
				0x01, //second item has a length of 1
				0x20, //second item has a value of 32
			};
			var decoded = AsnDecoder.Decode(data);
			var sequence = Assert.IsType<AsnSequence>(decoded);
			Assert.Throws<InvalidOperationException>(() => sequence.Elements().ToArray());
		}

		[Fact]
		public void ShouldDecodeNestedSequence()
		{
			var data = new byte[]
			{
				0x30, //sequence tag
				0x05, //with a length of 5
				0x30, //nested sequence tag
				0x03, //nested sequence has a length of 3
				0x02, //nested sequence contains an integer
				0x01, //with a length of 1,
				0x40, //with a value of 64
			};
			var decoded = AsnDecoder.Decode(data);
			var sequence = Assert.IsType<AsnSequence>(decoded);
			var sequenceItems = sequence.Elements().ToArray();
			Assert.Equal(1, sequenceItems.Length);
			var childElement = sequenceItems[0];
			var childSequence = Assert.IsType<AsnSequence>(childElement);
			var childItems = childSequence.Elements().ToArray();
			var childInteger = Assert.IsType<AsnInteger>(childItems[0]);
			Assert.Equal(64, childInteger.Value);
		}

		[Fact]
		public void ShouldDecodeSequenceOfWithNoItems()
		{
			var data = new byte[]
			{
				0x30, //sequence tag
				0x00, //no items
			};
			var decoded = AsnDecoder.Decode(data);
			var sequence = Assert.IsType<AsnSequence>(decoded);
			Assert.Equal(0, sequence.Elements().Count());
		}
	}
}

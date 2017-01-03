using System;
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
            Assert.Equal(2, sequence.Count);
            Assert.All(sequence, (obj) => Assert.IsType<AsnInteger>(obj));
            var integerOne = (AsnInteger)sequence[0];
            var integerTwo = (AsnInteger)sequence[1];
            Assert.Equal(16, integerOne.Value);
            Assert.Equal(32, integerTwo.Value);
            Assert.Equal(data, SerializeArraySegement(sequence.ElementData));
        }

        [Fact]
        public void ShouldDecodeSimpleSequenceWithUnknownLengthBERStyle()
        {
            var data = new byte[]
            {
                0x30, //sequence tag
                0x80, //with an unspecified length
                0x02, //first item in sequence is an integer
                0x01, //first item has a length of 1
                0x10, //first item has a value of 16
                0x02, //second item in sequence is an integer
                0x01, //second item has a length of 1
                0x20, //second item has a value of 32
                0x00, 0x00 //terminator
            };
            var decoded = AsnDecoder.Decode(data);
            var sequence = Assert.IsType<AsnSequence>(decoded);
            Assert.Equal(2, sequence.Count);
            Assert.All(sequence, (obj) => Assert.IsType<AsnInteger>(obj));
            var integerOne = (AsnInteger)sequence[0];
            var integerTwo = (AsnInteger)sequence[1];
            Assert.Equal(16, integerOne.Value);
            Assert.Equal(32, integerTwo.Value);
            Assert.Equal(data, SerializeArraySegement(sequence.ElementData));
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
            var decoded = Assert.Throws<AsnException>(() => AsnDecoder.Decode(data));
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
            Assert.Equal(1, sequence.Count);
            var childElement = sequence[0];
            var childSequence = Assert.IsType<AsnSequence>(childElement);
            var childInteger = Assert.IsType<AsnInteger>(childSequence[0]);
            Assert.Equal(64, childInteger.Value);
        }

        [Fact]
        public void ShouldDecodeNestedSequenceWithUnknownLengthBERStyle()
        {
            var data = new byte[]
            {
                0x30, //sequence tag
                0x80, //with an unspecified length
                0x30, //nested sequence tag
                0x80, //nested sequence has an unspecified length
                0x02, //nested sequence contains an integer
                0x01, //with a length of 1,
                0x40, //with a value of 64
                0x00, 0x00, //inner sequence terminator
                0x00, 0x00 //outer sequence terminator
            };
            var decoded = AsnDecoder.Decode(data);
            var sequence = Assert.IsType<AsnSequence>(decoded);
            Assert.Equal(1, sequence.Count);
            var childElement = sequence[0];
            var childSequence = Assert.IsType<AsnSequence>(childElement);
            var childInteger = Assert.IsType<AsnInteger>(childSequence[0]);
            Assert.Equal(64, childInteger.Value);
        }

        [Fact]
        public void ShouldDecodeDataCorrectlyAfterTerminatorWithNestingBER()
        {
            var data = new byte[]
            {
                0x30, //sequence tag
                0x80, //with an unspecified length
                0x30, //nested sequence tag
                0x80, //nested sequence has an unspecified length
                0x02, //nested sequence contains an integer
                0x01, //with a length of 1,
                0x40, //with a value of 64
                0x00, 0x00, //inner sequence terminator
                0x02, //nested integer tag
                0x01, //with a length of one
                0x20, //with a value of 32
                0x00, 0x00 //outer sequence terminator
            };
            var decoded = AsnDecoder.Decode(data);
            var sequence = Assert.IsType<AsnSequence>(decoded);
            Assert.Equal(2, sequence.Count);
            var childElement = sequence[0];
            var childSequence = Assert.IsType<AsnSequence>(childElement);
            var childInteger = Assert.IsType<AsnInteger>(childSequence[0]);
            Assert.Equal(64, childInteger.Value);
            Assert.Equal(32, Assert.IsType<AsnInteger>(sequence[1]).Value);
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
            Assert.Equal(0, sequence.Count);
        }

        [Fact]
        public void ShouldSupportRealConversionFromConstructed()
        {
            var data = new byte[]
            {
                0xA0, //constructed, application specific,
                0x04, //with a length of four
                0x02, //asn.1 integer
                0x02, //with a length of 2
                0x00, 0xFF, //with a value of 255.
            };
            var decoded = AsnDecoder.Decode(data);
            Assert.IsNotType<AsnSequence>(decoded);
            var constructed = Assert.IsType<AsnConstructed>(decoded);
            var sequence = constructed.Reinterpret<AsnSequence>();
            Assert.Equal(0x30, sequence.ElementData.Array[sequence.ElementData.Offset]);
            Assert.Equal(1, sequence.Count);
            Assert.Equal(255, Assert.IsType<AsnInteger>(sequence[0]).Value);
            Assert.Equal(data.Length, sequence.ElementData.Count);
            Assert.Equal(4, sequence.ContentData.Count);
        }

        [Fact]
        public void ShouldSupportRealConversionFromConstructedWithLongLength()
        {
            var data = new byte[]
            {
                0xA0, //constructed, application specific,
                0x81, 0x80, //with a length of 128
                0x02, //asn.1 integer
                0x7E, //with a length of 126
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x7F,
            };
            var decoded = AsnDecoder.Decode(data);
            Assert.IsNotType<AsnSequence>(decoded);
            var constructed = Assert.IsType<AsnConstructed>(decoded);
            var sequence = constructed.Reinterpret<AsnSequence>();
            Assert.Equal(127, Assert.IsType<AsnInteger>(sequence[0]).Value);
            Assert.Equal(130, sequence.ElementData.Count);
            Assert.Equal(128, sequence.ContentData.Count);
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

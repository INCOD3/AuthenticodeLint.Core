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
                0x7F,
                0x05, //Content length is "5",
                0x01, 0x02, 0x03, 0x04, 0x05, 0x6, 0x7
            };
            var decoded = AsnDecoder.Decode(data);
            var asnRaw = Assert.IsType<AsnRaw>(decoded);
            Assert.Equal((AsnTagValue)127, asnRaw.Tag.Tag);
            var tagData = SerializeArraySegement(asnRaw.ContentData);
            Assert.Equal(new byte[] { 1, 2, 3, 4, 5 }, tagData);
            Assert.Equal(new byte[] { 0x1F, 0x7F, 0x5, 1, 2, 3, 4, 5 }, SerializeArraySegement(asnRaw.ElementData));
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
            var tagData = SerializeArraySegement(octetString.ContentData);
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
        public void ShouldDecodeLongFormTag()
        {
            var data = new byte[]
            {
                0xDF, 0xFF, 0x01, 0x00
            };
            var decoded = AsnDecoder.Decode(data);
            Assert.Equal(16257UL, (ulong)decoded.Tag.Tag);
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
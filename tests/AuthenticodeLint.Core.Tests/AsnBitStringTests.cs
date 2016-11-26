using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class AsnBitStringTests
    {
        [Fact]
        public void ShouldDecodeBitStringWithNoUnusedBits()
        {
            var data = new byte[]
            {
                0x03, //BitString tag
                0x02, //with a content length of 2,
                0x00, //With 0 unused bits,
                0x0A, //With a value of 00001010
            };
            var decoded = AsnDecoder.Decode(data);
            var asnBitString = Assert.IsType<AsnBitString>(decoded);
            Assert.Equal(0, asnBitString.UnusedBits);
            Assert.Equal(10, asnBitString.Value.Array[asnBitString.Value.Offset]);
            Assert.Equal("00001010", asnBitString.ToString());
        }

        [
            Theory,
            InlineData(new byte[] { 0x03, 0x03, 0x01, 0x00, 0xFF }, "000000001111111"),
            InlineData(new byte[] { 0x03, 0x03, 0x07, 0x00, 0xFF }, "000000001"),
            InlineData(new byte[] { 0x03, 0x03, 0x01, 0x00, 0x00 }, "000000000000000"),
            InlineData(new byte[] { 0x03, 0x03, 0x00, 0x00, 0x00 }, "0000000000000000"),
        ]
        public void ShouldConvertToStringWithUnusedBits(byte[] data, string expected)
        {
            var decoded = AsnDecoder.Decode(data);
            var bitString = Assert.IsType<AsnBitString>(decoded);
            Assert.Equal(expected, bitString.ToString());
        }
    }
}

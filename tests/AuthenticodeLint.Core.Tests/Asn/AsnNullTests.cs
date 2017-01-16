using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class AsnNullTests
    {
        [Fact]
        public void ShouldDecodeNull()
        {
            var data = new byte[]
            {
                0x05, //null tag
                0x00, //with a length of zero
            };
            var decoded = AsnDecoder.Decode(data);
            Assert.IsType<AsnNull>(decoded);
        }

        [Fact]
        public void ShouldThrowExceptionIfNullHasLength()
        {
            var data = new byte[]
            {
                0x05, //null tag
                0x01, //with a length of 1
                0xFF, //with 255 for data
            };
            Assert.Throws<AsnException>(() => AsnDecoder.Decode(data));
        }

        [
            Theory,
            InlineData(new byte[] { 0x05, 0x00 }, new byte[] { 0x05, 0x00 }, true),
            InlineData(new byte[] { 0x05, 0x00, 0x01 }, new byte[] { 0x05, 0x00, 0x02 }, true),
        ]
        public void EqualityTests(byte[] data1, byte[] data2, bool equal)
        {
            var decoded1 = AsnDecoder.Decode(data1);
            var null1 = Assert.IsType<AsnNull>(decoded1);

            var decoded2 = AsnDecoder.Decode(data2);
            var null2 = Assert.IsType<AsnNull>(decoded2);
            if (equal)
            {
                Assert.Equal(null1, null2);
            }
            else
            {
                Assert.NotEqual(null1, null2);
            }
        }
    }
}

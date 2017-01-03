using System.Text;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class AsnIA5StringTests
    {
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
        public void ShouldNotDecodeBeyondSpecifiedTagLength()
        {
            var data = new byte[]
            {
                0x16, //IA5String tag
                0x05, //with a content length of 5
                0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x6f, 0x6f, 0x6f, 0x6f //ascii "helloooo"
            };
            var decoded = AsnDecoder.Decode(data);
            var ia5String = Assert.IsType<AsnIA5String>(decoded);
            Assert.Equal("hello", ia5String.Value);
        }

        [Fact]
        public void ShouldThrowAsnExceptionWithBadData()
        {
            var data = new byte[]
            {
                0x16, //IA5String tag
                0x05, //with a content length of 5
                0xFF, 0xFF, 0xFF, 0xFF, 0xFF
            };
            var exception = Assert.Throws<AsnException>(() => AsnDecoder.Decode(data));
            Assert.IsType<DecoderFallbackException>(exception.InnerException);
        }
    }
}
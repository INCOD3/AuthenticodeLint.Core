using System.Text;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class AsnBmpStringTests
    {
        [Fact]
        public void ShouldDecodeSimpleString()
        {
            var data = new byte[] {
                0x1E, //asn.1 bmp string tag,
                0x0A, //with a length of 10
                0x00, 0x68, 0x00, 0x65, 0x00, 0x6C, 0x00, 0x6C, 0x00, 0x6F //big endian "hello"
            };
            var decoded = AsnDecoder.Decode(data);
            var bmpString = Assert.IsType<AsnBmpString>(decoded);
            Assert.Equal("hello", bmpString.Value);
        }

        [Fact]
        public void ShouldThrowExceptionWithInvalidUnicodeSequence()
        {
            var data = new byte[] {
                0x1E, //asn.1 bmp string
                0x02, //with a length of two
                0xD8, 0x00 //bad surrogate
            };
            var exception = Assert.Throws<AsnException>(() => AsnDecoder.Decode(data));
            Assert.IsType<DecoderFallbackException>(exception.InnerException);
        }
    }
}
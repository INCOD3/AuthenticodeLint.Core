using System.Text;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class AsnVisibleStringTests
    {
        [Fact]
        public void ShouldDecodeSimpleVisibleString()
        {
            var data = new byte[]
            {
                0x1A, //VisibleString tag
                0x05, //with a length of 5
                0x68, 0x65, 0x6c, 0x6C, 0x6F //with a value of "hello"
            };
            var decoded = Assert.IsType<AsnVisibleString>(AsnDecoder.Decode(data));
            Assert.Equal("hello", decoded.Value);
        }

        [Fact]
        public void ShouldNotDecodeBeyondSpecifiedLength()
        {
            var data = new byte[]
            {
                0x1A, //VisibleString tag
                0x05, //with a length of 5
                0x68, 0x65, 0x6c, 0x6C, 0x6F, 0x6F, 0xFF //with a value of "hello"
            };
            var decoded = Assert.IsType<AsnVisibleString>(AsnDecoder.Decode(data));
            Assert.Equal("hello", decoded.Value);
        }


        [Fact]
        public void ShouldThrowAsnExceptionWhenStringIsInvalid()
        {
            var data = new byte[]
            {
                0x1A, //VisibleString tag
                0x05, //with a length of 5
                0x68, 0x65, 0x6c, 0x6F, 0xFF //with a value of "helo?"
            };
            var exception = Assert.Throws<AsnException>(() => AsnDecoder.Decode(data));
            Assert.IsType<DecoderFallbackException>(exception);
        }

        [Fact]
        public void ShouldThrowExceptionOnUndefinedLengths()
        {

            var data = new byte[]
            {
                0x1A, //VisibleString tag
                0x80, //with an undefined length
                0x68, 0x65, 0x6c, 0x6C, 0x6F, //with a value of "hello"
                0x00, 0x00 //terminator
            };
            Assert.Throws<AsnException>(() => AsnDecoder.Decode(data));
        }
    }
}
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class AsnNumericStringTests
    {
        [Fact]
        public void ShouldParseSimpleNumericString()
        {
            var data = new byte[] {
                0x12, //NumericString tag,
                0x05, //with a length of 5
                0x31, 0x32, 0x30, 0x37, 0x34, //12074
            };

            var element = AsnDecoder.Decode(data);
            var numericString = Assert.IsType<AsnNumericString>(element);
            Assert.Equal("12074", numericString.Value);
        }

        [Fact]
        public void ShouldNotReadDataBeyondSpecifiedLength()
        {
            var data = new byte[] {
                0x12, //NumericString tag,
                0x05, //with a length of 5
                0x31, 0x32, 0x30, 0x37, 0x34, 0x35 //120745
            };

            var element = AsnDecoder.Decode(data);
            var numericString = Assert.IsType<AsnNumericString>(element);
            Assert.Equal("12074", numericString.Value);
        }

        [Fact]
        public void ShouldAllowSpaces()
        {
            var data = new byte[] {
                0x12, //NumericString tag,
                0x0A, //with a length of 10
                0x31, 0x20, 0x32, 0x20, 0x30, 0x20, 0x37, 0x20, 0x34, 0x20 //1 2 0 7 4 
            };

            var element = AsnDecoder.Decode(data);
            var numericString = Assert.IsType<AsnNumericString>(element);
            Assert.Equal("1 2 0 7 4 ", numericString.Value);
        }

        [Fact]
        public void ShouldThrowExceptionOnInvalidCharacters()
        {
            var data = new byte[] {
                0x12, //NumericString tag,
                0x02, //with a length of 2
                0x31, 0x65, //1A
            };
            Assert.Throws<AsnException>(() => AsnDecoder.Decode(data));
        }
    }
}
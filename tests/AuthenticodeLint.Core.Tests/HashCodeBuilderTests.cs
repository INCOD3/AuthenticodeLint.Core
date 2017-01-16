using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class HashCodeBuilderTests
    {
        [Fact]
        public void ShouldShiftAByteAtATime()
        {
            var builder = new HashCodeBuilder();
            builder.Push((byte)0xFF);
            builder.Push((byte)0xFE);
            builder.Push((byte)0xFD);
            builder.Push((byte)0xFC);
            Assert.Equal(unchecked((int)0xFCFDFEFF), builder.GetHashCode());
        }


        [Fact]
        public void ShouldWrapAround()
        {
            var builder = new HashCodeBuilder();
            builder.Push((byte)0x0F);
            builder.Push((byte)0);
            builder.Push((byte)0);
            builder.Push((byte)0);
            builder.Push((byte)0xF8);
            Assert.Equal(unchecked((int)0xF7), builder.GetHashCode());
        }
    }
}
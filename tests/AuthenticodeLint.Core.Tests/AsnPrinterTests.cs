using System.IO;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class AsnPrinterTests
    {
        [Fact]
        public void ShouldSupportSequences()
        {
            var seq = new byte[] { 0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x04 };
            var decoded = AsnDecoder.Decode(seq);
            var writer = new StringWriter();
            AsnPrinter.Print(writer, decoded);
            Assert.Equal(@"SequenceSequenceOf:
  Integer: 1
  Integer: 4
", writer.ToString());
        }

        [Fact]
        public void ShouldPrintSimpleThings()
        {
            var seq = new byte[] { 0x02, 0x01, 0x01 };
            var decoded = AsnDecoder.Decode(seq);
            var writer = new StringWriter();
            AsnPrinter.Print(writer, decoded);
            Assert.Equal("Integer: 1\n", writer.ToString());
        }
    }
}

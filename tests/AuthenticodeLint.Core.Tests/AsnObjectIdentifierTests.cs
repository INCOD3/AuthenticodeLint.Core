using System;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class AsnObjectIdentifierTests
    {
        [Fact]
        public static void ShouldDecodeObjectIdentifier()
        {
            var data = new byte[]
            {
                0x06, //ObjectIdentifier tag
                0x08, //with a content lengh of 8
                42, 134, 72, 206, 61, 3, 1, 7 //oid
            };
            var decoded = AsnDecoder.Decode(data);
            var objectIdentifier = Assert.IsType<AsnObjectIdentifier>(decoded);
            Assert.Equal("1.2.840.10045.3.1.7", objectIdentifier.Value);
            Assert.Equal("1.2.840.10045.3.1.7", objectIdentifier.ToString());
        }

        [Fact]
        public void ShouldThrowOnIncorrectedTerminatedVlq()
        {
            var data = new byte[]
            {
                0x06, //ObjectIdentifier tag
                0x08, //with a content length of 8
                0x2a, 0x86, 0x48, 0xce, 0x3d, 0x3, 0x1,
                    0xff //final octet has MSB set, but no data to process afterward.
            };
            Assert.Throws<AsnException>(() => AsnDecoder.Decode(data));
        }

        [
            Theory,
            InlineData(new byte[] { 0x06, 0x02, 0x2A, 0x01 }, new byte[] { 0x06, 0x02, 0x2A, 0x01 }, true),
            InlineData(new byte[] { 0x06, 0x02, 0x2A, 0x01, 0x00 }, new byte[] { 0x06, 0x02, 0x2A, 0x01, 0xFF }, true),
            InlineData(new byte[] { 0x06, 0x02, 0x2A, 0x01, 0x00 }, new byte[] { 0x06, 0x02, 0x2A, 0x02, 0xFF }, false),
        ]
        public void EqualityTests(byte[] data1, byte[] data2, bool equal)
        {
            var decoded1 = AsnDecoder.Decode(data1);
            var oid1 = Assert.IsType<AsnObjectIdentifier>(decoded1);

            var decoded2 = AsnDecoder.Decode(data2);
            var oid2 = Assert.IsType<AsnObjectIdentifier>(decoded2);
            if (equal)
            {
                Assert.Equal(oid1, oid2);
            }
            else
            {
                Assert.NotEqual(oid1, oid2);
            }
        }
    }
}

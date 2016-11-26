using System;
using AuthenticodeLint.Core.Asn;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class AsnGeneralizedTimeTests
    {
        [Fact]
        public void ShouldDecodeSimpleLocalWithHours()
        {
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x0A, //with a length of 10
                0x32, 0x30, 0x38, 0x30, 0x31, //ASCII for 2080121023
                    0x32, 0x31, 0x30, 0x32, 0x33
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTime(2080, 12, 10, 23, 00, 00, DateTimeKind.Local);
            Assert.Equal(expectedDateTime, generalizedTime.Value.LocalDateTime);
            Assert.Equal(expectedDateTime, generalizedTime.Value.DateTime);
        }

        [Fact]
        public void ShouldDecodeSimpleLocalWithHoursAndMinutes()
        {
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x0C, //with a length of 12
                0x32, 0x30, 0x38, 0x30, 0x31, //ASCII for 208012102345
                    0x32, 0x31, 0x30, 0x32, 0x33, 0x34, 0x35
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTime(2080, 12, 10, 23, 45, 00, DateTimeKind.Local);
            Assert.Equal(expectedDateTime, generalizedTime.Value.LocalDateTime);
            Assert.Equal(expectedDateTime, generalizedTime.Value.DateTime);
        }

        [Fact]
        public void ShouldDecodeSimpleLocalWithHoursAndMinutesAndSeconds()
        {
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x0E, //with a length of 14
                0x32, 0x30, 0x38, 0x30, 0x31, //ASCII for 20801210234557
                    0x32, 0x31, 0x30, 0x32, 0x33, 0x34, 0x35, 0x35, 0x37
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTime(2080, 12, 10, 23, 45, 57, DateTimeKind.Local);
            Assert.Equal(expectedDateTime, generalizedTime.Value.LocalDateTime);
            Assert.Equal(expectedDateTime, generalizedTime.Value.DateTime);
        }

        [Fact]
        public void ShouldDecodeSimpleLocalWithHoursAndMinutesAndSecondsAndFractionalSeconds()
        {
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x12, //with a length of 18
                0x32, 0x30, 0x38, 0x30, 0x31, 0x32, 0x31, //20801210234557.999
                    0x30, 0x32, 0x33, 0x34, 0x35, 0x35, 0x37,
                    0x2e, 0x39, 0x39, 0x39
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTime(2080, 12, 10, 23, 45, 57, DateTimeKind.Local).AddMilliseconds(999);
            Assert.Equal(expectedDateTime, generalizedTime.Value.LocalDateTime);
            Assert.Equal(expectedDateTime, generalizedTime.Value.DateTime);
        }

        [Fact]
        public void ShouldDecodeSimpleUtcWithHours()
        {
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x0B, //with a length of 11
                0x32, 0x30, 0x38, 0x30, 0x31, //ASCII for 2080121023Z
                    0x32, 0x31, 0x30, 0x32, 0x33, 0x5A
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTimeOffset(2080, 12, 10, 23, 00, 00, TimeSpan.Zero);
            Assert.Equal(expectedDateTime, generalizedTime.Value);
        }


        [Fact]
        public void ShouldDecodeSimpleUtcWithHoursAndMinutes()
        {
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x0D, //with a length of 13
                0x32, 0x30, 0x38, 0x30, 0x31, //ASCII for 208012102345Z
                    0x32, 0x31, 0x30, 0x32, 0x33, 0x34, 0x35, 0x5A
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTimeOffset(2080, 12, 10, 23, 45, 00, TimeSpan.Zero);
            Assert.Equal(expectedDateTime, generalizedTime.Value);
        }


        [Fact]
        public void ShouldDecodeSimpleUtcWithHoursAndMinutesAndSeconds()
        {
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x0F, //with a length of 15
                0x32, 0x30, 0x38, 0x30, 0x31, //ASCII for 20801210234557Z
                    0x32, 0x31, 0x30, 0x32, 0x33, 0x34, 0x35, 0x35, 0x37, 0x5A
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTimeOffset(2080, 12, 10, 23, 45, 57, TimeSpan.Zero);
            Assert.Equal(expectedDateTime, generalizedTime.Value);
        }

        [Fact]
        public void ShouldDecodeSimpleUtcWithHoursAndMinutesAndSecondsAndFractionalSeconds()
        {
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x13, //with a length of 19
                0x32, 0x30, 0x38, 0x30, 0x31, 0x32, 0x31, //20801210234557.999Z
                    0x30, 0x32, 0x33, 0x34, 0x35, 0x35, 0x37,
                    0x2e, 0x39, 0x39, 0x39, 0x5A
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTimeOffset(2080, 12, 10, 23, 45, 57, TimeSpan.Zero).AddMilliseconds(999);
            Assert.Equal(expectedDateTime, generalizedTime.Value);
        }

        [Fact]
        public void ShouldDecodeSimpleOffsetWithHours()
        {
            //2014031106-0545
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x0F, //with a length of 15
                0x32, 0x30, 0x31, 0x34, 0x30, 0x33, 0x31,
                0x31, 0x30, 0x36, 0x2d, 0x30, 0x35, 0x34, 0x35
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTimeOffset(2014, 03, 11, 06, 00, 00, -new TimeSpan(5, 45, 0));
            Assert.Equal(expectedDateTime, generalizedTime.Value);
        }

        [Fact]
        public void ShouldDecodeSimpleOffsetWithHoursAndMinutes()
        {
            //201403110637-0545
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x11, //with a length of 17
                0x32, 0x30, 0x31, 0x34, 0x30, 0x33, 0x31,
                0x31, 0x30, 0x36, 0x33, 0x37, 0x2d, 0x30, 0x35, 0x34, 0x35
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTimeOffset(2014, 03, 11, 06, 37, 00, -new TimeSpan(5, 45, 0));
            Assert.Equal(expectedDateTime, generalizedTime.Value);
        }

        [Fact]
        public void ShouldDecodeSimpleOffsetWithHoursAndMinutesAndSeconds()
        {
            //20140311063701-0545
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x13, //with a length of 19
                0x32, 0x30, 0x31, 0x34, 0x30, 0x33, 0x31,
                0x31, 0x30, 0x36, 0x33, 0x37, 0x30, 0x31,
                0x2d, 0x30, 0x35, 0x34, 0x35
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTimeOffset(2014, 03, 11, 06, 37, 01, -new TimeSpan(5, 45, 0));
            Assert.Equal(expectedDateTime, generalizedTime.Value);
        }

        [Fact]
        public void ShouldDecodeSimpleOffsetWithHoursAndMinutesAndSecondsAndFractionalSeconds()
        {
            //20140311063701.999-0545
            var data = new byte[]
            {
                0x18, //GeneralizedTime tag
                0x17, //with a length of 23
                0x32, 0x30, 0x31, 0x34, 0x30, 0x33, 0x31,
                0x31, 0x30, 0x36, 0x33, 0x37, 0x30, 0x31,
                0x2e, 0x39, 0x39, 0x39,
                0x2d, 0x30, 0x35, 0x34, 0x35
            };
            var decoded = AsnDecoder.Decode(data);
            var generalizedTime = Assert.IsType<AsnGeneralizedTime>(decoded);
            var expectedDateTime = new DateTimeOffset(2014, 03, 11, 06, 37, 01, -new TimeSpan(5, 45, 0)).AddMilliseconds(999);
            Assert.Equal(expectedDateTime, generalizedTime.Value);
        }
    }
}

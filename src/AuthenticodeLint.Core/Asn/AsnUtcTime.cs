using System;
using System.Globalization;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    public class AsnUtcTime : AsnElement, IAsnDateTime
    {
        private static readonly CultureInfo _parsingCulture;

        static AsnUtcTime()
        {
            _parsingCulture = (CultureInfo)CultureInfo.InvariantCulture.Clone();
            _parsingCulture.DateTimeFormat.Calendar = new UTCTimeCalendar();
        }

        public DateTimeOffset Value { get; }

        public AsnUtcTime(AsnTag tag, ArraySegment<byte> contentData) : base(tag, contentData)
        {
            var strData = Encoding.ASCII.GetString(contentData.Array, contentData.Offset, contentData.Count);
            var formats = new string[] {
                "yyMMddHHmmsszzz",
                "yyMMddHHmmzzz",
                "yyMMddHHmmZ",
                "yyMMddHHmmssZ",
            };
            DateTimeOffset val;
            if (!DateTimeOffset.TryParseExact(strData, formats, _parsingCulture, DateTimeStyles.AssumeUniversal, out val))
            {
                throw new AsnException("Encoded UTCDate is not valid.");
            }
            Value = val;
        }

        public override string ToString() => Value.ToString();

        private class UTCTimeCalendar : GregorianCalendar
        {
            public override int ToFourDigitYear(int year) => (year < 50 ? 2000 : 1900) + year;
        }
    }
}
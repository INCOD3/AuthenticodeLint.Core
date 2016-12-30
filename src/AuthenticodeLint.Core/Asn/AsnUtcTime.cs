using System;
using System.Globalization;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    public class AsnUtcTime : AsnElement, IAsnDateTime
    {
        private static readonly CultureInfo _parsingCulture;
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        static AsnUtcTime()
        {
            _parsingCulture = (CultureInfo)CultureInfo.InvariantCulture.Clone();
            _parsingCulture.DateTimeFormat.Calendar = new UTCTimeCalendar();
        }

        public DateTimeOffset Value { get; }

        public AsnUtcTime(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength)
            : base(tag)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of UTCTime are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for UTCTime are not supported.");
            }
            string strData;
            try
            {
                ElementData = elementData.ConstrainWith(contentData, contentLength.Value);
                ContentData = contentData.Constrain(contentLength.Value);
                strData = Encoding.ASCII.GetString(ContentData.Array, ContentData.Offset, ContentData.Count);
            }
            catch (Exception e) when (e is ArgumentException || e is DecoderFallbackException)
            {
                throw new AsnException("asn.1 UTCTime could not be decoded to a string.", e);
            }
            var formats = new string[] {
                "yyMMddHHmmsszzz",
                "yyMMddHHmmzzz",
                "yyMMddHHmmZ",
                "yyMMddHHmmssZ",
            };
            DateTimeOffset val;
            if (!DateTimeOffset.TryParseExact(strData, formats, _parsingCulture, DateTimeStyles.AssumeUniversal, out val))
            {
                throw new AsnException("Encoded UTCTime is not valid.");
            }
            Value = val;
        }

        public override string ToString() => Value.ToString();


        //This is dumb trick to get UTCTime to handle two digit years the way the specification says.
        //UTCTime only supports dates between 1/1/1950 and 12/31/2049 (with GeneralizedTime being the
        //way to fix that.) If the two digit year is less then fifty, then the year should be interpreted
        //as in the 2000s. Otherwise, it's the 1900s. This is a specialized calendar that is given to the parser
        //that follows this rule.
        private class UTCTimeCalendar : GregorianCalendar
        {
            public override int ToFourDigitYear(int year) => (year < 50 ? 2000 : 1900) + year;
        }
    }
}

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
            _parsingCulture.DateTimeFormat.Calendar.TwoDigitYearMax = 2049;
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
            if (!DateTimeOffset.TryParseExact(strData, formats, _parsingCulture, DateTimeStyles.AssumeUniversal, out var val))
            {
                throw new AsnException("Encoded UTCTime is not valid.");
            }
            Value = val;
        }

        public override string ToString() => Value.ToString();
    }
}

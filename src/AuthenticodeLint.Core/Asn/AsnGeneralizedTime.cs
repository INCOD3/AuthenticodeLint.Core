using System;
using System.Globalization;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnGeneralizedTime : AsnElement, IAsnDateTime
    {
        public DateTimeOffset Value { get; }

        public AsnGeneralizedTime(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
            : base(tag, contentData, elementData)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of GeneralizeTime are not valid.");
            }
            string strData;
            try
            {
                strData = Encoding.ASCII.GetString(contentData.Array, contentData.Offset, contentData.Count);
            }
            catch (Exception e) when (e is DecoderFallbackException || e is ArgumentException)
            {
                throw new AsnException("asn.1 encoded GeneralizedTime could not be decoded into a string.", e);
            }
            var formats = new string[] {
                //Valid local times
                "yyyyMMddHH",
                "yyyyMMddHHmm",
                "yyyyMMddHHmmss",
                "yyyyMMddHHmmss.fff",

                //Valid UTC times
                "yyyyMMddHHZ",
                "yyyyMMddHHmmZ",
                "yyyyMMddHHmmssZ",
                "yyyyMMddHHmmss.fffZ",

                //Valid offset times
                "yyyyMMddHHzzz",
                "yyyyMMddHHmmzzz",
                "yyyyMMddHHmmsszzz",
                "yyyyMMddHHmmss.fffzzz",
            };
            DateTimeOffset val;
            if (!DateTimeOffset.TryParseExact(strData, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out val))
            {
                throw new AsnException("Encoded GeneralizedTime is not valid.");
            }
            Value = val;
        }

        public override string ToString() => Value.ToString();
    }
}

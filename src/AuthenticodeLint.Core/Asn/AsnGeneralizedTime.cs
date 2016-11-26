using System;
using System.Globalization;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnGeneralizedTime : AsnElement, IAsnDateTime
    {
        public DateTimeOffset Value { get; }

        public AsnGeneralizedTime(AsnTag tag, ArraySegment<byte> contentData) : base(tag, contentData)
        {
            var strData = Encoding.ASCII.GetString(contentData.Array, contentData.Offset, contentData.Count);
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
                throw new InvalidOperationException("Encoded GeneralizedTime is not valid.");
            }
            Value = val;
        }

        public override string ToString() => Value.ToString();
    }
}

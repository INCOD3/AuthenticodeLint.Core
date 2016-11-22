using System;
using System.Globalization;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
	public class AsnUtcTime : AsnElement
	{
		public DateTimeOffset Value { get; }
		
		public AsnUtcTime(AsnTag tag, ArraySegment<byte> data) : base(tag, data)
		{
			var strData = Encoding.ASCII.GetString(data.Array, data.Offset, data.Count);
			var formats = new string[] {
				"yyMMddHHmmsszzz",
				"yyMMddHHmmzzz",
				"yyMMddHHmmZ",
				"yyMMddHHmmssZ",
			};
			DateTimeOffset val;
			if (!DateTimeOffset.TryParseExact(strData, formats, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out val))
			{
				throw new InvalidOperationException("Encoded UTCDate is not valid.");
			}
			Value = val;
		}

		public override string ToString() => Value.ToString();
	}
}

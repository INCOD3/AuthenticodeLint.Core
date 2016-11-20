using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{

	public sealed class AsnIA5String : AsnElement
	{
		public string Value { get; }

		public AsnIA5String(AsnTagType tag, ArraySegment<byte> data) : base(tag, data)
		{
			Value = Encoding.ASCII.GetString(data.Array, data.Offset, data.Count);
		}

		public override string ToString() => Value;
	}

}
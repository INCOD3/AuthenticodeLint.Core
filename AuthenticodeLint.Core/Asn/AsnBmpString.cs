using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{

	public sealed class AsnBmpString : AsnElement
	{
		public string Value { get; }

		public AsnBmpString(AsnTag tag, ArraySegment<byte> data) : base(tag, data)
		{
			Value = Encoding.Unicode.GetString(data.Array, data.Offset, data.Count);
		}

		public override string ToString() => Value;
	}

}
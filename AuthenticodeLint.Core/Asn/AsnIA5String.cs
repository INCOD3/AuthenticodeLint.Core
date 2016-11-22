using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
	public sealed class AsnIA5String : AsnElement, IDirectoryString
	{
		public string Value { get; }

		public AsnIA5String(AsnTag tag, ArraySegment<byte> data) : base(tag, data)
		{
			Value = Encoding.ASCII.GetString(data.Array, data.Offset, data.Count);
		}

		public override string ToString() => Value;
	}
}
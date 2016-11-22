using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
	public sealed class AsnPrintableString : AsnElement, IDirectoryString
	{
		public string Value { get; }

		public AsnPrintableString(AsnTag tag, ArraySegment<byte> data) : base(tag, data)
		{
			Value = Encoding.ASCII.GetString(data.Array, data.Offset, data.Count);
		}

		public override string ToString() => Value;
	}
}

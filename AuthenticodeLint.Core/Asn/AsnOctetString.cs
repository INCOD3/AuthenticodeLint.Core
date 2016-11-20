using System;

namespace AuthenticodeLint.Core.Asn
{

	public sealed class AsnOctetString : AsnElement
	{
		public ArraySegment<byte> Value { get; }

		public AsnOctetString(AsnTagType tag, ArraySegment<byte> data) : base(tag, data)
		{
			Value = data;
		}
	}

}
using System;

namespace AuthenticodeLint.Core.Asn
{

	public sealed class AsnOctetString : AsnElement
	{
		public ArraySegment<byte> Value => Data;

		public AsnOctetString(AsnTag tag, ArraySegment<byte> data) : base(tag, data)
		{
		}
	}

}
using System;

namespace AuthenticodeLint.Core.Asn
{

	public sealed class AsnBitString : AsnElement
	{
		public ArraySegment<byte> Value { get; }

		public int UnusedBits { get; }

		public AsnBitString(AsnTagType tag, ArraySegment<byte> data) : base(tag, data)
		{
			UnusedBits = data.Array[data.Offset];
			Value = new ArraySegment<byte>(data.Array, data.Offset + 1, data.Count - 1);
		}
	}

}
using System;

namespace AuthenticodeLint.Core.Asn
{
	public sealed class AsnNull : AsnElement
	{
		public AsnNull(AsnTag tag, ArraySegment<byte> data) : base(tag, data)
		{
			if (data.Count > 0)
			{
				throw new InvalidOperationException("Null data cannot have a length.");
			}
		}

		public override string ToString() => "Null";
	}
}
using System;
using System.Collections.Generic;

namespace AuthenticodeLint.Core.Asn
{
	public class AsnConstructed : AsnElement
	{
		public AsnConstructed(AsnTag tag, ArraySegment<byte> data) : base(tag, data)
		{
		}

		public IEnumerable<AsnElement> Elements()
		{
			var segment = Data;
			while (true)
			{
				if (segment.Count == 0)
				{
					yield break;
				}
				int elementLength;
				yield return AsnDecoder.Process(segment, out elementLength);
				if (segment.Count - elementLength < 0)
				{
					throw new InvalidOperationException("Child data extended beyond set total length.");
				}
				segment = new ArraySegment<byte>(segment.Array, segment.Offset + elementLength, segment.Count - elementLength);
			}
		}
	}
}

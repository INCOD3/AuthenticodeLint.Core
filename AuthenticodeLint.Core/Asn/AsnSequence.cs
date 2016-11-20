using System;
using System.Collections.Generic;

namespace AuthenticodeLint.Core.Asn
{

	public sealed class AsnSequence : AsnElement
	{
		public AsnSequence(AsnTagType tag, ArraySegment<byte> data) : base(tag, data)
		{
		}

		public IEnumerable<AsnElement> Elements()
		{
			var segment = Data;
			var consumedLength = 0;
			while (true)
			{
				if (segment.Count == 0)
				{
					yield break;
				}
				int elementLength;
				yield return AsnDecoder.Process(segment, out elementLength);
				consumedLength += elementLength;
				segment = new ArraySegment<byte>(segment.Array, segment.Offset + elementLength, segment.Count - elementLength);
			}
			if (consumedLength != Data.Count)
			{
				throw new InvalidOperationException("The amount of data in the sequence is not equal to the amount of data read.");
			}
		}
	}
	
}
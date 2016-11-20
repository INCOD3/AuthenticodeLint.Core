using System;

namespace AuthenticodeLint.Core.Asn
{

	public sealed class AsnRaw : AsnElement
	{
		public AsnRaw(AsnTagType tag, ArraySegment<byte> data) : base(tag, data)
		{
		}
	}
}
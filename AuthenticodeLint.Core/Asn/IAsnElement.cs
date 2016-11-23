using System;

namespace AuthenticodeLint.Core.Asn
{
	public interface IAsnElement
	{
		ArraySegment<byte> Data { get; }

		AsnTag Tag { get; }
	}
}

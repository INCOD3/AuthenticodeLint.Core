using System;

namespace AuthenticodeLint.Core.Asn
{
    public interface IAsnElement
    {
        ArraySegment<byte> ContentData { get; }

        AsnTag Tag { get; }
    }
}

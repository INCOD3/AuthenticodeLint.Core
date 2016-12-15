using System;

namespace AuthenticodeLint.Core.Asn
{
    public interface IAsnElement
    {
        ArraySegment<byte> ElementData { get; }
        ArraySegment<byte> ContentData { get; }
        AsnTag Tag { get; }
    }
}

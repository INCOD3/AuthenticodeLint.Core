using System;

namespace AuthenticodeLint.Core.Asn
{

    /// <summary>
    /// An ordered sequence of zero or more asn.1 elements.
    /// </summary>
    public sealed class AsnSequence : AsnConstructed
    {
        public AsnSequence(AsnTag tag, ArraySegment<byte> elementData, long? contentLength, int headerSize)
            : base(tag, elementData, contentLength, headerSize)
        {
        }
    }
}
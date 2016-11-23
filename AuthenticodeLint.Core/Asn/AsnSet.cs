using System;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// An unordered set of zero or more asn.1 elements.
    /// </summary>
    public sealed class AsnSet : AsnConstructed
    {
        public AsnSet(AsnTag tag, ArraySegment<byte> contentData) : base(tag, contentData)
        {
        }
    }
}
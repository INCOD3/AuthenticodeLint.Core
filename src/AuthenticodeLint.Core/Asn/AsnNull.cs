using System;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnNull : AsnElement
    {
        public AsnNull(AsnTag tag, ArraySegment<byte> contentData) : base(tag, contentData)
        {
            if (contentData.Count > 0)
            {
                throw new InvalidOperationException("Null data cannot have a length.");
            }
        }

        public override string ToString() => "Null";
    }
}
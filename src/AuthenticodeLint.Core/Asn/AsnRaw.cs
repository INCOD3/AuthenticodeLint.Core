using System;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// A raw asn.1 data element.
    /// </summary>
    public sealed class AsnRaw : AsnElement
    {
        public AsnRaw(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
            : base(tag, contentData, elementData)
        {
        }
    }
}
using System;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// A raw asn.1 data element.
    /// </summary>
    public sealed class AsnRaw : AsnElement
    {
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnRaw(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength, ulong? elementContentLength)
            : base(tag)
        {
             if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of RAW are not valid.");
            }
            if (contentLength == null || elementContentLength == null)
            {
                throw new AsnException("Undefined lengths for RAW are not supported.");
            }
            ContentData = contentData.Constrain(contentLength.Value);
            ElementData = elementData.Constrain(elementContentLength.Value);
        }
    }
}
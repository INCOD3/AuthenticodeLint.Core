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

        public AsnRaw(AsnTag tag, ArraySegment<byte> elementData, long? contentLength, int headerSize)
            : base(tag, headerSize)
        {
             if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of RAW are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for RAW are not supported.");
            }
            ContentData = elementData.Window(headerSize, contentLength.Value);
            ElementData = elementData.Constrain(contentLength.Value + headerSize);
        }
    }
}
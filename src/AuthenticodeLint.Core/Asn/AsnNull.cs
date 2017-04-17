using System;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnNull : AsnElement
    {
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnNull(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength, ulong headerSize)
            : base(tag)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of NULL are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for NULL are not supported.");
            }
            ElementData = elementData.Constrain(contentLength.Value + headerSize);
            ContentData = contentData.Constrain(contentLength.Value);
            if (ContentData.Count > 0)
            {
                throw new AsnException("Null data cannot have a length.");
            }
        }

        public override string ToString() => "Null";
    }
}
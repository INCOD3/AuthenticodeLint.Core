using System;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnNull : AsnElement
    {
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnNull(AsnTag tag, ArraySegment<byte> elementData, long? contentLength, int headerSize)
            : base(tag, headerSize)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of NULL are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for NULL are not supported.");
            }
            if (contentLength > 0)
            {
                throw new AsnException("Null data cannot have a length.");
            }
            ElementData = elementData.Constrain(contentLength.Value + headerSize);
            ContentData = elementData.Window(headerSize, contentLength.Value);

        }

        public override string ToString() => "Null";
    }
}
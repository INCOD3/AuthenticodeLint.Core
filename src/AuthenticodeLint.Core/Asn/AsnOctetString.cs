using System;

namespace AuthenticodeLint.Core.Asn
{

    public sealed class AsnOctetString : AsnElement
    {
        public ArraySegment<byte> Value => ContentData;
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnOctetString(AsnTag tag, ArraySegment<byte> elementData, long? contentLength, int headerSize)
            : base(tag, headerSize)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of OctetString are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for OctetString are not supported.");
            }
            ElementData = elementData.Constrain(contentLength.Value + headerSize);
            ContentData = elementData.Window(headerSize, contentLength.Value);
        }
    }

}
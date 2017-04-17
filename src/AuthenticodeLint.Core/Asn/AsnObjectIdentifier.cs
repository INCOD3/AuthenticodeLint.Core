using System;

namespace AuthenticodeLint.Core.Asn
{

    public sealed class AsnObjectIdentifier : AsnElement
    {
        public Oid Value { get; }
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnObjectIdentifier(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength, ulong headerSize)
            : base(tag)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of ObjectIdentifier are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for ObjectIdentifier are not supported.");
            }
            ElementData = elementData.Constrain(contentLength.Value + headerSize);
            ContentData = contentData.Constrain(contentLength.Value);
            Value = new Oid(ContentData);
        }

        public override string ToString() => Value.Value;

        public override int GetHashCode() => Value.GetHashCode();
    }

}
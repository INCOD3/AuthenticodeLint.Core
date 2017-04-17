using System;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// An asn.1 encoded boolean value.
    /// </summary>
    public sealed class AsnBoolean : AsnElement
    {
        /// <summary>
        /// The value of the asn element.
        /// </summary>
        public bool Value { get; }
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnBoolean(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength, ulong headerSize)
            : base(tag)
        {
            if (contentData.Count == 0)
            {
                throw new AsnException("asn.1 boolean value cannot be empty.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for AsnBoolean are not supported.");
            }
            ElementData = elementData.Constrain(contentLength.Value + headerSize);
            ContentData = contentData.Constrain(contentLength.Value);
            for (var i = 0; i < ContentData.Count; i++)
            {
                if (ContentData.Array[ContentData.Offset + i] > 0)
                {
                    Value = true;
                    return;
                }
            }
            Value = false;
        }

        public override string ToString() => Value.ToString();

        public override bool Equals(AsnElement other)
        {
            //"True" can be respresented as any non-zero value. For the sake of boolean, we want to allow "true"
            //to always equal true, regardless of how it was encoded.
            switch (other)
            {
                case AsnBoolean boolean:
                    return boolean.Value == Value;
                default:
                    return base.Equals(other);
            }
        }
    }
}
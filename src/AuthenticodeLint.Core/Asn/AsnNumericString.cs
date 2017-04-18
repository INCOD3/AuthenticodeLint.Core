using System;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnNumericString : AsnElement, IDirectoryString
    {
        public string Value { get; }
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnNumericString(AsnTag tag, ArraySegment<byte> elementData, long? contentLength, int headerSize)
            : base(tag, headerSize)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of NumericString are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for NumericString are not supported.");
            }
            ElementData = elementData.Constrain(contentLength.Value + headerSize);
            ContentData = elementData.Window(headerSize, contentLength.Value);
            var arr = new char[ContentData.Count];
            for (int i = 0, j = ContentData.Offset; i < ContentData.Count; i++, j++)
            {
                byte c = ContentData.Array[j];
                if (c != ' ' && (c < '0' || c > '9'))
                {
                    throw new AsnException($"Invalid character \"{c:X2}\" for NumericString.");
                }
                arr[i] = (char)c;
            }
            Value = new string(arr);
        }

        public override string ToString() => Value;
    }
}
using System;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnNumericString : AsnElement, IDirectoryString
    {
        public string Value { get; }

        public AsnNumericString(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
            : base(tag, contentData, elementData)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of NumericString are not valid.");
            }
            var arr = new char[contentData.Count];
            for (int i = 0, j = contentData.Offset; i < contentData.Count; i++, j++)
            {
                byte c = contentData.Array[j];
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
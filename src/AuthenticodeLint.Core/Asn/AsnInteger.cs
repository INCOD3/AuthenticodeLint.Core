using System;
using System.Numerics;

namespace AuthenticodeLint.Core.Asn
{

    /// <summary>
    /// A signed, big endian, asn1 integer.
    /// </summary>
    public sealed class AsnInteger : AsnElement
    {
        /// <summary>
        /// The value of the integer.
        /// </summary>
        public BigInteger Value { get; }
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnInteger(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength, ulong? elementContentLength)
            : base(tag)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of Integer are not valid.");
            }
            if (contentLength == null || elementContentLength == null)
            {
                throw new AsnException("Undefined lengths for Integer are not supported.");
            }
            ElementData = elementData.Constrain(elementContentLength.Value);
            ContentData = contentData.Constrain(contentLength.Value);
            var buffer = new byte[ContentData.Count];
            //BigInteger expects the number in little endian.
            for (int i = ContentData.Count - 1, j = 0; i >= 0; i--, j++)
            {
                buffer[j] = ContentData.Array[ContentData.Offset + i];
            }
            Value = new BigInteger(buffer);
        }

        public override string ToString() => Value.ToString();
    }

}
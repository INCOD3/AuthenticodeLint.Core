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

        public AsnInteger(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
            : base(tag, contentData, elementData)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of Integer are not valid.");
            }
            var buffer = new byte[contentData.Count];
            //BigInteger expects the number in little endian.
            for (int i = contentData.Count - 1, j = 0; i >= 0; i--, j++)
            {
                buffer[j] = contentData.Array[contentData.Offset + i];
            }
            Value = new BigInteger(buffer);
        }

        public override string ToString() => Value.ToString();
    }

}
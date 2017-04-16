using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core
{
    public static class EcdsaUtilities
    {
        /// <summary>
        /// Converts an asn.1 sequence encoded ECDSA signature into an R || S encoded
        /// signature.
        /// </summary>
        public static byte[] AsnPointSignatureToConcatSignature(AsnSequence signature, int sizeBits)
        {
            var size = (sizeBits + 7) / 8; //Round up to nearest multiple of 8, then divide by 8.
            var (asnR, asnS) = AsnReader.Read<AsnInteger, AsnInteger>(signature);
            var r = ExpandShrinkToSize(asnR.ContentData, size);
            var s = ExpandShrinkToSize(asnS.ContentData, size);
            var concated = new byte[r.Count + s.Count];
            Buffer.BlockCopy(r.Array, r.Offset, concated, 0, r.Count);
            Buffer.BlockCopy(s.Array, s.Offset, concated, r.Count, s.Count);
            return concated;
        }

        public static ArraySegment<byte> ExpandShrinkToSize(ArraySegment<byte> value, int size)
        {
            //Just right. Leave it alone.
            if (value.Count == size)
            {
                return value;
            }
            //The value is one greater than the size because it is using zero to encode the value
            //as positive. Since we don't really have a sign in field elements, just take it off.
            if (value.Count == size + 1 && value.At(0) == 0)
            {
                return value.Advance(1);
            }
            if (value.Count < size)
            {
                var additional = new byte[size];
                var move = size - value.Count;
                Buffer.BlockCopy(value.Array, value.Offset, additional, move, value.Count);
                return new ArraySegment<byte>(additional);
            }
            throw new InvalidOperationException("Unable to transform point value.");
        }
    }
}
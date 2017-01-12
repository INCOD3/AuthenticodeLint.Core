using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core
{
    public static class EcdsaUtilities
    {
        /// <summary>
        /// Converts an asn.1 sequence encoded ECDSA signature into an X || Y encoded
        /// signature.
        /// </summary>
        public static byte[] AsnPointSignatureToConcatSignature(AsnSequence signature)
        {
            var ecPoint = AsnReader.Read<AsnInteger, AsnInteger>(signature);
            var x = ecPoint.Item1.ContentData.TrimOff(b => b == 0).AsArray();
            var y = ecPoint.Item2.ContentData.TrimOff(b => b == 0).AsArray();
            var concated = new byte[x.Length + y.Length];
            Buffer.BlockCopy(x, 0, concated, 0, x.Length);
            Buffer.BlockCopy(y, 0, concated, y.Length, x.Length);
            return concated;
        }
    }
}
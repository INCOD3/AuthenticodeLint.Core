using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
    public class SubjectPublicKeyInfo
    {
        public AlgorithmIdentifier Algorithm { get; }
        public ArraySegment<byte> PublicKey { get; }
        public int UnusedBits { get; }
        public ArraySegment<byte> RawData { get; }

        public SubjectPublicKeyInfo(AsnSequence sequence)
        {
            RawData = sequence.ElementData;
            var reader = new AsnConstructedReader(sequence);
            AsnSequence algorithmIdentifier;
            AsnBitString publicKey;
            if (!reader.MoveNext(out algorithmIdentifier))
            {
                throw new x509Exception("Missing SPKI algorithm identifier.");
            }
            if (!reader.MoveNext(out publicKey))
            {
                throw new x509Exception("Missing public key.");
            }
            Algorithm = new AlgorithmIdentifier(algorithmIdentifier);
            PublicKey = publicKey.ContentData;
            UnusedBits = publicKey.UnusedBits;
        }
    }
}

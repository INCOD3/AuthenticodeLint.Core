using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
	public class SubjectPublicKeyInfo
	{
		public AlgorithmIdentifier Algorithm { get; }
		public ArraySegment<byte> PublicKey { get; }
		public int UnusedBits { get; }
		
		public SubjectPublicKeyInfo(AsnSequence sequence)
		{
			var reader = new AsnConstructedReader(sequence);
			AsnSequence algorithmIdentifier;
			AsnBitString publicKey;
			if (!reader.MoveNext(out algorithmIdentifier))
			{
				throw new InvalidOperationException("Invalid SPKI algorithm identifier.");
			}
			if (!reader.MoveNext(out publicKey))
			{
				throw new InvalidOperationException("Invalid public key.");
			}
			Algorithm = new AlgorithmIdentifier(algorithmIdentifier);
			PublicKey = publicKey.Data;
			UnusedBits = publicKey.UnusedBits;
		}
	}
}

using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{

	public sealed class AlgorithmIdentifier
	{
		public AlgorithmIdentifier(string algorithm, ArraySegment<byte> parameters)
		{
			Algorithm = algorithm;
			Parameters = parameters;
		}

		public AlgorithmIdentifier(AsnSequence sequence)
		{
			var reader = new AsnConstructedReader(sequence);
			AsnObjectIdentifier algorithm;
			AsnElement parameters;
			if (!reader.MoveNext(out algorithm))
			{
				throw new InvalidOperationException("Unable to read algorithm from sequence.");
			}
			Algorithm = algorithm.Value;
			if (reader.MoveNext(out parameters))
			{
				Parameters = parameters.Data;
			}
			else
			{
				Parameters = null;
			}
		}

		public string Algorithm { get; }
		public ArraySegment<byte>? Parameters { get; }
	}
}
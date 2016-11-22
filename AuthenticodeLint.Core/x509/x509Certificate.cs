using System;
using System.IO;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
	public class x509Certificate
	{
		private readonly byte[] _data;
		private readonly AsnSequence _certificate;

		public x509Certificate(byte[] data)
		{
			_data = data;
			var decoded = AsnDecoder.Decode(data) as AsnSequence;
			if (decoded == null)
			{
				throw new Exception("Encoded data is not an x509 certificate.");
			}
			_certificate = decoded;
			AsnSequence tbsCertificate;
			AsnSequence tbsSignatureAlgorithm;
			AsnBitString tbsSignature;
			var certificateReader = new AsnConstructedReader(_certificate);
			if (!certificateReader.MoveNext(out tbsCertificate))
			{
				ThrowRead(nameof(tbsCertificate));
			}
			if (!certificateReader.MoveNext(out tbsSignatureAlgorithm))
			{
				ThrowRead(nameof(tbsSignatureAlgorithm));
			}
			if (!certificateReader.MoveNext(out tbsSignature))
			{
				ThrowRead(nameof(tbsSignature));
			}
			ReadTbsCertificate(tbsCertificate);
		}

		public x509Certificate(string filePath) : this(File.ReadAllBytes(filePath))
		{
		}

		public int Version { get; private set; }

		public byte[] SerialNumber { get; private set; }

		public AlgorithmIdentifier AlgorithmIdentifier { get; private set; }

		public x500DistinguishedName Issuer { get; private set; }

		private void ReadTbsCertificate(AsnSequence tbsCertificate)
		{
			AsnConstructed version;
			AsnInteger serialNumber;
			AsnSequence signature, issuer;
			var reader = new AsnConstructedReader(tbsCertificate);
			if (!reader.MoveNext(out version))
			{
				ThrowRead(nameof(version));
			}
			if (!reader.MoveNext(out serialNumber))
			{
				ThrowRead(nameof(serialNumber));
			}
			if (!reader.MoveNext(out signature))
			{
				ThrowRead(nameof(signature));
			}
			if (!reader.MoveNext(out issuer))
			{
				ThrowRead(nameof(issuer));
			}
			SerialNumber = serialNumber.Data.ToArray();
			AlgorithmIdentifier = new AlgorithmIdentifier(signature);
			Issuer = new x500DistinguishedName(issuer);
			if (version.Count != 1)
			{
				throw new InvalidOperationException("Version is not specified.");
			}
			Version = (int)((version[0] as AsnInteger)?.Value ?? 0);
		}

		private static void ThrowRead(string field)
		{
			throw new InvalidOperationException($"Unable to read {field} from certificate.");
		}
	}
}
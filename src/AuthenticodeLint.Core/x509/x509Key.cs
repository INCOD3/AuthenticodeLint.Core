using System;
using System.Security.Cryptography;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
    public sealed class x509Key
    {
        private readonly ISign _algorithm;

        public x509Key(SubjectPublicKeyInfo spki)
        {
            switch(spki.Algorithm.Algorithm)
            {
                case "1.2.840.10045.2.1":
                    _algorithm = FromEcDsa(spki);
                    break;
            }
        }

        public bool VerifyHash(byte[] hash, byte[] signature)
        {
            return _algorithm.VerifyHash(hash, signature);
        }


        private static EcDsaSign FromEcDsa(SubjectPublicKeyInfo spki)
        {
            if (spki.Algorithm.Parameters == null)
            {
                throw new InvalidOperationException("Unknown ECC curve.");
            }
            var decodedParameters = AsnDecoder.Decode(spki.Algorithm.Parameters.Value) as AsnObjectIdentifier;
            if (decodedParameters == null)
            {
                throw new InvalidOperationException("Unknown ECC curve.");
            }
            var curve = ECCurve.CreateFromValue(decodedParameters.Value);
            var point = DecodePoint(spki.PublicKey);
            var parameters = new ECParameters()
            {
                Curve = curve,
                Q = point
            };
            parameters.Validate();
            return new EcDsaSign(ECDsa.Create(parameters));
        }

        private static ECPoint DecodePoint(ArraySegment<byte> data)
        {
            var trimmed = data.TrimOff(b => b == 0);
            var pc = trimmed.At(0);
            var pointType = (PointType)pc;
            switch (pointType)
            {
                case PointType.Uncompressed:
                    return DecodeUncompressedPoint(trimmed.Advance(1));
                default:
                    throw new InvalidOperationException($"Unsupported curve compression {pointType}.");
            }
        }

        private static ECPoint DecodeUncompressedPoint(ArraySegment<byte> data)
        {
            if (data.Count % 2 != 0)
            {
                throw new InvalidOperationException("Unexpected uncompressed EC point size.");
            }
            var size = data.Count / 2;
            var x = data.Constrain(size);
            var y = data.Advance(size);
            if (x.Count != y.Count)
            {
                throw new InvalidOperationException("EC points are not equal in size.");
            }
            return new ECPoint
            {
                X = x.AsArray(),
                Y = y.AsArray()
            };
        }

        private enum PointType : byte
        {
            Uncompressed = 0x04,
            Compressed = 0x02,
            Hybrid = 0x03
        }
    }

    internal class EcDsaSign : ISign
    {
        private readonly ECDsa _algorithm;

        public EcDsaSign(ECDsa algorithm)
        {
            _algorithm = algorithm;
        }

        public bool VerifyHash(byte[] hash, byte[] signature) => _algorithm.VerifyHash(hash, signature);
    }

    internal interface ISign
    {
        bool VerifyHash(byte[] hash, byte[] signature);
    }
}
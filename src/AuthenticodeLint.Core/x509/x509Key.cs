using System;
using System.Security.Cryptography;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
    public sealed class x509Key : IDisposable
    {
        private readonly ISign _algorithm;

        public x509Key(SubjectPublicKeyInfo spki)
        {
            switch(spki.Algorithm.Algorithm)
            {
                case KnownOids.Algorithms.SigningAlgorithms.ecc:
                    _algorithm = FromEcDsa(spki);
                    break;
                case KnownOids.Algorithms.SigningAlgorithms.rsa:
                    _algorithm = FromRsa(spki);
                    break;
                default:
                    throw new NotSupportedException($"Signing algorithm {spki.Algorithm.Algorithm} is not supported.");
            }
        }

        public bool VerifyHash(byte[] hash, byte[] signature, string digestAlgorithmOid)
        {
            return _algorithm.VerifyHash(hash, signature, digestAlgorithmOid);
        }

        public bool VerifyHash(ArraySegment<byte> hash, ArraySegment<byte> signature, string digestAlgorithmOid) =>
            VerifyHash(hash.AsArray(), signature.AsArray(), digestAlgorithmOid);

        private static RsaSign FromRsa(SubjectPublicKeyInfo spki)
        {
            var publicKey = spki.PublicKey.TrimOff(b => b == 0);
            var publicKeyDecoded = AsnDecoder.Decode(publicKey) as AsnSequence;
            if (publicKeyDecoded == null)
            {
                throw new InvalidOperationException("Could not decode RSA key.");
            }
            var rsaComponents = AsnReader.Read<AsnInteger, AsnInteger>(publicKeyDecoded);
            var parameters = new RSAParameters
            {
                Modulus = rsaComponents.Item1.ContentData.AsArray(),
                Exponent = rsaComponents.Item2.ContentData.AsArray()
            };
            var rsa = RSA.Create();
            rsa.ImportParameters(parameters);
            return new RsaSign(rsa);
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

        public void Dispose()
        {
            _algorithm.Dispose();
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

        public bool VerifyHash(byte[] hash, byte[] signature, string digestAlgorithmOid)
        {
            byte[] transformSignature;
            AsnElement element;

            //In PKCS#7 an ECC signature is encoded as a Sequence of (R, S). However the
            //.NET Framework Core expects the signature to be encoded as R || S. Here we
            //try and sniff out how the signature was encoded. If it's a DER Sequence,
            //convert it. Otherwise, continue as-is.
            if (AsnDecoder.TryDecode(signature, out element) && element is AsnSequence)
            {
                var ecPoint = (AsnSequence)element;
                transformSignature = EcdsaUtilities.AsnPointSignatureToConcatSignature(ecPoint, _algorithm.KeySize);
            }
            else
            {
                transformSignature = signature;
            }
            return _algorithm.VerifyHash(hash, transformSignature);
        }

        public void Dispose() => _algorithm.Dispose();
    }

    internal class RsaSign : ISign
    {
        private readonly RSA _algorithm;

        public RsaSign(RSA algorithm)
        {
            _algorithm = algorithm;
        }

        public bool VerifyHash(byte[] hash, byte[] signature, string digestAlgorithmOid)
        {
            return _algorithm.VerifyHash(hash, signature, OidToHashAlgorithmName(digestAlgorithmOid), RSASignaturePadding.Pkcs1);
        }

        private static HashAlgorithmName OidToHashAlgorithmName(string oid)
        {
            switch (oid)
            {
                case KnownOids.Algorithms.Digest.sha1:
                    return HashAlgorithmName.SHA1;
                case KnownOids.Algorithms.Digest.sha256:
                    return HashAlgorithmName.SHA256;
                case KnownOids.Algorithms.Digest.sha384:
                    return HashAlgorithmName.SHA384;
                case KnownOids.Algorithms.Digest.sha512:
                    return HashAlgorithmName.SHA512;
                case KnownOids.Algorithms.Digest.md5:
                    return HashAlgorithmName.MD5;
                default:
                    throw new NotSupportedException($"Unknown hash algorithm oid {oid}.");
            }
        }

        public void Dispose() =>_algorithm.Dispose();
    }

    internal interface ISign : IDisposable
    {
        bool VerifyHash(byte[] hash, byte[] signature, string digestAlgorithmOid);
    }
}
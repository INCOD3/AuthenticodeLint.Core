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
            switch(spki.Algorithm.Algorithm.Value)
            {
                case KnownOids.Algorithms.SigningAlgorithms.ecc:
                    Algorithm = SignatureAlgorithm.Ecc;
                    _algorithm = FromEcDsa(spki);
                    break;
                case KnownOids.Algorithms.SigningAlgorithms.rsa:
                    Algorithm = SignatureAlgorithm.Rsa;
                    _algorithm = FromRsa(spki);
                    break;
                default:
                    throw new NotSupportedException($"Signing algorithm {spki.Algorithm.Algorithm} is not supported.");
            }
        }

        public SignatureAlgorithm Algorithm { get; }

        public bool VerifyHash(byte[] hash, byte[] signature, Oid digestAlgorithmOid)
        {
            return _algorithm.VerifyHash(hash, signature, digestAlgorithmOid);
        }

        public bool VerifyHash(ArraySegment<byte> hash, ArraySegment<byte> signature, Oid digestAlgorithmOid) =>
            VerifyHash(hash.AsArray(), signature.AsArray(), digestAlgorithmOid);

        public bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName digestAlgorithm)
        {
            return _algorithm.VerifyHash(hash, signature, digestAlgorithm);
        }

        public bool VerifyHash(ArraySegment<byte> hash, ArraySegment<byte> signature, HashAlgorithmName digestAlgorithm) =>
            VerifyHash(hash.AsArray(), signature.AsArray(), digestAlgorithm);

        public bool VerifyData(byte[] hash, byte[] signature, Oid digestAlgorithmOid)
        {
            return _algorithm.VerifyData(hash, signature, digestAlgorithmOid);
        }

        public bool VerifyData(ArraySegment<byte> hash, ArraySegment<byte> signature, Oid digestAlgorithmOid) =>
            VerifyData(hash.AsArray(), signature.AsArray(), digestAlgorithmOid);

        public bool VerifyData(byte[] hash, byte[] signature, HashAlgorithmName digestAlgorithm)
        {
            return _algorithm.VerifyData(hash, signature, digestAlgorithm);
        }

        public bool VerifyData(ArraySegment<byte> hash, ArraySegment<byte> signature, HashAlgorithmName digestAlgorithm) =>
            VerifyData(hash.AsArray(), signature.AsArray(), digestAlgorithm);

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
            var curve = ECCurve.CreateFromValue(decodedParameters.Value.Value);
            var point = DecodePoint(spki.PublicKey);
            var parameters = new ECParameters
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

        public bool VerifyHash(byte[] hash, byte[] signature, Oid digestAlgorithmOid) =>
            VerifyHash(hash, signature, OidToHashAlgorithmName(digestAlgorithmOid));

        public bool VerifyData(byte[] hash, byte[] signature, Oid digestAlgorithmOid) =>
            VerifyData(hash, signature, OidToHashAlgorithmName(digestAlgorithmOid));

        public bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName digestAlgorithm)
        {
            return _algorithm.VerifyHash(hash, DecodeSignature(signature));
        }

        public bool VerifyData(byte[] hash, byte[] signature, HashAlgorithmName digestAlgorithm)
        {
            return _algorithm.VerifyData(hash, DecodeSignature(signature), digestAlgorithm);
        }

        private byte[] DecodeSignature(byte[] signature)
        {
            AsnElement element;

            //In PKCS#7 an ECC signature is encoded as a Sequence of (R, S). However the
            //.NET Framework Core expects the signature to be encoded as R || S. We need
            //to unpack the sequence and concat them. To make matters more difficult, the
            //asn sequence is signed since it's encoded as integers. Field points don't really
            //have a "sign" so we need to strip off octets that exist purely to preserve sign.
            if (AsnDecoder.TryDecode(signature, out element) && element is AsnSequence)
            {
                var ecPoint = (AsnSequence)element;
                return EcdsaUtilities.AsnPointSignatureToConcatSignature(ecPoint, _algorithm.KeySize);
            }
            else
            {
                throw new InvalidOperationException("Signature was not encoded correctly.");
            }
        }

        private static HashAlgorithmName OidToHashAlgorithmName(Oid oid)
        {
            switch (oid.Value)
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

        public void Dispose() => _algorithm.Dispose();
    }

    internal class RsaSign : ISign
    {
        private readonly RSA _algorithm;

        public RsaSign(RSA algorithm)
        {
            _algorithm = algorithm;
        }

        public bool VerifyHash(byte[] hash, byte[] signature, Oid digestAlgorithmOid)
        {
            return _algorithm.VerifyHash(hash, signature, OidToHashAlgorithmName(digestAlgorithmOid), RSASignaturePadding.Pkcs1);
        }

        public bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName digestAlgorithm)
        {
            return _algorithm.VerifyHash(hash, signature, digestAlgorithm, RSASignaturePadding.Pkcs1);
        }


        public bool VerifyData(byte[] hash, byte[] signature, Oid digestAlgorithmOid)
        {
            return _algorithm.VerifyData(hash, signature, OidToHashAlgorithmName(digestAlgorithmOid), RSASignaturePadding.Pkcs1);
        }

        public bool VerifyData(byte[] hash, byte[] signature, HashAlgorithmName digestAlgorithm)
        {
            return _algorithm.VerifyData(hash, signature, digestAlgorithm, RSASignaturePadding.Pkcs1);
        }

        private static HashAlgorithmName OidToHashAlgorithmName(Oid oid)
        {
            switch (oid.Value)
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

        public void Dispose() => _algorithm.Dispose();
    }

    internal interface ISign : IDisposable
    {
        bool VerifyHash(byte[] hash, byte[] signature, Oid digestAlgorithmOid);
        bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName digestAlgorithm);

        bool VerifyData(byte[] hash, byte[] signature, Oid digestAlgorithmOid);
        bool VerifyData(byte[] hash, byte[] signature, HashAlgorithmName digestAlgorithm);
    }
}
using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
    public sealed class x509Certificate : IEquatable<x509Certificate>, IComparable<x509Certificate>
    {
        private readonly AsnSequence _certificate;
        private ArraySegment<byte> _thumbprint, _tbsCertificate;
        private bool _hasThumbprint = false;

        public x509Certificate(byte[] data) : this(new ArraySegment<byte>(data))
        {
        }

        public x509Certificate(AsnSequence certificate)
        {
            _certificate = certificate;
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
            SignatureAlgorithmIdentifier = new AlgorithmIdentifier(tbsSignatureAlgorithm);
            Signature = tbsSignature.Value;
            ReadTbsCertificate(tbsCertificate);
        }

        public x509Certificate(ArraySegment<byte> data) : this(DecodeData(data))
        {
        }

        public x509Certificate(string filePath) : this(File.ReadAllBytes(filePath))
        {
        }


        public int Version { get; private set; }

        public ArraySegment<byte> SerialNumber { get; private set; }

        public AlgorithmIdentifier AlgorithmIdentifier { get; private set; }

        public x500DistinguishedName Issuer { get; private set; }

        public DateTimeOffset NotBefore { get; private set; }

        public DateTimeOffset NotAfter { get; private set; }

        public x500DistinguishedName Subject { get; private set; }

        public SubjectPublicKeyInfo PublicKey { get; private set; }

        public x509Extensions Extensions { get; private set; }

        public AlgorithmIdentifier SignatureAlgorithmIdentifier { get; private set; }

        public ArraySegment<byte> Signature { get; private set; }

        public ArraySegment<byte> Thumbprint
        {
            get
            {
                if (!_hasThumbprint)
                {
                    using (var sha1 = SHA1.Create())
                    {
                        var data = _certificate.ElementData;
                        _thumbprint = new ArraySegment<byte>(sha1.ComputeHash(data.Array, data.Offset, data.Count));
                    }
                    _hasThumbprint = true;
                }
                return _thumbprint;
            }
        }

        private static AsnSequence DecodeData(ArraySegment<byte> data)
        {
            var certificate = AsnDecoder.Decode(data) as AsnSequence;
            if (certificate == null)
            {
                throw new AsnException("Decoded data is not a certificate");
            }
            return certificate;
        }

        private void ReadTbsCertificate(AsnSequence tbsCertificate)
        {
            _tbsCertificate = tbsCertificate.ElementData;
            AsnConstructed version;
            AsnInteger serialNumber;
            AsnSequence signature, issuer, validityPeriod, subject, spki;
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
            if (!reader.MoveNext(out validityPeriod))
            {
                ThrowRead(nameof(validityPeriod));
            }
            if (!reader.MoveNext(out subject))
            {
                ThrowRead(nameof(subject));
            }
            if (!reader.MoveNext(out spki))
            {
                ThrowRead(nameof(spki));
            }
            SerialNumber = serialNumber.ContentData;
            AlgorithmIdentifier = new AlgorithmIdentifier(signature);
            Issuer = new x500DistinguishedName(issuer);
            if (!version.Tag.IsExImTag(0))
            {
                throw new x509Exception("Version is not specified.");
            }
            Version = (int)AsnReader.Read<AsnInteger>(version).Value;
            var (notBefore, notAfter) = AsnReader.Read<IAsnDateTime, IAsnDateTime>(validityPeriod);
            NotBefore = notBefore.Value;
            NotAfter = notAfter.Value;
            Subject = new x500DistinguishedName(subject);
            PublicKey = new SubjectPublicKeyInfo(spki);
            if (reader.CanMove() && Version == 0)
            {
                throw new x509Exception("x509 certificate is version 1 but contains version 2 or 3 data.");
            }
            while (reader.MoveNext(out AsnConstructed element))
            {
                if (element.Tag.IsExImTag(1) || element.Tag.IsExImTag(2))
                {
                    //We don't do anything with the issuerUniqueID or subjectUniqueID fields right now.
                    continue;
                }
                if (element.Tag.IsExImTag(3))
                {
                    var extensions = AsnReader.Read<AsnSequence>(element);
                    Extensions = new x509Extensions(extensions);
                }
            }
            if (Extensions == null)
            {
                Extensions = new x509Extensions();
            }
        }

        public Task ExportAsync(Stream destination)
        {
            var data = _certificate.ElementData;
            return destination.WriteAsync(data.Array,data.Offset, data.Count);
        }

        internal X509Certificate2 AsCore() => new X509Certificate2(_certificate.ElementData.AsArray());

        internal static x509Certificate FromCore(X509Certificate2 coreCert) => new x509Certificate(coreCert.RawData);

        public void Export(byte[] buffer, int offset)
        {
            var data = _certificate.ElementData;
            if (buffer.Length - offset < data.Count)
            {
                throw new ArgumentException("Buffer is not large enough to contain data.");
            }
            Buffer.BlockCopy(data.Array, data.Offset, buffer, offset, data.Count);
        }

        private static void ThrowRead(string field)
        {
            throw new x509Exception($"Unable to read {field} from certificate.");
        }

        public bool Equals(x509Certificate other)
        {
            if (ReferenceEquals(this, other))
            {
                return true;
            }
            if (ReferenceEquals(other, null))
            {
                return false;
            }

            return _certificate.ElementData.Compare(other._certificate.ElementData) == 0;
        }

        public int CompareTo(x509Certificate other) => CompareTo(other, IdenticalCertificateComparer.Instance);

        public int CompareTo(x509Certificate other, IComparer<x509Certificate> comparer) => comparer.Compare(this, other);

        public override string ToString() => Subject.ToString();

        /// <summary>
        /// Validates the signature of this certificate against the issuing, signing certificate.
        /// </summary>
        public bool ValidateSignature(x509Certificate signingCertificate)
        {
            //X509 spec says that the algorithm in the TBSCertificate must be the same
            //algorithm as the signatureAlgorithm.
            if (AlgorithmIdentifier != SignatureAlgorithmIdentifier)
            {
                return false;
            }
            using (var signerKey = new x509Key(signingCertificate.PublicKey))
            {
                //This certificate was hashed with an algorithm we don't understand. Return false,
                //later possibly try to include diagnostic information.
                HashAlgorithmName hash;
                SignatureAlgorithm signature;
                if (!HashUtilities.TryHashNameFromSignatureHashOid(AlgorithmIdentifier.Algorithm, out hash, out signature))
                {
                    return false;
                }
                //The signature algorithm on the certificate does not explicitly match the algorithm
                //so turn it down before we actually try to do the verification.
                if (signature != signerKey.Algorithm)
                {
                    return false;
                }
                return signerKey.VerifyData(_tbsCertificate, Signature, hash);
            }
        }

        /// <summary>
        /// Compares two certificates with byte-for-byte equality of their DER representation.
        /// </summary>
        public sealed class IdenticalCertificateComparer : IComparer<x509Certificate>
        {
            public static IdenticalCertificateComparer Instance { get; } = new IdenticalCertificateComparer();

            public int Compare(x509Certificate x, x509Certificate y)
            {
                if (ReferenceEquals(x, y))
                {
                    return 0;
                }
                if (ReferenceEquals(y, null))
                {
                    return -1;
                }

                if (ReferenceEquals(x, null))
                {
                    return 1;
                }
                return x._certificate.ElementData.Compare(y._certificate.ElementData);
            }

            private IdenticalCertificateComparer()
            {
            }
        }

        public sealed class IssuerAndSerialComparer : IComparer<x509Certificate>
        {
            public static IssuerAndSerialComparer Instance { get; } = new IssuerAndSerialComparer();

            public int Compare(x509Certificate x, x509Certificate y)
            {
                if (ReferenceEquals(x, y))
                {
                    return 0;
                }
                if (ReferenceEquals(y, null))
                {
                    return -1;
                }

                if (ReferenceEquals(x, null))
                {
                    return 1;
                }
                var sameIssuer = x.Issuer.UnderlyingSequence.ElementData.Compare(y.Issuer.UnderlyingSequence.ElementData);
                if (sameIssuer != 0)
                {
                    return sameIssuer;
                }
                return x.SerialNumber.Compare(y.SerialNumber);
            }

            private IssuerAndSerialComparer()
            {
            }
        }

        public sealed class ThumbprintComparer : IComparer<x509Certificate>
        {
            public static ThumbprintComparer Instance { get; } = new ThumbprintComparer();

            public int Compare(x509Certificate x, x509Certificate y)
            {
                if (ReferenceEquals(x, y))
                {
                    return 0;
                }
                if (ReferenceEquals(y, null))
                {
                    return -1;
                }

                if (ReferenceEquals(x, null))
                {
                    return 1;
                }
                return x.Thumbprint.Compare(y.Thumbprint);
            }

            private ThumbprintComparer()
            {
            }
        }
    }
}
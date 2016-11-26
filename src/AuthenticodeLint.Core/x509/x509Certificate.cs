using System;
using System.IO;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
    public sealed class x509Certificate
    {
        private readonly ArraySegment<byte> _data;
        private readonly AsnSequence _certificate;

        public x509Certificate(byte[] data) : this(new ArraySegment<byte>(data))
        {
        }

        public x509Certificate(ArraySegment<byte> data)
        {
            _data = data;
            var decoded = AsnDecoder.Decode(data) as AsnSequence;
            if (decoded == null)
            {
                throw new x509Exception("Encoded data is not an x509 certificate.");
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

        public ArraySegment<byte> SerialNumber { get; private set; }

        public AlgorithmIdentifier AlgorithmIdentifier { get; private set; }

        public x500DistinguishedName Issuer { get; private set; }

        public DateTimeOffset NotBefore { get; private set; }

        public DateTimeOffset NotAfter { get; private set; }

        public x500DistinguishedName Subject { get; private set; }

        public SubjectPublicKeyInfo PublicKey { get; private set; }

        private void ReadTbsCertificate(AsnSequence tbsCertificate)
        {
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
            if (version.Tag.Tag != 0)
            {
                throw new x509Exception("Version is not specified.");
            }
            Version = (int)AsnContructedStaticReader.Read<AsnInteger>(version).Item1.Value;
            var validity = AsnContructedStaticReader.Read<IAsnDateTime, IAsnDateTime>(validityPeriod);
            NotBefore = validity.Item1.Value;
            NotAfter = validity.Item2.Value;
            Subject = new x500DistinguishedName(subject);
            PublicKey = new SubjectPublicKeyInfo(spki);
        }

        private static void ThrowRead(string field)
        {
            throw new x509Exception($"Unable to read {field} from certificate.");
        }
    }
}
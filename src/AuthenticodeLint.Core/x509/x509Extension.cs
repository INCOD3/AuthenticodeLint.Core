using System;
using System.Collections.Generic;
using System.Numerics;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
    public class x509Extension
    {
        public string Oid { get; }
        public ArraySegment<byte> Content { get; }
        public bool Critical { get; }

        public x509Extension(string oid, ArraySegment<byte> data, bool critical)
        {
            Oid = oid;
            Content = data;
            Critical = critical;
        }
    }

    public sealed class ExtendedKeyUsageExtension : x509Extension
    {
        public IReadOnlyList<Oid> KeyPurposeIds { get; }

        public ExtendedKeyUsageExtension(string oid, ArraySegment<byte> data, bool critical)
            : base(oid, data, critical)
        {
            var keyPurposes = new List<Oid>();
            var keyPurposeSequence = AsnDecoder.Decode(data) as AsnSequence;
            if (keyPurposeSequence == null)
            {
                throw new AsnException("Failed to decode EKU extension.");
            }
            var reader = new AsnConstructedReader(keyPurposeSequence);
            while(reader.MoveNext(out AsnObjectIdentifier purpose))
            {
                keyPurposes.Add(purpose.Value);
            }
            KeyPurposeIds = keyPurposes;
        }
    }

    public sealed class BasicConstraintsExtension : x509Extension
    {
        public bool CA { get; } = false;
        public int PathLengthConstraint { get; } = 0;

        public BasicConstraintsExtension(string oid, ArraySegment<byte> data, bool critical)
            : base(oid, data, critical)
        {
            var basicConstraintData = AsnDecoder.Decode(data) as AsnSequence;
            if (basicConstraintData == null)
            {
                throw new AsnException("Failed to decode Basic Constraints extension.");
            }
            var reader = new AsnConstructedReader(basicConstraintData);
            if (reader.MoveNext(out AsnBoolean isCa))
            {
                CA = isCa.Value;
            }
            if (reader.MoveNext(out AsnInteger pathLengthConstraint))
            {
                PathLengthConstraint = checked((int)pathLengthConstraint.Value);
            }
        }
    }

    public sealed class SubjectKeyIdentifier : x509Extension
    {
        public SubjectKeyIdentifier(string oid, ArraySegment<byte> data, bool critical)
            : base(oid, data, critical)
        {
            var keyIdentifier = AsnDecoder.Decode(data) as AsnOctetString;
            if (keyIdentifier == null)
            {
                throw new AsnException("Failed to decode Subject Key Identifier extension.");
            }
            KeyIdentifier = keyIdentifier.ContentData;
        }

        public ArraySegment<byte> KeyIdentifier { get; }
    }

    public sealed class AuthorityKeyIdentifierExtension : x509Extension
    {
        public AuthorityKeyIdentifierExtension(string oid, ArraySegment<byte> data, bool critical)
            : base(oid, data, critical)
        {
            var akiSequence = AsnDecoder.Decode(data) as AsnSequence;
            if (akiSequence == null)
            {
                throw new AsnException("Failed to decode Authority Key Identifier extension.");
            }
            var reader = new AsnConstructedReader(akiSequence);
            while (reader.MoveNext(out AsnElement element))
            {
                if (element.Tag.IsExImTag(0)) //keyIdentifier
                {
                    KeyIdentifier = element.Reinterpret<AsnOctetString>().Value;
                }
                else if (element.Tag.IsExImTag(1)) //authorityCertIssuer
                {
                    var set = element.Reinterpret<AsnSet>();
                    var list = new List<GeneralName>();
                    foreach (var item in set)
                    {
                        list.Add(new GeneralName(item));
                    }
                    GeneralNames = list.AsReadOnly();
                }
                else if (element.Tag.IsExImTag(2)) //authorityCertSerialNumber
                {
                    AuthoritySerialNumber = element.Reinterpret<AsnInteger>().Value;
                }
            }
        }

        public ArraySegment<byte>? KeyIdentifier { get; }
        public BigInteger? AuthoritySerialNumber { get; }
        public IReadOnlyList<GeneralName> GeneralNames { get; }
    }
}
using System;
using System.Collections.Generic;
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
        public IReadOnlyList<string> KeyPurposeIds { get; }

        public ExtendedKeyUsageExtension(string oid, ArraySegment<byte> data, bool critical)
            : base(oid, data, critical)
        {
            var keyPurposes = new List<string>();
            var keyPurposeSequence = AsnDecoder.Decode(data) as AsnSequence;
            if (keyPurposeSequence == null)
            {
                throw new AsnException("Failed to decode EKU extension.");
            }
            var reader = new AsnConstructedReader(keyPurposeSequence);
            AsnObjectIdentifier purpose;
            while(reader.MoveNext(out purpose))
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
            AsnBoolean isCa;
            AsnInteger pathLengthConstraint;
            if (reader.MoveNext(out isCa))
            {
                CA = isCa.Value;
            }
            if (reader.MoveNext(out pathLengthConstraint))
            {
                PathLengthConstraint = (int)pathLengthConstraint.Value;
            }
        }
    }
}
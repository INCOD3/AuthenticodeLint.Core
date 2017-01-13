using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{

    public class RelativeDistinguishedNameComponent : IEquatable<RelativeDistinguishedNameComponent>
    {
        public Oid ObjectIdentifier { get; }
        public string Value { get; }
        public byte[] RawValue { get; }
        private AsnSequence AsnData {get; }

        public RelativeDistinguishedNameComponent(AsnSequence asnData, Oid objectIdentifier, string value, byte[] rawValue)
        {
            AsnData = asnData;
            ObjectIdentifier = objectIdentifier;
            Value = value;
            RawValue = rawValue;
        }

        public bool Equals(RelativeDistinguishedNameComponent other)
        {
            if (ReferenceEquals(other, null)) return false;
            return AsnData.Equals(other.AsnData);
        }

        public override bool Equals(object obj) => Equals(obj as RelativeDistinguishedNameComponent);

        public override int GetHashCode()  => AsnData.GetHashCode();
    }
}

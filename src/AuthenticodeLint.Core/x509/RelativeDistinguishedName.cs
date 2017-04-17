using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{

    public class RelativeDistinguishedName : IReadOnlyList<RelativeDistinguishedNameComponent>, IEquatable<RelativeDistinguishedName>
    {
        private readonly IReadOnlyList<RelativeDistinguishedNameComponent> _components;

        public RelativeDistinguishedName(AsnSet asnSet)
        {
            var dnList = new List<RelativeDistinguishedNameComponent>();
            var seqReader = new AsnConstructedReader();
            foreach (var dn in asnSet.Cast<AsnSequence>())
            {
                seqReader.ReTarget(dn);
                if (!seqReader.MoveNext(out AsnObjectIdentifier identifier) || !seqReader.MoveNext(out IDirectoryString value))
                {
                    throw new x509Exception("Distinguished Name component does not contain a valid ObjectIdentifer or directory string.");
                }
                dnList.Add(new RelativeDistinguishedNameComponent(dn, identifier.Value, value.Value, value.ContentData.AsArray()));
            }
            _components = dnList;
        }

        public RelativeDistinguishedNameComponent this[int index] => _components[index];

        public int Count => _components.Count;

        public IEnumerator<RelativeDistinguishedNameComponent> GetEnumerator() => _components.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public override string ToString()
        {
            var builder = new StringBuilder();
            for (int i = 0; i < Count; i++)
            {
                var component = this[i];
                builder.Append(DistinguishedNameComponents.GetComponentName(component.ObjectIdentifier));
                builder.Append('=');
                builder.Append(component.Value);
                if (i < Count - 1)
                {
                    builder.Append(" + ");
                }
            }
            return builder.ToString();
        }

        public bool Equals(RelativeDistinguishedName other)
        {
            if (ReferenceEquals(other, null))
            {
                return false;
            }
            //We use HashSets here because we don't care about the order
            //of the components. They're a set, which is unordered.
            var meSet = new HashSet<RelativeDistinguishedNameComponent>(this);
            var otherSet = new HashSet<RelativeDistinguishedNameComponent>(other);
            return meSet.SetEquals(otherSet);
        }

        public override bool Equals(object obj) => Equals(obj as RelativeDistinguishedName);

        public override int GetHashCode()
        {
            var builder = new HashCodeBuilder();
            foreach (var component in this)
            {
                builder.Push(component.GetHashCode());
            }
            return builder.GetHashCode();
        }
    }
}

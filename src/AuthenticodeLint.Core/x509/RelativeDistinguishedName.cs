using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{

    public class RelativeDistinguishedName : IReadOnlyList<RelativeDistinguishedNameComponent>
    {
        private readonly IReadOnlyList<RelativeDistinguishedNameComponent> _components;

        public RelativeDistinguishedName(AsnSet asnSet)
        {
            var dnList = new List<RelativeDistinguishedNameComponent>();
            var seqReader = new AsnConstructedReader();
            foreach (var dn in asnSet.Cast<AsnSequence>())
            {
                seqReader.ReTarget(dn);
                AsnObjectIdentifier identifier;
                IDirectoryString value;
                if (!seqReader.MoveNext(out identifier) || !seqReader.MoveNext(out value))
                {
                    throw new InvalidOperationException();
                }
                dnList.Add(new RelativeDistinguishedNameComponent(identifier.Value, value.Value, value.ContentData.ToArray()));
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
    }

}

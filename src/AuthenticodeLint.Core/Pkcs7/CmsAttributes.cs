using System.Collections;
using System.Collections.Generic;
using System.Linq;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsAttributes : IReadOnlyList<CmsAttribute>
    {
        private readonly List<CmsAttribute> _list = new List<CmsAttribute>();

        public CmsAttribute this[int index] => _list[index];

        public int Count => _list.Count;

        public IEnumerator<CmsAttribute> GetEnumerator() => _list.GetEnumerator();

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public CmsAttributes(AsnConstructed constructed)
        {
            foreach(var sequence in constructed.Cast<AsnSequence>())
            {
                _list.Add(CmsAttributeDecoder.Decode(sequence));
            }
        }


        public CmsAttributes()
        {
        }
    }
}
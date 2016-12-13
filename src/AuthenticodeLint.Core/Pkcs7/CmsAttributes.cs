using System.Collections;
using System.Collections.Generic;
using System.Linq;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsAttributes : IReadOnlyList<CmsGenericAttribute>
    {
        private readonly List<CmsGenericAttribute> _list = new List<CmsGenericAttribute>();

        public CmsGenericAttribute this[int index] => _list[index];

        public int Count => _list.Count;

        public IEnumerator<CmsGenericAttribute> GetEnumerator() => _list.GetEnumerator();

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
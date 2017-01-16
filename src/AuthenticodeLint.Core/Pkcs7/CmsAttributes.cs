using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsAttributes : IReadOnlyList<CmsGenericAttribute>
    {
        private readonly List<CmsGenericAttribute> _internalList;

        public CmsGenericAttribute this[int index] => _internalList[index];

        public int Count => _internalList.Count;

        public IEnumerator<CmsGenericAttribute> GetEnumerator() => _internalList.GetEnumerator();
        internal AsnConstructed AsnElement { get; }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

        public CmsAttributes(AsnConstructed constructed)
        {
            AsnElement = constructed;
            _internalList = new List<CmsGenericAttribute>(constructed.Count);

            foreach(var sequence in constructed.Cast<AsnSequence>())
            {
                _internalList.Add(CmsAttributeDecoder.Decode(sequence));
            }
        }

        public CmsAttributes()
        {
            _internalList = new List<CmsGenericAttribute>(0);
        }

        public CmsGenericAttribute this[string attributeId]
        {
            get
            {
                CmsGenericAttribute result = null;
                foreach(var attribute in this)
                {
                    if (attribute.AttributeId == attributeId)
                    {
                        if (result != null)
                        {
                            throw new InvalidOperationException("More than one attribute found.");
                        }
                        result = attribute;
                    }
                }
                return result;
            }
        }
    }
}
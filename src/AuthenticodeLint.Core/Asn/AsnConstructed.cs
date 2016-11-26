using System;
using System.Collections;
using System.Collections.Generic;

namespace AuthenticodeLint.Core.Asn
{
    public class AsnConstructed : AsnElement, IReadOnlyList<AsnElement>
    {
        private readonly AsnElement[] _items;

        public AsnConstructed(AsnTag tag, ArraySegment<byte> contentData) : base(tag, contentData)
        {
            var collection = new List<AsnElement>();
            var segment = ContentData;
            while (true)
            {
                if (segment.Count == 0)
                {
                    break;
                }
                int elementLength;
                collection.Add(AsnDecoder.Process(segment, out elementLength));
                if (segment.Count - elementLength < 0)
                {
                    throw new InvalidOperationException("Child data extended beyond set total length.");
                }
                segment = new ArraySegment<byte>(segment.Array, segment.Offset + elementLength, segment.Count - elementLength);
            }
            _items = collection.ToArray();
        }

        public AsnElement this[int index] => _items[index];

        public int Count => _items.Length;

        public IEnumerator<AsnElement> GetEnumerator()
        {
            foreach (var item in _items) yield return item;
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

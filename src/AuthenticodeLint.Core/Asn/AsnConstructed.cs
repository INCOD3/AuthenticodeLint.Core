using System;
using System.Collections;
using System.Collections.Generic;

namespace AuthenticodeLint.Core.Asn
{
    public class AsnConstructed : AsnElement, IReadOnlyList<AsnElement>
    {
        private readonly AsnElement[] _items;

        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        private static readonly byte[] _terminator = new byte[] { 0, 0 };
        internal const int MAX_ITEMS = 65535;

        public AsnConstructed(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength)
            : base(tag)
        {
            //unknownLengths mean the constructed form has a length that is unknown. Instead,
            //we need to look for the "end of data" terminator, which is 0x0000.
            bool isUnkownLength = contentLength == null;
            var collection = new List<AsnElement>();
            var segment = contentData;

            var runningContentLength = 0u;
            for (var counter = 0;; counter++)
            {
                //For this asn.1 decoder's use, there is no practical reason why a sequence / set would
                //contain more then 65k items. Soft limit that so we don't end up in an infinite loop if
                //there is a decoding bug.
                if (counter > MAX_ITEMS)
                {
                    throw new AsnException("Maximum number of items to decode has been reached.");
                }

                //If there is no more data at all, time to stop.
                if (segment.Count == 0)
                {
                    break;
                }

                //We have a known-length item, and at this point the segment is past the length, so we're done.
                if (!isUnkownLength && segment.Offset - contentData.Offset >= (int)contentLength.Value)
                {
                    break;
                }
                //If there is more data, and we are in unknown length mode,
                //check to see if we're at a terminator. If so, stop.
                else if (isUnkownLength && segment.StartsWith(_terminator))
                {
                    break;
                }

                //There is more data. Decode an element.
                var decoded = AsnDecoder.Decode(segment);
                collection.Add(decoded);

                //Keep a running total of all of the content we have decoded so far.
                //when we've reached the end, this will be the length of this items
                //content data.
                runningContentLength += (uint)decoded.ElementData.Count;

                //Move the current segment to the data immediately after the decoded length.
                segment = segment.Advance(decoded.ElementData.Count);
            }

            //even though we have a defined length of the content, we calculate it ourselves
            //all the time. If we have a known length, but it does not match what we calculated,
            //then something went wrong.
            if (!isUnkownLength && runningContentLength != contentLength)
            {
                throw new AsnException($"Calculated decoded length {runningContentLength} does not match specified length {contentLength}.");
            }
            ContentData = contentData.Constrain(runningContentLength);
            ElementData = elementData.ConstrainWith(ContentData, isUnkownLength ? runningContentLength + _terminator.Length : runningContentLength);
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

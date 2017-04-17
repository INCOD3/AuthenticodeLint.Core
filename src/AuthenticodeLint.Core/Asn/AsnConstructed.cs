using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;

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
            var isUnkownLength = contentLength == null;
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

        //This is a special case where we want to be able to actually change the binary
        //interpretation of the constructed form for Sets and Sequences rather than just
        //just changing the type.
        public override TType Reinterpret<TType>()
        {
            var type = typeof(TType);
            //If we are not trying to convert to a set or a sequence, defer back to the base
            //implementation
            if (typeof(TType) != typeof(AsnSequence) && typeof(TType) != typeof(AsnSet))
            {
                return base.Reinterpret<TType>();
            }
            //If we are for whatever reason converting to the same binary form, don't bother
            //this is just a type transformation. This avoids a memory copy.
            var tagValue = TagValueForType(type);
            if (Tag.IsUniTag(tagValue))
            {
                return base.Reinterpret<TType>();
            }

            //At this point we are going to create our own DER encoded value.
            var newTag = (byte)(0x20u | (byte)tagValue); //We know this won't overflow.
            var length = EncodeLength(ContentData.Count);
            using (var newElementData = new MemoryStream())
            {
                newElementData.WriteByte(newTag);
                newElementData.Write(length, 0, length.Length);
                newElementData.Write(ContentData.Array, ContentData.Offset, ContentData.Count);
                var materialize = newElementData.ToArray();
                var tag = new AsnTag(tagValue, AsnClass.Univeral, true);
                var newElementDataSegment = new ArraySegment<byte>(materialize);
                var newContentDataSegment = new ArraySegment<byte>(materialize, 1 + length.Length, materialize.Length - 1 - length.Length);
                return (TType)Activator.CreateInstance(typeof(TType), tag, newContentDataSegment, newElementDataSegment, (ulong?)newContentDataSegment.Count);
            }
        }

        private static byte[] EncodeLength(long length)
        {
            if (length < 0)
            {
                throw new ArgumentException(nameof(length));
            }
            if (length < 0x80)
            {
                return new byte[] { (byte)length };
            }
            var bytes = new List<byte>();
            var copy = length;
            while (length > 0)
            {
                bytes.Insert(0, (byte)(length & 0xFF));
                length >>= 8;
            }
            bytes.Insert(0, (byte)(0x80 | bytes.Count));
            return bytes.ToArray();
        }

        private static AsnTagValue TagValueForType(Type type)
        {
            if (type == typeof(AsnSequence))
            {
                return AsnTagValue.SequenceSequenceOf;
            }
            if (type == typeof(AsnSet))
            {
                return AsnTagValue.SetSetOf;
            }
            throw new InvalidOperationException("Trying to reinterpret to an unsupported type. This should have deferred to the base.");
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }
}

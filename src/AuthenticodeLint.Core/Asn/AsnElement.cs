using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// An asn1 element. All elements inherit from this type.
    /// </summary>
    public abstract class AsnElement : IAsnElement, IEquatable<AsnElement>
    {
        /// <summary>
        /// Gets the segement of data for the element.
        /// </summary>
        public ArraySegment<byte> ContentData { get; }

        /// <summary>
        /// The tag of the asn1 element.
        /// </summary>
        public AsnTag Tag { get; }

        protected AsnElement(AsnTag tag, ArraySegment<byte> contentData)
        {
            ContentData = contentData;
            Tag = tag;
        }

        public override bool Equals(object obj) => Equals(obj as AsnElement);

        public override int GetHashCode() => ContentData.GetHashCode();

        public virtual bool Equals(AsnElement other)
        {
            if (ReferenceEquals(other, null))
            {
                return false;
            }
            if (ReferenceEquals(this, other))
            {
                return true;
            }

            //They aren't for the same element type. False. We need to make sure
            //that two tags with the same binary representation (like 1 and "true")
            //aren't considered the same.
            if (Tag != other.Tag)
            {
                return false;
            }

            //If the segements lengths are different, we know it to be false.
            if (ContentData.Count != other.ContentData.Count)
            {
                return false;
            }

            //The counts are the same, and one of them is zero, so zero-length segements
            //should be equal to each other.
            if (ContentData.Count == 0)
            {
                return true;
            }

            //We can't check purely by offset since two elements might be the same
            //but duplicated in the segment.

            //If the underlying byte array has reference equality, and the count and offset
            //are the same, we can assume they are equal without a byte-for-byte comparison.
            //The previous check ensures we have the same count up to here.
            if (ContentData.Offset == other.ContentData.Offset && ReferenceEquals(ContentData, other.ContentData))
            {
                return true;
            }

            //We have the same count, but we have different offsets in to potentially different
            //arrays. We need to compare bytes. We might be able to vectorize this later.
            for (var i = 0; i < ContentData.Count; i++)
            {
                var position = ContentData.Offset + i;
                if (ContentData.Array[position] != other.ContentData.Array[position])
                {
                    return false;
                }
            }
            //Byte comparison passed, return true.
            return true;
        }

        public override string ToString()
        {
            var builder = new StringBuilder();
            for (var i = 0; i < ContentData.Count; i++)
            {
                builder.AppendFormat("{0:X2}", ContentData.Array[ContentData.Offset + i]);
            }
            return builder.ToString();
        }
    }
}
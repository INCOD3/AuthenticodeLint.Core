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
        /// Gets the segement of data for the content of the element.
        /// </summary>
        public ArraySegment<byte> ContentData { get; private set; }

        /// <summary>
        /// Gets the segement of data for the entire element triplet.
        /// </summary>
        public ArraySegment<byte> ElementData { get; private set; }

        /// <summary>
        /// The tag of the asn1 element.
        /// </summary>
        public AsnTag Tag { get; private set; }

        protected AsnElement(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
        {
            ContentData = contentData;
            ElementData = elementData;
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

            return ElementData.Compare(other.ElementData) == 0;
        }

        public TType Reinterpret<TType>() where TType : AsnElement
        {
            //Yuck, but, yuck.
            return (TType)Activator.CreateInstance(typeof(TType), Tag, ContentData, ElementData);
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
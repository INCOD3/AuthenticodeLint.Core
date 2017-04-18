using System;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// An asn1 element. All elements inherit from this type.
    /// </summary>
    public abstract class AsnElement : IAsnElement, IEquatable<AsnElement>
    {
        private readonly int _headerSize;

        /// <summary>
        /// Gets the segement of data for the content of the element.
        /// </summary>
        public abstract ArraySegment<byte> ContentData { get; }

        /// <summary>
        /// Gets the segement of data for the entire element triplet.
        /// </summary>
        public abstract ArraySegment<byte> ElementData { get; }

        /// <summary>
        /// The tag of the asn1 element.
        /// </summary>
        public AsnTag Tag { get; private set; }

        protected AsnElement(AsnTag tag, int headerSize)
        {
            Tag = tag;
            _headerSize = headerSize;
        }

        public override bool Equals(object obj) => Equals(obj as AsnElement);

        public override int GetHashCode()
        {
            var builder = new HashCodeBuilder();
            foreach (var b in ElementData)
            {
                builder.Push(b);
            }
            return builder.GetHashCode();
        }

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

        /// <summary>
        /// Reinterprets the current element as another element type.
        /// This is useful for implicit tags.
        /// </summary>
        public virtual TType Reinterpret<TType>() where TType : AsnElement
        {
            //Yuck, but, yuck.
            return (TType)Activator.CreateInstance(typeof(TType), Tag, ElementData, (long?)ContentData.Count, _headerSize);
        }

        public override string ToString() => ContentData.Join();
    }
}
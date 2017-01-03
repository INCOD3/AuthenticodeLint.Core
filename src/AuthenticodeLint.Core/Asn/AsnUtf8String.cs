using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    /// <summary>
    /// An ASN encoded UTF8 string.
    /// </summary>
    /// <remarks>
    /// This creates a copy of the data to create a string.
    /// </remarks>
    public sealed class AsnUtf8String : AsnElement, IDirectoryString
    {
        /// <summary>
        /// The value of the string.
        /// </summary>
        /// <value>A string of the value.</value>
        public string Value { get; }
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="AsnUtf8String"/> with a segement of data.
        /// </summary>
        public AsnUtf8String(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength)
            : base(tag)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of Utf8String are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for Utf8String are not supported.");
            }
            try
            {
                ElementData = elementData.ConstrainWith(contentData, contentLength.Value);
                ContentData = contentData.Constrain(contentLength.Value);
                Value = AsnTextEncoding.UTF8.GetString(ContentData.Array, ContentData.Offset, ContentData.Count);
            }
            catch (Exception e) when (e is ArgumentException || e is DecoderFallbackException)
            {
                throw new AsnException("asn.1 UTF-8 string could not be decoded to a string.", e);
            }
        }

        public override string ToString() => Value;
    }

}
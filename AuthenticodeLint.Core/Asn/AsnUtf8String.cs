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

        /// <summary>
        /// Initializes a new instance of the <see cref="AsnUtf8String"/> with a segement of data.
        /// </summary>
        public AsnUtf8String(AsnTag tag, ArraySegment<byte> contentData) : base(tag, contentData)
        {
            Value = Encoding.UTF8.GetString(contentData.Array, contentData.Offset, contentData.Count);
        }

        public override string ToString() => Value;
    }

}
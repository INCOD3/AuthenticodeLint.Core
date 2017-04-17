using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnVisibleString : AsnElement, IDirectoryString
    {
        public string Value { get; }
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnVisibleString(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength, ulong? elementContentLength)
            : base(tag)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of VisibleString are not valid.");
            }
            if (contentLength == null || elementContentLength == null)
            {
                throw new AsnException("Undefined lengths for VisibleString are not supported.");
            }
            try
            {
                ElementData = elementData.Constrain(elementContentLength.Value);
                ContentData = contentData.Constrain(contentLength.Value);
                Value = AsnTextEncoding.ASCII.GetString(ContentData.Array, ContentData.Offset, ContentData.Count);
            }
            catch (Exception e) when (e is ArgumentException || e is DecoderFallbackException)
            {
                throw new AsnException("asn.1 VisibleString string could not be decoded into a string.", e);
            }
        }

        public override string ToString() => Value;
    }
}
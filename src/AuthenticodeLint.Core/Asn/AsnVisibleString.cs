using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnVisibleString : AsnElement, IDirectoryString
    {
        public string Value { get; }
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        private static Encoding Decoder { get; }

        static AsnVisibleString()
        {
            Decoder = Encoding.GetEncoding(Encoding.ASCII.CodePage, new EncoderExceptionFallback(), new DecoderExceptionFallback());
        }

        public AsnVisibleString(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength)
            : base(tag)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of VisibleString are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for VisibleString are not supported.");
            }
            try
            {
                ElementData = elementData.ConstrainWith(contentData, contentLength.Value);
                ContentData = contentData.Constrain(contentLength.Value);
                Value = Decoder.GetString(ContentData.Array, ContentData.Offset, ContentData.Count);
            }
            catch (Exception e) when (e is ArgumentException || e is DecoderFallbackException)
            {
                throw new AsnException("asn.1 VisibleString string could not be decoded into a string.", e);
            }
        }

        public override string ToString() => Value;
    }
}
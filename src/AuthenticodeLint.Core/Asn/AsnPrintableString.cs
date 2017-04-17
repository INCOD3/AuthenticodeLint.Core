using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnPrintableString : AsnElement, IDirectoryString
    {
        public string Value { get; }
        public override ArraySegment<byte> ContentData { get; }
        public override ArraySegment<byte> ElementData { get; }

        public AsnPrintableString(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData, ulong? contentLength, ulong headerSize)
            : base(tag)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of PrintableString are not valid.");
            }
            if (contentLength == null)
            {
                throw new AsnException("Undefined lengths for PrintableString are not supported.");
            }
            try
            {
                ElementData = elementData.Constrain(contentLength.Value + headerSize);
                ContentData = contentData.Constrain(contentLength.Value);
                Value = AsnTextEncoding.ASCII.GetString(ContentData.Array, ContentData.Offset, ContentData.Count);
            }
            catch (Exception e) when (e is ArgumentException || e is DecoderFallbackException)
            {
                throw new AsnException("asn.1 PrintableString failed to decode into a string.", e);
            }
        }

        public override string ToString() => Value;
    }
}

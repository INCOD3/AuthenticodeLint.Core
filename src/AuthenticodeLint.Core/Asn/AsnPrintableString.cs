using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnPrintableString : AsnElement, IDirectoryString
    {
        public string Value { get; }

        public AsnPrintableString(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
            : base(tag, contentData, elementData)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of PrintableString are not valid.");
            }
            try
            {
                Value = Encoding.ASCII.GetString(contentData.Array, contentData.Offset, contentData.Count);
            }
            catch (Exception e) when (e is ArgumentException || e is DecoderFallbackException)
            {
                throw new AsnException("asn.1 PrintableString failed to decode into a string.", e);
            }
        }

        public override string ToString() => Value;
    }
}

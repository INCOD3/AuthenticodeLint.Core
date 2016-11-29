using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{
    public sealed class AsnIA5String : AsnElement, IDirectoryString
    {
        public string Value { get; }

        public AsnIA5String(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
            : base(tag, contentData, elementData)
        {
            if (tag.Constructed)
            {
                throw new AsnException("Constructed forms of IA5String are not valid.");
            }
            try
            {
                Value = Encoding.ASCII.GetString(contentData.Array, contentData.Offset, contentData.Count);
            }
            catch (Exception e) when (e is ArgumentException || e is DecoderFallbackException)
            {
                throw new AsnException("asn.1 IA5 string could not be decoded into a string.", e);
            }
        }

        public override string ToString() => Value;
    }
}
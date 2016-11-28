using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{

    public sealed class AsnBmpString : AsnElement, IDirectoryString
    {
        public string Value { get; }

        public AsnBmpString(AsnTag tag, ArraySegment<byte> contentData, ArraySegment<byte> elementData)
            : base(tag, contentData, elementData)
        {
            try
            {
                Value = Encoding.BigEndianUnicode.GetString(contentData.Array, contentData.Offset, contentData.Count);
            }
            catch (Exception e) when (e is ArgumentException || e is DecoderFallbackException)
            {
                throw new AsnException("asn.1 BmpString failed to decode.", e);
            }
        }

        public override string ToString() => Value;
    }

}
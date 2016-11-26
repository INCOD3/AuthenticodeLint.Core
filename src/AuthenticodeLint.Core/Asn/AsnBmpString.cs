using System;
using System.Text;

namespace AuthenticodeLint.Core.Asn
{

    public sealed class AsnBmpString : AsnElement, IDirectoryString
    {
        public string Value { get; }

        public AsnBmpString(AsnTag tag, ArraySegment<byte> contentData) : base(tag, contentData)
        {
            Value = Encoding.Unicode.GetString(contentData.Array, contentData.Offset, contentData.Count);
        }

        public override string ToString() => Value;
    }

}
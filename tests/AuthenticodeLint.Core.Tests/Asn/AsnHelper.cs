using System;
using System.IO;
using System.Linq;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Tests
{
    public static class AsnHelper
    {
        public static AsnSequence ConstructSequence(params AsnElement[] elements)
        {
            var totalSize = elements.Sum(e => e.ElementData.Count);
            if (totalSize > 0x7F)
            {
                throw new NotSupportedException();
            }
            using (var memoryStream = new MemoryStream(totalSize + 2))
            {
                memoryStream.WriteByte(0x30);
                memoryStream.WriteByte((byte)totalSize);
                foreach(var element in elements)
                {
                    memoryStream.Write(element.ElementData.Array, element.ElementData.Offset, element.ElementData.Count);
                }
                return (AsnSequence)AsnDecoder.Decode(memoryStream.ToArray());
            }
        }
    }
}
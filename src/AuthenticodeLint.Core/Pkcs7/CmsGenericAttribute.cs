using System;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public class CmsGenericAttribute
    {
        public string AttributeId { get; protected set; }

        public CmsGenericAttribute(string attributeId, AsnSet content)
        {
            AttributeId = attributeId;
            Content = content.ElementData;
        }

        public ArraySegment<byte> Content { get; }
    }
}
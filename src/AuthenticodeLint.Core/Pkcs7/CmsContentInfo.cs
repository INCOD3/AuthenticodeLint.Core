using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.Pkcs7
{
    public sealed class CmsContentInfo
    {
        public string ContentType { get; }
        public AsnElement Content { get; }


        public CmsContentInfo(AsnSequence sequence)
        {
            var reader = new AsnConstructedReader(sequence);
            AsnObjectIdentifier contentType;
            AsnConstructed content;
            if (!reader.MoveNext(out contentType))
            {
                throw new Pkcs7Exception("Unable to read ContentType from ContentInfo.");
            }
            if (!reader.MoveNext(out content))
            {
                content = null;
            }
            ContentType = contentType.Value;
            Content = AsnReader.Read<AsnElement>(content);
            //System.Console.WriteLine(contentType);
            //System.Console.WriteLine(Content.GetType());
        }
    }
}
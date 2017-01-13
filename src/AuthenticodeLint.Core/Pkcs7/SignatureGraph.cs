using System.Collections.Generic;

namespace AuthenticodeLint.Core.Pkcs7
{
    public class SignatureGraph
    {
        public CmsSignature Signature { get; }
        public IReadOnlyList<CmsSignature> Children { get; }
    }

    public static class SignatureGraphExtensions
    {
        public static IEnumerable<CmsSignature> VisitAll(this CmsSignature signature)
        {
            if (signature.ContentType != ContentType.SignedData)
            {
                yield break;
            }
            var data = (CmsSignedData)signature.Content;
            foreach (var signer in data.SignerInfos)
            {
                foreach (var attribute in signer.UnauthenticatedAttributes)
                {
                    var nested = attribute as CmsNestedSignatureAttribute;
                    if (nested != null)
                    {
                        yield return nested.Signature;
                        var nestNest = nested.Signature.VisitAll();
                        foreach (var item in nestNest)
                        {
                            yield return item;
                        }
                    }
                }
            }
        }
    }
}
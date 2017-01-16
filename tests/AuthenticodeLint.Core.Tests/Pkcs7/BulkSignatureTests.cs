using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;
using AuthenticodeLint.Core.Pkcs7;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class BulkSignatureTests
    {
        [Theory]
        [MemberDataAttribute(nameof(GetSignatures))]
        public async Task ShouldVerifyAllSignatures(string path)
        {
            var signaturePath = PathHelper.CombineWithProjectPath(Path.Combine("signature", path));
            var signature = new CmsSignature(File.ReadAllBytes(signaturePath));
            Assert.True(await signature.VerifySignature(), "Root signature validation");
            foreach(var childSignature in signature.VisitAll())
            {
                Assert.True(await childSignature.VerifySignature(), "Child signature validation");
            }
        }

        public static IEnumerable<object[]> GetSignatures()
        {
            yield break;
        }
    }
}
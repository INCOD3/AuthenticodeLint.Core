using AuthenticodeLint.Core.x509;
using Xunit;

namespace AuthenticodeLint.Core.Tests
{
    public class x509ChainTests
    {
        [Fact]
        public void ShouldBuildAnHttpsCertChain()
        {
            var certificate = new x509Certificate("files/vcsjones.com.crt");
            var chainBuilder = x509Chain.Build(certificate);
            Assert.True(chainBuilder.Successful);
            Assert.NotEqual(0, chainBuilder.Chain.Count);
        }
    }
}
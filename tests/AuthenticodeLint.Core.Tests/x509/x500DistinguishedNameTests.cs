using DNC = System.Collections.Generic.Dictionary<string, string>;
using static AuthenticodeLint.Core.Asn.KnownOids.DistinguishedName;
using Xunit;
using AuthenticodeLint.Core.x509;

namespace AuthenticodeLint.Core.Tests
{
    public class x500DistinguishedNameTests
    {
        [Fact]
        public void ShouldCompareTwoSimpleComponentsSuccessfully()
        {
            var dn1 = DNHelper.TestDN(
                new DNC {
                    [id_at_countryName] = "US"
                },
                new DNC {
                    [id_at_commonName] = "test"
                }
            );

            var dn2 = DNHelper.TestDN(
                new DNC {
                    [id_at_countryName] = "US"
                },
                new DNC {
                    [id_at_commonName] = "test"
                }
            );

            var x5001 = new x500DistinguishedName(dn1);
            var x5002 = new x500DistinguishedName(dn2);
            Assert.True(x5001.Equals(x5002));
            Assert.True(x5001.Equals((object)x5002));
            Assert.True(((object)x5001).Equals((object)x5002));
            Assert.Equal(x5001.GetHashCode(), x5002.GetHashCode());
        }

        [Fact]
        public void ShouldCompareTwoComponentsAndFailWhenNotSameOrder()
        {
            var dn1 = DNHelper.TestDN(
                new DNC {
                    [id_at_countryName] = "US"
                },
                new DNC {
                    [id_at_commonName] = "test"
                }
            );

            var dn2 = DNHelper.TestDN(
                new DNC {
                    [id_at_commonName] = "test"
                },
                new DNC {
                    [id_at_countryName] = "US"
                }
            );

            var x5001 = new x500DistinguishedName(dn1);
            var x5002 = new x500DistinguishedName(dn2);
            Assert.False(x5001.Equals(x5002));
            Assert.False(x5001.Equals((object)x5002));
            Assert.False(((object)x5001).Equals((object)x5002));

            //They still get the same hash code because they fall in to the same
            //hash bucket as order as not accounted for with hash codes.
            Assert.Equal(x5001.GetHashCode(), x5002.GetHashCode());
        }

        [Fact]
        public void ShouldCompareTwoComponentsAndFailWithDifferentValues()
        {
            var dn1 = DNHelper.TestDN(
                new DNC {
                    [id_at_countryName] = "US"
                },
                new DNC {
                    [id_at_commonName] = "test"
                }
            );

            var dn2 = DNHelper.TestDN(
                new DNC {
                    [id_at_countryName] = "US"
                },
                new DNC {
                    [id_at_commonName] = "test2"
                }
            );

            var x5001 = new x500DistinguishedName(dn1);
            var x5002 = new x500DistinguishedName(dn2);
            Assert.False(x5001.Equals(x5002));
            Assert.False(x5001.Equals((object)x5002));
            Assert.False(((object)x5001).Equals((object)x5002));
            Assert.NotEqual(x5001.GetHashCode(), x5002.GetHashCode());
        }

        [Fact]
        public void ShouldNotConsiderOrderOfMulticomponentRids()
        {
            var dn1 = DNHelper.TestDN(
                new DNC {
                    [id_at_countryName] = "US",
                    [id_at_commonName] = "test"
                }
            );

            var dn2 = DNHelper.TestDN(
                new DNC {
                    [id_at_commonName] = "test",
                    [id_at_countryName] = "US"
                }
            );

            var x5001 = new x500DistinguishedName(dn1);
            var x5002 = new x500DistinguishedName(dn2);
            Assert.True(x5001.Equals(x5002));
            Assert.True(x5001.Equals((object)x5002));
            Assert.True(((object)x5001).Equals((object)x5002));
            Assert.Equal(x5001.GetHashCode(), x5002.GetHashCode());
        }



        [Fact]
        public void ShouldNotConsiderEqualWhenOneIsASuperSetOfTheOther()
        {
            var dn1 = DNHelper.TestDN(
                new DNC {
                    [id_at_countryName] = "US",
                    [id_at_commonName] = "test"
                }
            );

            var dn2 = DNHelper.TestDN(
                new DNC {
                    [id_at_commonName] = "test"
                }
            );

            var x5001 = new x500DistinguishedName(dn1);
            var x5002 = new x500DistinguishedName(dn2);
            Assert.False(x5001.Equals(x5002));
            Assert.False(x5001.Equals((object)x5002));
            Assert.False(((object)x5001).Equals((object)x5002));
            Assert.NotEqual(x5001.GetHashCode(), x5002.GetHashCode());

            Assert.False(x5002.Equals(x5001));
            Assert.False(x5002.Equals((object)x5001));
            Assert.False(((object)x5002).Equals((object)x5001));
            Assert.NotEqual(x5002.GetHashCode(), x5001.GetHashCode());
        }
    }
}
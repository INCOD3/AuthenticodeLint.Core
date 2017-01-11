using System.Collections.Generic;
using AuthenticodeLint.Core.Pkcs7;

namespace AuthenticodeLint.Core.x509
{
    public class x509CertificateCollection : List<x509Certificate>
    {
        public x509CertificateCollection(IReadOnlyList<x509Certificate> certificates)
        {
            foreach(var certificate in certificates)
            {
                this.Add(certificate);
            }
        }

        public x509Certificate FindSingleBy(CmsIssuerAndSerialNumber ias)
        {
            foreach (var certificate in this)
            {
                if (certificate.SerialNumber.Compare(ias.SerialNumber) != 0)
                {
                    //Serial numbers don't match.
                    continue;
                }
                if (certificate.Issuer.Equals(ias.Name))
                {
                    //The issuer and serial match. Return.
                    return certificate;
                }
            }
            return null;
        }
    }
}
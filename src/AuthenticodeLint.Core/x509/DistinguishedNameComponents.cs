using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
    internal static class DistinguishedNameComponents
    {
        public static string GetComponentName(string oid)
        {
            switch (oid)
            {
                case KnownOids.DistinguishedName.id_at_commonName:
                    return "CN";
                case KnownOids.DistinguishedName.id_at_countryName:
                    return "C";
                case KnownOids.DistinguishedName.id_at_localityName:
                    return "L";
                case KnownOids.DistinguishedName.id_at_organizationName:
                    return "O";
                case KnownOids.DistinguishedName.id_at_stateOrProvinceName:
                    return "ST";
                case KnownOids.DistinguishedName.id_at_organizationalUnitName:
                    return "OU";
                case KnownOids.DistinguishedName.e_mailAddress:
                    return "E";
                default:
                    return oid;
            }
        }
    }
}

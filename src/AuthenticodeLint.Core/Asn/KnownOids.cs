namespace AuthenticodeLint.Core.Asn
{
    public static class KnownOids
    {
        public static class Algorithms
        {
            public static class Digest
            {
                public const string sha1 = "1.3.14.3.2.26";
                public const string sha256 = "2.16.840.1.101.3.4.2.1";
            }

            public static class EcdsaCurves
            {
                public const string ecdsa_nist_p256 = "1.2.840.10045.3.1.7";
                public const string ecdsa_nist_p384 = "1.3.132.0.34";
                public const string ecdsa_nist_p521 = "1.3.132.0.35";
            }
        }

        public static class CmsPkcs9AttributeIds
        {
            public const string messageDigest = "1.2.840.113549.1.9.4";
            public const string opusInfo = "1.3.6.1.4.1.311.2.1.12";
            public const string nested_signature = "1.3.6.1.4.1.311.2.4.1";
            public const string rfc3161_timestamp = "1.3.6.1.4.1.311.3.3.1";
            public const string rsa_authenticode_timestamp = "1.2.840.113549.1.9.6";
            public const string signing_time = "1.2.840.113549.1.9.5";
            public const string signing_certificate = "1.2.840.113549.1.9.16.2.12";
            public const string contentType = "1.2.840.113549.1.9.3";
        }

        public static class CmsContentTypes
        {
            public const string signedData = "1.2.840.113549.1.7.2";
            public const string data = "1.2.840.113549.1.7.1";
            public const string envelopedData = "1.2.840.113549.1.7.3";
            public const string signedAndEnvelopedData = "1.2.840.113549.1.7.4";
            public const string digestedData = "1.2.840.113549.1.7.5";
            public const string encryptedData = "1.2.840.113549.1.7.6";
        }

        public static class CertificateExtensions
        {
            public const string id_ce_basicConsraints = "2.5.29.19";
            public const string id_ce_extKeyUsage = "2.5.29.37";
        }

        public static class DistinguishedName
        {
            public const string id_at_objectClass = "2.5.4.0";
            public const string id_at_aliasedEntryName = "2.5.4.1";
            public const string id_at_knowldgeinformation = "2.5.4.2";
            public const string id_at_commonName = "2.5.4.3";
            public const string id_at_surname = "2.5.4.4";
            public const string id_at_serialNumber = "2.5.4.5";
            public const string id_at_countryName = "2.5.4.6";
            public const string id_at_localityName = "2.5.4.7";
            public const string id_at_stateOrProvinceName = "2.5.4.8";
            public const string id_at_streetAddress = "2.5.4.9";
            public const string id_at_organizationName = "2.5.4.10";
            public const string id_at_organizationalUnitName = "2.5.4.11";
            public const string id_at_title = "2.5.4.12";
            public const string id_at_description = "2.5.4.13";
            public const string id_at_searchGuide = "2.5.4.14";
            public const string id_at_businessCategory = "2.5.4.15";
            public const string id_at_postalAddress = "2.5.4.16";
            public const string id_at_postalCode = "2.5.4.17";
            public const string id_at_postOfficeBox = "2.5.4.18";
            public const string id_at_physicalDeliveryOfficeName = "2.5.4.19";
            public const string id_at_telephoneNumber = "2.5.4.20";
            public const string id_at_telexNumber = "2.5.4.21";
            public const string id_at_teletexTerminalIdentifier = "2.5.4.22";
            public const string id_at_facsimileTelephoneNumber = "2.5.4.23";
            public const string id_at_x121Address = "2.5.4.24";
            public const string id_at_internationalISDNNumber = "2.5.4.25";
            public const string id_at_registeredAddress = "2.5.4.26";
            public const string id_at_destinationIndicator = "2.5.4.27";
            public const string id_at_preferredDeliveryMethod = "2.5.4.28";
            public const string id_at_presentationAddress = "2.5.4.29";
            public const string id_at_supportedApplicationContext = "2.5.4.30";
            public const string id_at_member = "2.5.4.31";
            public const string id_at_owner = "2.5.4.32";
            public const string id_at_roleOccupant = "2.5.4.33";
            public const string id_at_seeAlso = "2.5.4.34";
            public const string id_at_userPassword = "2.5.4.35";
            public const string id_at_userCertificate = "2.5.4.36";
            public const string id_at_cACertificate = "2.5.4.37";
            public const string id_at_authorityRevocationList = "2.5.4.38";
            public const string id_at_certificateRevocationList = "2.5.4.39";
            public const string id_at_crossCertificatePair = "2.5.4.40";
            public const string id_at_name = "2.5.4.41";
            public const string id_at_givenName = "2.5.4.42";
            public const string id_at_initials = "2.5.4.43";
            public const string id_at_generationQualifier = "2.5.4.44";
            public const string id_at_uniqueIdentifier = "2.5.4.45";
            public const string id_at_dnQualifier = "2.5.4.46";
            public const string id_at_enhancedSearchGuide = "2.5.4.47";
            public const string id_at_protocolInformation = "2.5.4.48";
            public const string id_at_distinguishedName = "2.5.4.49";
            public const string id_at_uniqueMember = "2.5.4.50";
            public const string id_at_houseIdentifier = "2.5.4.51";
            public const string id_at_supportedAlgorithms = "2.5.4.52";
            public const string id_at_deltaRevocationList = "2.5.4.53";
            public const string id_at_attributeCertificate = "2.5.4.58";
            public const string id_at_pseudonym = "2.5.4.65";
            public const string e_mailAddress = "1.2.840.113549.1.9.1";

        }
    }
}

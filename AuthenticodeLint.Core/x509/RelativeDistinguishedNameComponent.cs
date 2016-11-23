namespace AuthenticodeLint.Core.x509
{

    public class RelativeDistinguishedNameComponent
    {
        public string ObjectIdentifier { get; }
        public string Value { get; }
        public byte[] RawValue { get; }

        public RelativeDistinguishedNameComponent(string objectIdentifier, string value, byte[] rawValue)
        {
            ObjectIdentifier = objectIdentifier;
            Value = value;
            RawValue = rawValue;
        }
    }
}

namespace AuthenticodeLint.Core
{
    public class HashCodeBuilder
    {
        private int _built = 0;
        private int _counter = 0;

        public void Push(byte item)
        {
            _built ^= (int)item << ((_counter++ % 4) * 8);
        }

        public override int GetHashCode() => _built;
    }
}
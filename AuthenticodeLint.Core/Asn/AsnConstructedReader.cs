namespace AuthenticodeLint.Core.Asn
{

	internal class AsnConstructedReader
	{
		private AsnConstructed _sequence;
		private int _next = -1;

		public AsnConstructedReader(AsnConstructed sequence)
		{
			_sequence = sequence;
		}

		public AsnConstructedReader()
		{
		}

		public void ReTarget(AsnConstructed sequence)
		{
			_sequence = sequence;
			_next = -1;
		}

		public bool MoveNext<T>(out T item) where T : class, IAsnElement
		{
			if (_sequence == null || _next+1 >= _sequence.Count)
			{
				item = default(T);
				return false;
			}
			_next++;
			var next = _sequence[_next] as T;
			if (next == null)
			{
				item = default(T);
				return false;
			}
			item = next;
			return true;
		}

		public void Reset() => _next = -1;
	}
}

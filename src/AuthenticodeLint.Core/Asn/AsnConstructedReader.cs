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
            if (_sequence == null || _next + 1 >= _sequence.Count)
            {
                item = default(T);
                return false;
            }
            var next = _sequence[_next + 1] as T;
            if (next == null)
            {
                item = default(T);
                return false;
            }
            _next++;
            item = next;
            return true;
        }

        public bool MoveNext()
        {
            if (_sequence == null || _next + 1 >= _sequence.Count)
            {
                return false;
            }
            _next++;
            return true;
        }

        public bool CanMove() => _next < _sequence.Count - 1;

        public void Reset() => _next = -1;
    }

    internal static class AsnReader
    {
        public static T1 Read<T1>(AsnConstructed sequence)
            where T1 : class, IAsnElement
        {
            if (sequence.Count != 1)
            {
                throw new AsnException("Expected exactly one item in asn sequence.");
            }
            var item = sequence[0] as T1;
            if (item == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T1)} but was {item?.GetType()?.ToString() ?? "null" }.");
            }
            return item;
        }

        public static (T1, T2) Read<T1, T2>(AsnConstructed sequence)
            where T1 : class, IAsnElement
            where T2 : class, IAsnElement
        {
            if (sequence.Count != 2)
            {
                throw new AsnException("Expected exactly two items in asn sequence.");
            }
            var first = sequence[0] as T1;
            var second = sequence[1] as T2;
            if (first == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T1)} but was {first?.GetType()}.");
            }
            if (second == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T2)} but was {second?.GetType()}.");
            }
            return (first, second);
        }


        public static (T1, T2, T3) Read<T1, T2, T3>(AsnConstructed sequence)
            where T1 : class, IAsnElement
            where T2 : class, IAsnElement
            where T3 : class, IAsnElement
        {
            if (sequence.Count != 3)
            {
                throw new AsnException("Expected exactly three items in asn sequence.");
            }
            var first = sequence[0] as T1;
            var second = sequence[1] as T2;
            var third = sequence[3] as T3;
            if (second == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T1)} but was {first?.GetType()}.");
            }
            if (second == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T2)} but was {second?.GetType()}.");
            }
            if (third == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T3)} but was {third?.GetType()}.");
            }
            return (first, second, third);
        }
    }
}

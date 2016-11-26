using System;

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

    internal static class AsnContructedStaticReader
    {
        public static ValueTuple<T1> Read<T1>(AsnConstructed sequence)
            where T1 : class, IAsnElement
        {
            if (sequence.Count != 1)
            {
                throw new InvalidOperationException();
            }
            var item = sequence[0] as T1;
            if (item == null)
            {
                throw new InvalidOperationException();
            }
            return ValueTuple.Create(item);
        }


        public static ValueTuple<T1, T2> Read<T1, T2>(AsnConstructed sequence)
            where T1 : class, IAsnElement
            where T2 : class, IAsnElement
        {
            if (sequence.Count != 2)
            {
                throw new InvalidOperationException();
            }
            var item1 = sequence[0] as T1;
            var item2 = sequence[1] as T2;
            if (item1 == null || item2 == null)
            {
                throw new InvalidOperationException();
            }
            return ValueTuple.Create(item1, item2);
        }


        public static ValueTuple<T1, T2, T3> Read<T1, T2, T3>(AsnConstructed sequence)
            where T1 : class, IAsnElement
            where T2 : class, IAsnElement
            where T3 : class, IAsnElement
        {
            if (sequence.Count != 3)
            {
                throw new InvalidOperationException();
            }
            var item1 = sequence[0] as T1;
            var item2 = sequence[1] as T2;
            var item3 = sequence[3] as T3;
            if (item1 == null || item2 == null || item3 == null)
            {
                throw new InvalidOperationException();
            }
            return ValueTuple.Create(item1, item2, item3);
        }
    }
}

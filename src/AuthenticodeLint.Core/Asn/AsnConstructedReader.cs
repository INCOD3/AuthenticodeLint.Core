using System;
using System.Reflection;

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

        public bool MoveNext<T1, T2>(out ValueTuple<T1, T2> items)
            where T1 : class, IAsnElement
            where T2 : class, IAsnElement
        {
            if (_sequence == null || _next + 2 >= _sequence.Count)
            {
                items = default(ValueTuple<T1, T2>);
                return false;
            }
            var next1 = _sequence[_next + 1] as T1;
            var next2 = _sequence[_next + 2] as T2;
            if (next1 == null || next2 == null)
            {
                items = default(ValueTuple<T1, T2>);
                return false;
            }
            _next += 2;
            items = ValueTuple.Create(next1, next2);
            return true;
        }

        public bool MoveNext<T1, T2, T3>(out ValueTuple<T1, T2, T3> items)
            where T1 : class, IAsnElement
            where T2 : class, IAsnElement
            where T3 : class, IAsnElement
        {
            if (_sequence == null || _next + 3 >= _sequence.Count)
            {
                items = default(ValueTuple<T1, T2, T3>);
                return false;
            }
            var next1 = _sequence[_next + 1] as T1;
            var next2 = _sequence[_next + 2] as T2;
            var next3 = _sequence[_next + 3] as T3;
            if (next1 == null || next2 == null || next3 == null)
            {
                items = default(ValueTuple<T1, T2, T3>);
                return false;
            }
            _next += 3;
            items = ValueTuple.Create(next1, next2, next3);
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
        public static ValueTuple<T1> Read<T1>(AsnConstructed sequence)
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
            return ValueTuple.Create(item);
        }

        public static ValueTuple<T1, T2> Read<T1, T2>(AsnConstructed sequence)
            where T1 : class, IAsnElement
            where T2 : class, IAsnElement
        {
            if (sequence.Count != 2)
            {
                throw new AsnException("Expected exactly two items in asn sequence.");
            }
            var item1 = sequence[0] as T1;
            var item2 = sequence[1] as T2;
            if (item1 == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T1)} but was {item1?.GetType()}.");
            }
            if (item2 == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T2)} but was {item2?.GetType()}.");
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
                throw new AsnException("Expected exactly three items in asn sequence.");
            }
            var item1 = sequence[0] as T1;
            var item2 = sequence[1] as T2;
            var item3 = sequence[3] as T3;
            if (item2 == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T1)} but was {item1?.GetType()}.");
            }
            if (item2 == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T2)} but was {item2?.GetType()}.");
            }
            if (item3 == null)
            {
                throw new AsnException($"Item in sequence is not the expected type. Expected {typeof(T3)} but was {item3?.GetType()}.");
            }
            return ValueTuple.Create(item1, item2, item3);
        }

        private static ValueTuple<Type, bool> GetElementType<TType>()
        {
            var t1Type = typeof(TType);
            var t1TypeInfo = t1Type.GetTypeInfo();
            Type asnType;
            bool optional;
            if (typeof(AsnElement).GetTypeInfo().IsAssignableFrom(t1TypeInfo))
            {
                asnType = t1Type;
                optional = false;
            }
            else if (t1Type.IsConstructedGenericType && t1Type.GetGenericTypeDefinition() == typeof(AsnOptional<>))
            {
                asnType = t1Type.GenericTypeArguments[0];
                optional = true;
            }
            else
            {
                throw new AsnException("Unexpected, non-asn type.");
            }
            return ValueTuple.Create(asnType, optional);
        }
    }

    public sealed class AsnOptional<TElement>
        where TElement : class, IAsnElement
    {
        public TElement Element { get; }

        internal AsnOptional(AsnElement element)
        {
            Element = (TElement)(object)element;
        }
    }
}

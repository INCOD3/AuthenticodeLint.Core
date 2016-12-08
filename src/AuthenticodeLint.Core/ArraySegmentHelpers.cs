using System;
using System.Text;

namespace AuthenticodeLint.Core
{
    internal static class ArraySegmentHelpers
    {
        public static string Join(this ArraySegment<byte> ars)
        {
            var arr = new StringBuilder(ars.Count * 2);
            for (var i = 0; i < ars.Count; i++)
            {
                arr.AppendFormat(ars.Array[ars.Offset + i].ToString("X2"));
            }
            return arr.ToString();
        }

        public static T[] AsArray<T>(this ArraySegment<T> ars)
        {
            var arr = new T[ars.Count];
            for (var i = 0; i < ars.Count; i++)
            {
                arr[i] = ars.Array[ars.Offset + i];
            }
            return arr;
        }

        public static ArraySegment<T> Advance<T>(this ArraySegment<T> ars, int by)
        {
            return new ArraySegment<T>(ars.Array, ars.Offset + by, ars.Count - by);
        }

        public static int Compare<T>(this ArraySegment<T> ars, ArraySegment<T> other)
            where T : IComparable<T>
        {
            var compareCounts = ars.Count.CompareTo(other.Count);
            // If the counts are different, then off-the-bat we know it's false.
            if (compareCounts != 0)
            {
                return compareCounts;
            }
            // If the arrays have reference equality (the same array), and the offsets
            // are the same, then we know the array segements point to the same segement
            // in the same array. We already check for Count equality previously. This
            // Lets us know they segements are equal.
            if (ReferenceEquals(ars.Array, other.Array) && ars.Offset == other.Offset)
            {
                return 0;
            }

            for (var i = 0; i < ars.Count; i++)
            {
                var index = i + ars.Offset;
                var compare = ars.Array[index].CompareTo(other.Array[index]);
                if (compare != 0)
                {
                    return compare;
                }
            }

            return 0;
        }
    }
}

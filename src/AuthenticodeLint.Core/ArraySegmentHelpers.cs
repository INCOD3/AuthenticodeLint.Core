using System;
namespace AuthenticodeLint.Core
{
    internal static class ArraySegmentHelpers
    {
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
    }
}

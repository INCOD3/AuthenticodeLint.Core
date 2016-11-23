using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core.x509
{
	public class x500DistinguishedName : IReadOnlyList<RelativeDistinguishedName>
	{
		private readonly RelativeDistinguishedName[] _rdns;

		/// <summary>
		/// Creates a new Distinguished Name from an asn.1 RDNSequence.
		/// </summary>
		public x500DistinguishedName(AsnSequence sequence)
		{
			var sets = sequence.Cast<AsnSet>().ToArray();
			var rdns = new RelativeDistinguishedName[sets.Length];
			for (var i = 0; i < rdns.Length; i++)
			{
				var rdnSet = sets[i];
				rdns[i] = new RelativeDistinguishedName(rdnSet);
			}
			_rdns = rdns;
		}

		public RelativeDistinguishedName this[int index] => _rdns[index];

		public int Count => _rdns.Length;

		public IEnumerator<RelativeDistinguishedName> GetEnumerator()
		{
			foreach (var rdn in _rdns) yield return rdn;
		}

		IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();

		public override string ToString()
		{
			var builder = new StringBuilder();
			for (int i = 0; i < Count; i++)
			{
				var rdn = this[i];
				builder.Append(rdn);
				if (i < Count - 1)
				{
					builder.Append(", ");
				}
			}

			return builder.ToString();
		}
	}
}

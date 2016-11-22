using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AuthenticodeLint.Core.Asn;

namespace AuthenticodeLint.Core
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
			//TODO: this does not do nearly enough work, but simple for now.
			var builder = new StringBuilder();
			for (int i = 0; i < Count; i++)
			{
				var rdn = this[i];
				for (int j = 0; j < rdn.Count; j++)
				{
					var component = rdn[j];
					builder.Append(DistinguishedNameComponents.GetComponentName(component.ObjectIdentifier));
					builder.Append('=');
					builder.Append(component.Value);
					if (j < rdn.Count - 1)
					{
						builder.Append(" + ");
					}
				}
				if (i < Count - 1)
				{
					builder.Append(", ");
				}
			}

			return builder.ToString();
		}
	}

	public class RelativeDistinguishedName : IReadOnlyList<RelativeDistinguishedNameComponent>
	{
		private readonly IReadOnlyList<RelativeDistinguishedNameComponent> _components;
		
		public RelativeDistinguishedName(AsnSet asnSet)
		{
			var dnList = new List<RelativeDistinguishedNameComponent>();
			var seqReader = new AsnConstructedReader();
			foreach (var dn in asnSet.Cast<AsnSequence>())
			{
				seqReader.ReTarget(dn);
				AsnObjectIdentifier identifier;
				IDirectoryString value;
				if (!seqReader.MoveNext(out identifier) || !seqReader.MoveNext(out value))
				{
					throw new InvalidOperationException();
				}
				dnList.Add(new RelativeDistinguishedNameComponent(identifier.Value, value.Value, value.Data.ToArray()));
			}
			_components = dnList;
		}

		public RelativeDistinguishedNameComponent this[int index] => _components[index];

		public int Count => _components.Count;

		public IEnumerator<RelativeDistinguishedNameComponent> GetEnumerator() => _components.GetEnumerator();

		IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
	}

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

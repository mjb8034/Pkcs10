using System.Security.Cryptography;

namespace Pkcs10.Security.Cryptography;

/// <summary>
/// Specifies the matching behavior used when searching an OID collection.
/// </summary>
public enum OidMatchMode
{
    /// <summary>
    /// Specifies exact OID value matching.
    /// </summary>
    None,
    /// <summary>
    /// Enables subtree matching using a terminal <c>*</c> wildcard node.
    /// </summary>
    Wildcard
}

/// <summary>
/// Provides extension methods for searching <see cref="OidCollection"/>
/// instances by OID value.
/// </summary>
public static class OidCollectionExtensions
{
    /// <summary>
    /// Determines whether the collection contains an OID with the same
    /// <see cref="Oid.Value"/> as the specified OID.
    /// </summary>
    /// <param name="collection">The OID collection to search.</param>
    /// <param name="oid">The OID to locate.</param>
    /// <returns>
    /// <see langword="true"/> if the collection contains an OID with the
    /// same value; otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="collection"/>, <paramref name="oid"/>, or
    /// <see cref="Oid.Value"/> is <see langword="null"/>.
    /// </exception>
    public static bool Contains(this OidCollection collection, Oid oid)
    {
        return Contains(collection, oid, OidMatchMode.None);
    }

    /// <summary>
    /// Determines whether the collection contains an OID with the
    /// specified value.
    /// </summary>
    /// <param name="collection">The OID collection to search.</param>
    /// <param name="value">The OID value to locate.</param>
    /// <returns>
    /// <see langword="true"/> if the collection contains an OID with
    /// the specified value; otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="collection"/> or <paramref name="value"/>
    /// is <see langword="null"/>.
    /// </exception>
    public static bool Contains(this OidCollection collection, string value)
    {
        return Contains(collection, value, OidMatchMode.None);
    }

    /// <summary>
    /// Determines whether the collection contains an OID matching the
    /// specified OID according to the requested match mode.
    /// </summary>
    /// <param name="collection">The OID collection to search.</param>
    /// <param name="oid">The OID to locate.</param>
    /// <param name="matchMode">
    /// The matching behavior to use. When <see cref="OidMatchMode.Wildcard"/>
    /// is specified, a wildcard may be used as the complete final OID node
    /// to match any descendant of the specified OID.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the collection contains a matching OID;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="collection"/>, <paramref name="oid"/>, or
    /// <see cref="Oid.Value"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <see cref="OidMatchMode.Wildcard"/> is specified and the wildcard
    /// is not the complete final OID node.
    /// </exception>
    /// <exception cref="System.ComponentModel.InvalidEnumArgumentException">
    /// <paramref name="matchMode"/> is not a defined
    /// <see cref="OidMatchMode"/> value.
    /// </exception>
    public static bool Contains(this OidCollection collection, Oid oid, OidMatchMode matchMode)
    {
        ArgumentNullException.ThrowIfNull(oid);
        ArgumentNullException.ThrowIfNull(oid.Value);
        return Contains(collection, oid.Value, matchMode);
    }

    /// <summary>
    /// Determines whether the collection contains an OID matching the
    /// specified value according to the requested match mode.
    /// </summary>
    /// <param name="collection">The OID collection to search.</param>
    /// <param name="value">
    /// The OID value to locate. When <paramref name="matchMode"/> is
    /// <see cref="OidMatchMode.Wildcard"/>, the final OID node may be
    /// <c>*</c> to match any descendant of the preceding OID.
    /// </param>
    /// <param name="matchMode">
    /// The matching behavior to use.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if the collection contains a matching OID;
    /// otherwise, <see langword="false"/>.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="collection"/> or <paramref name="value"/> is
    /// <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <see cref="OidMatchMode.Wildcard"/> is specified and the wildcard
    /// is not the complete final OID node.
    /// </exception>
    /// <exception cref="System.ComponentModel.InvalidEnumArgumentException">
    /// <paramref name="matchMode"/> is not a defined
    /// <see cref="OidMatchMode"/> value.
    /// </exception>
    public static bool Contains(this OidCollection collection, string value, OidMatchMode matchMode)
    {
        // Validate arguments
        ArgumentNullException.ThrowIfNull(collection);
        ArgumentNullException.ThrowIfNull(value);
        if (matchMode is not OidMatchMode.Wildcard and not OidMatchMode.None)
        {
            throw new System.ComponentModel.InvalidEnumArgumentException(nameof(matchMode), (int)matchMode, typeof(OidMatchMode));
        }

        bool result = false;


        if (OidMatchMode.Wildcard == matchMode &&
            value.IndexOf('*', StringComparison.Ordinal) is int wildcardIndex &&
            wildcardIndex >= 0)
        {
            // IndexOf() returns the first '*', so requiring that
            // character to be last also guarantees uniqueness.
            if (wildcardIndex == value.Length - 1 &&
                wildcardIndex > 1 &&
                value[wildcardIndex - 1] == '.')
            {
                // Retain the '.' so the parent itself cannot match and
                // adjacent branches cannot produce false positives.
                //
                // "1.2.3.*" -> "1.2.3."
                string prefix = value[..^1];

                foreach (var item in collection)
                {
                    if (item.Value?.StartsWith(prefix, StringComparison.Ordinal) == true)
                    {
                        result = true;
                        break;
                    }
                }
            }
            else
            {
                throw new ArgumentException(
                    "The wildcard '*' must be the complete final OID node.",
                    nameof(value));
            }
        }
        else
        {
            foreach (var item in collection)
            {
                if (item.Value == value)
                {
                    result = true;
                    break;
                }
            }
        }

        return result;
    }
}

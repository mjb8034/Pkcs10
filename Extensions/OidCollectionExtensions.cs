using System.Security.Cryptography;

namespace Pkcs10.Security.Cryptography;

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
        ArgumentNullException.ThrowIfNull(collection);
        ArgumentNullException.ThrowIfNull(oid);
        ArgumentNullException.ThrowIfNull(oid.Value);

        return Contains(collection, oid.Value);
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
        ArgumentNullException.ThrowIfNull(collection);
        ArgumentNullException.ThrowIfNull(value);

        foreach (var item in collection)
        {
            if (item.Value == value)
                return true;
        }
        return false;
    }
}

using System.Net;
using System.Security.Cryptography;

namespace Pkcs10.Security.Cryptography.X509Certificates;

/// <summary>
/// Represents the supported values contained in an X.509
/// Subject Alternative Name extension.
/// </summary>
/// <param name="dns">The DNS names.</param>
/// <param name="ips">The IP addresses.</param>
/// <param name="emails">The email addresses.</param>
/// <param name="uris">The URI values.</param>
/// <param name="registeredIds">The registered-ID values.</param>
/// <remarks>
/// Supplied collections are retained rather than copied. Changes made to a
/// mutable collection retained by the caller are therefore reflected by this
/// instance. Collection properties cannot themselves be reassigned.
/// </remarks>
public sealed class SubjectAlternativeName(
    IReadOnlyCollection<string> dns,
    IReadOnlyCollection<IPAddress> ips,
    IReadOnlyCollection<string> emails,
    IReadOnlyCollection<string> uris,
    OidCollection registeredIds)
{
    /// <summary>
    /// Gets the DNS names.
    /// </summary>
    public IReadOnlyCollection<string> DnsNames { get; } = dns;

    /// <summary>
    /// Gets the IP addresses.
    /// </summary>
    public IReadOnlyCollection<IPAddress> IpAddresses { get; } = ips;

    /// <summary>
    /// Gets the email addresses.
    /// </summary>
    public IReadOnlyCollection<string> Emails { get; } = emails;

    /// <summary>
    /// Gets the URI values.
    /// </summary>
    public IReadOnlyCollection<string> Uris { get; } = uris;

    /// <summary>
    /// Gets the registered-ID values.
    /// </summary>
    /// <remarks>
    /// The collection reference is retained by this
    /// <see cref="SubjectAlternativeName"/> instance and may also be held
    /// by the caller. The property reference is read-only; however,
    /// <see cref="OidCollection"/> itself is mutable.
    /// </remarks>
    public OidCollection RegisteredIds { get; } = registeredIds;

    /// <inheritdoc/>
    public override string ToString()
    {
        return $"DNS={string.Join(",", DnsNames)}; " +
               $"IP={string.Join(",", IpAddresses)}; " +
               $"Email={string.Join(",", Emails)}; " +
               $"URI={string.Join(",", Uris)}; " +
               $"RegisteredID={string.Join(",", RegisteredIds.Cast<Oid>().Select(oid => oid.Value))}";
    }
}

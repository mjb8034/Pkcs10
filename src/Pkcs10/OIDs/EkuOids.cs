using System.Security.Cryptography;

namespace Pkcs10.Security.Cryptography;

/// <summary>
/// Provides object identifiers for commonly used X.509
/// extended key usages.
/// </summary>
public static class EkuOids
{
    /// <summary>Gets the TLS Web Server Authentication EKU OID.</summary>
    public static readonly Oid ServerAuthentication = Oid.FromOidValue("1.3.6.1.5.5.7.3.1", OidGroup.EnhancedKeyUsage);
    /// <summary>Gets the TLS Web Client Authentication EKU OID.</summary>
    public static readonly Oid ClientAuthentication = Oid.FromOidValue("1.3.6.1.5.5.7.3.2", OidGroup.EnhancedKeyUsage);
    /// <summary>Gets the Code Signing EKU OID.</summary>
    public static readonly Oid CodeSigning = Oid.FromOidValue("1.3.6.1.5.5.7.3.3", OidGroup.EnhancedKeyUsage);
    /// <summary>Gets the Email Protection EKU OID.</summary>
    public static readonly Oid EmailProtection = Oid.FromOidValue("1.3.6.1.5.5.7.3.4", OidGroup.EnhancedKeyUsage);
    /// <summary>Gets the Time Stamping EKU OID.</summary>
    public static readonly Oid TimeStamping = Oid.FromOidValue("1.3.6.1.5.5.7.3.8", OidGroup.EnhancedKeyUsage);
    /// <summary>Gets the OCSP Signing EKU OID.</summary>
    public static readonly Oid OcspSigning = Oid.FromOidValue("1.3.6.1.5.5.7.3.9", OidGroup.EnhancedKeyUsage);
}

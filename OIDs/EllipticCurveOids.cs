namespace Pkcs10.Security.Cryptography;

/// <summary>
/// Provides object identifier values for commonly used
/// elliptic curves.
/// </summary>
public static class EllipticCurveOids
{
    // Named elliptic curves
    /// <summary>OID for the NIST P-256 (secp256r1) elliptic curve.</summary>
    public const string Secp256r1 = "1.2.840.10045.3.1.7";
    /// <summary>OID for the NIST P-384 (secp384r1) elliptic curve.</summary>
    public const string Secp384r1 = "1.3.132.0.34";
    /// <summary>OID for the NIST P-521 (secp521r1) elliptic curve.</summary>
    public const string Secp521r1 = "1.3.132.0.35";
}
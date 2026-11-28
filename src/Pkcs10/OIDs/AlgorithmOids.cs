using System.Diagnostics.CodeAnalysis;

namespace Pkcs10.Security.Cryptography;

/// <summary>
/// Provides object identifier values for cryptographic algorithms
/// recognized by this library.
/// </summary>
public static class AlgorithmOids
{
    // Public key algorithms
    /// <summary>
    /// Identifies the RSA public-key algorithm.
    /// </summary>
    public const string RsaEncryption = "1.2.840.113549.1.1.1";
    /// <summary>
    /// Identifies the elliptic curve public-key algorithm.
    /// </summary>
    public const string EcPublicKey = "1.2.840.10045.2.1";

    // Hash algorithms
    /// <summary>
    /// Identifies the SHA-1 hash algorithm.
    /// </summary>
    public const string Sha1 = "1.3.14.3.2.26";
    /// <summary>
    /// Identifies the SHA-224 hash algorithm.
    /// </summary>
    public const string Sha224 = "2.16.840.1.101.3.4.2.4";
    /// <summary>
    /// Identifies the SHA-256 hash algorithm.
    /// </summary>
    public const string Sha256 = "2.16.840.1.101.3.4.2.1";
    /// <summary>
    /// Identifies the SHA-384 hash algorithm.
    /// </summary>
    public const string Sha384 = "2.16.840.1.101.3.4.2.2";
    /// <summary>
    /// Identifies the SHA-512 hash algorithm.
    /// </summary>
    public const string Sha512 = "2.16.840.1.101.3.4.2.3";
    /// <summary>
    /// Identifies the SHA-512/224 hash algorithm.
    /// </summary>
    [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Underscore separates the algorithm family from its output size.")]
    public const string Sha512_224 = "2.16.840.1.101.3.4.2.5";
    /// <summary>
    /// Identifies the SHA-512/256 hash algorithm.
    /// </summary>
    [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Underscore separates the algorithm family from its output size.")]
    public const string Sha512_256 = "2.16.840.1.101.3.4.2.6";
    /// <summary>
    /// Identifies the SHA3-224 hash algorithm.
    /// </summary>
    [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Underscore separates the algorithm family from its output size.")]
    public const string Sha3_224 = "2.16.840.1.101.3.4.2.7";
    /// <summary>
    /// Identifies the SHA3-256 hash algorithm.
    /// </summary>
    [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Underscore separates the algorithm family from its output size.")]
    public const string Sha3_256 = "2.16.840.1.101.3.4.2.8";
    /// <summary>
    /// Identifies the SHA3-384 hash algorithm.
    /// </summary>
    [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Underscore separates the algorithm family from its output size.")]
    public const string Sha3_384 = "2.16.840.1.101.3.4.2.9";
    /// <summary>
    /// Identifies the SHA3-512 hash algorithm.
    /// </summary>
    [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Underscore separates the algorithm family from its output size.")]
    public const string Sha3_512 = "2.16.840.1.101.3.4.2.10";

    // Mask generation algorithms
    /// <summary>
    /// Identifies the MGF1 mask generation algorithm.
    /// </summary>
    public const string Mgf1 = "1.2.840.113549.1.1.8";

    // RSA signature algorithms
    /// <summary>
    /// Identifies the RSASSA-PSS signature algorithm.
    /// </summary>
    public const string RsaPss = "1.2.840.113549.1.1.10";

    /// <summary>
    /// Identifies the RSA PKCS #1 v1.5 signature algorithm using SHA-1.
    /// </summary>
    public const string Sha1WithRsaEncryption = "1.2.840.113549.1.1.5";
    /// <summary>
    /// Identifies the RSA PKCS #1 v1.5 signature algorithm using SHA-224.
    /// </summary>
    public const string Sha224WithRsaEncryption = "1.2.840.113549.1.1.14";
    /// <summary>
    /// Identifies the RSA PKCS #1 v1.5 signature algorithm using SHA-256.
    /// </summary>
    public const string Sha256WithRsaEncryption = "1.2.840.113549.1.1.11";
    /// <summary>
    /// Identifies the RSA PKCS #1 v1.5 signature algorithm using SHA-384.
    /// </summary>
    public const string Sha384WithRsaEncryption = "1.2.840.113549.1.1.12";
    /// <summary>
    /// Identifies the RSA PKCS #1 v1.5 signature algorithm using SHA-512.
    /// </summary>
    public const string Sha512WithRsaEncryption = "1.2.840.113549.1.1.13";
    /// <summary>
    /// Identifies the RSA PKCS #1 v1.5 signature algorithm using SHA-512/224.
    /// </summary>
    [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Underscore separates the algorithm family from its output size.")]
    public const string Sha512_224WithRsaEncryption = "1.2.840.113549.1.1.15";
    /// <summary>
    /// Identifies the RSA PKCS #1 v1.5 signature algorithm using SHA-512/256.
    /// </summary>
    [SuppressMessage("Naming", "CA1707:Identifiers should not contain underscores", Justification = "Underscore separates the algorithm family from its output size.")]
    public const string Sha512_256WithRsaEncryption = "1.2.840.113549.1.1.16";

    // ECDSA signature algorithms
    /// <summary>
    /// Identifies the ECDSA signature algorithm using SHA-224.
    /// </summary>
    public const string EcdsaWithSha224 = "1.2.840.10045.4.3.1";
    /// <summary>
    /// Identifies the ECDSA signature algorithm using SHA-256.
    /// </summary>
    public const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";
    /// <summary>
    /// Identifies the ECDSA signature algorithm using SHA-384.
    /// </summary>
    public const string EcdsaWithSha384 = "1.2.840.10045.4.3.3";
    /// <summary>
    /// Identifies the ECDSA signature algorithm using SHA-512.
    /// </summary>
    public const string EcdsaWithSha512 = "1.2.840.10045.4.3.4";

    // ML-DSA PQC algorithms
    /// <summary>
    /// Identifies the ML-DSA-44 algorithm.
    /// </summary>
    public const string MLDsa44 = "2.16.840.1.101.3.4.3.17";
    /// <summary>
    /// Identifies the ML-DSA-65 algorithm.
    /// </summary>
    public const string MLDsa65 = "2.16.840.1.101.3.4.3.18";
    /// <summary>
    /// Identifies the ML-DSA-87 algorithm.
    /// </summary>
    public const string MLDsa87 = "2.16.840.1.101.3.4.3.19";

    /// <summary>
    /// Determines whether the specified OID identifies an RSA public-key algorithm
    /// recognized by this library.
    /// </summary>
    /// <param name="oidValue">
    /// The dotted-decimal OID value to examine.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="oidValue"/> identifies a
    /// recognized RSA public-key algorithm; otherwise, <see langword="false"/>.
    /// </returns>
    public static bool IsRsa(string? oidValue)
    {
        return oidValue is
            RsaEncryption or
            RsaPss;
    }

    /// <summary>
    /// Determines whether the specified OID identifies an ML-DSA algorithm.
    /// </summary>
    /// <param name="oidValue">
    /// The dotted-decimal OID value to examine.
    /// </param>
    /// <returns>
    /// <see langword="true"/> if <paramref name="oidValue"/> identifies
    /// ML-DSA-44, ML-DSA-65, or ML-DSA-87; otherwise,
    /// <see langword="false"/>.
    /// </returns>
    public static bool IsMLDsa(string? oidValue)
    {
        return oidValue is
            MLDsa44 or
            MLDsa65 or
            MLDsa87;
    }
}
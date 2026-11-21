namespace Pkcs10.Security.Cryptography;

/// <summary>
/// Provides object identifier values for cryptographic algorithms
/// supported by this library.
/// </summary>
public static class AlgorithmOids
{
    // Public key algorithms
    /// <summary>OID for RSA encryption.</summary>
    public const string RsaEncryption = "1.2.840.113549.1.1.1";
    /// <summary>OID for an elliptic curve public key.</summary>
    public const string EcPublicKey = "1.2.840.10045.2.1";

    // RSA signature algorithms
    /// <summary>OID for SHA-256 with RSA encryption.</summary>
    public const string Sha256WithRsaEncryption = "1.2.840.113549.1.1.11";
    /// <summary>OID for SHA-384 with RSA encryption.</summary>
    public const string Sha384WithRsaEncryption = "1.2.840.113549.1.1.12";
    /// <summary>OID for SHA-512 with RSA encryption.</summary>
    public const string Sha512WithRsaEncryption = "1.2.840.113549.1.1.13";

    // ECDSA signature algorithms
    /// <summary>OID for ECDSA with SHA-224.</summary>
    public const string EcdsaWithSha224 = "1.2.840.10045.4.3.1";
    /// <summary>OID for ECDSA with SHA-256.</summary>
    public const string EcdsaWithSha256 = "1.2.840.10045.4.3.2";
    /// <summary>OID for ECDSA with SHA-384.</summary>
    public const string EcdsaWithSha384 = "1.2.840.10045.4.3.3";
    /// <summary>OID for ECDSA with SHA-512.</summary>
    public const string EcdsaWithSha512 = "1.2.840.10045.4.3.4";

    // ML-DSA PQC algorithms
    /// <summary>OID for ML-DSA-44.</summary>
    public const string MLDsa44 = "2.16.840.1.101.3.4.3.17";
    /// <summary>OID for ML-DSA-65.</summary>
    public const string MLDsa65 = "2.16.840.1.101.3.4.3.18";
    /// <summary>OID for ML-DSA-87.</summary>
    public const string MLDsa87 = "2.16.840.1.101.3.4.3.19";

    /// <summary>
    /// Determines whether an OID identifies an ML-DSA algorithm.
    /// </summary>
    /// <param name="oidValue">The OID value to examine, or <see langword="null"/>.</param>
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
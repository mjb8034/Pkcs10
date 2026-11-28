using Pkcs10.Security.Cryptography;
using Pkcs10.Security.Cryptography.X509Certificates;
using System.Formats.Asn1;
using System.Globalization;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using static Pkcs10.Security.Cryptography.Utilities;

namespace Pkcs10;

/// <summary>
/// Specifies the format used to produce a summary of a PKCS #10
/// certification request.
/// </summary>
public enum Pkcs10Format
{
    /// <summary>
    /// Produces a human-readable text summary.
    /// </summary>
    Text,

    /// <summary>
    /// Produces a JSON-formatted summary.
    /// </summary>
    Json,

    /// <summary>
    /// Produces a compact single-line summary.
    /// </summary>
    Compact,

    /// <summary>
    /// Produces output resembling the OpenSSL PKCS #10
    /// request display format.
    /// </summary>
    OpenSsl
}

/// <summary>
/// Represents a parsed and validated PKCS #10 certification request.
/// </summary>
public sealed class Pkcs10CertificationRequest
{
    /// <summary>
    /// Gets the certificate request represented using the
    /// .NET cryptography object model.
    /// </summary>
    public CertificateRequest Request { get; }

    /// <summary>
    /// Gets the signature algorithm specified by the
    /// PKCS #10 certification request.
    /// </summary>
    public Oid SignatureAlgorithm { get; }

    /// <summary>
    /// Gets the signature value from the PKCS #10
    /// certification request.
    /// </summary>
    public ReadOnlyMemory<byte> Signature { get; }

    /// <summary>
    /// Gets the DER-encoded signature algorithm parameters,
    /// or <see langword="null"/> if no parameters are present.
    /// </summary>
    public ReadOnlyMemory<byte>? SignatureAlgorithmParameters { get; }

    private readonly OidCollection? _knownOids;
    private static readonly JsonSerializerOptions JsonSummaryOptions = new()
    {
        WriteIndented = true
    };

    private Pkcs10CertificationRequest(
        CertificateRequest request,
        Oid signatureAlgorithm,
        ReadOnlyMemory<byte> signature,
        ReadOnlyMemory<byte>? signatureAlgorithmParameters,
        OidCollection? knownOids
    )
    {
        Request = request;
        SignatureAlgorithm = signatureAlgorithm;
        Signature = signature.ToArray();
        SignatureAlgorithmParameters = signatureAlgorithmParameters?.ToArray();
        _knownOids = knownOids;
    }

    /// <summary>
    /// Parses and validates a DER-encoded PKCS #10 certification request.
    /// </summary>
    /// <param name="der">
    /// The DER-encoded PKCS #10 certification request.
    /// </param>
    /// <param name="knownOids">
    /// Optional caller-owned OID instances used when resolving OIDs decoded
    /// by this class or its convenience views. Matching OIDs reuse the supplied
    /// instance, preserving caller-defined metadata such as
    /// <see cref="Oid.FriendlyName"/> and object identity.
    /// </param>
    /// <returns>
    /// The parsed PKCS #10 certification request.
    /// </returns>
    /// <remarks>
    /// Supported signature algorithms include RSA PKCS #1 v1.5,
    /// RSA-PSS, ECDSA, and, on supported target frameworks and
    /// platforms, ML-DSA.
    ///
    /// RSA-PSS parameters are decoded before the request is loaded.
    /// Supported RSA-PSS configurations require the MGF1 hash to match the message hash,
    /// the salt length to equal the hash output length,
    /// and the trailer field to be 1.
    /// 
    /// Support for a particular hash algorithm may additionally
    /// depend on the underlying .NET cryptography provider.
    /// 
    /// When an OID resolved by this class or its convenience views has the same value as an
    /// OID supplied in <paramref name="knownOids"/>, the supplied <see cref="Oid"/>
    /// instance is used directly rather than copied. This preserves caller-defined
    /// metadata, such as <see cref="Oid.FriendlyName"/>, as well as object identity.
    ///
    /// OID instances supplied through <paramref name="knownOids"/> remain owned by
    /// the caller. The parser does not modify them. Because the same instances may
    /// be referenced by the returned request, subsequent modifications made by the
    /// caller are observable through the parsed request.
    ///
    /// OIDs that do not match an entry in <paramref name="knownOids"/> are
    /// represented by the OID instances supplied by the underlying .NET
    /// cryptography APIs, or when decoded directly by this class, by newly created
    /// <see cref="Oid"/> instances.
    /// </remarks>
    /// <exception cref="NotSupportedException">
    /// The certification request uses an unsupported signature algorithm or an unsupported signature algorithm configuration.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// The certification request is malformed, contains trailing data,
    /// contains an invalid signature encoding or invalid signature algorithm
    /// parameters, or fails cryptographic validation.
    /// </exception>
    public static Pkcs10CertificationRequest FromDer(ReadOnlyMemory<byte> der, OidCollection? knownOids = default)
    {
        try
        {
            var reader = new AsnReader(der, AsnEncodingRules.DER);

            // CertificationRequest ::= SEQUENCE {
            //     certificationRequestInfo CertificationRequestInfo,
            //     signatureAlgorithm       AlgorithmIdentifier,
            //     signature                BIT STRING
            // }
            var requestSequence = reader.ReadSequence();
            reader.ThrowIfNotEmpty();

            // CertificateRequest.LoadSigningRequest parses and validates this.
            requestSequence.ReadEncodedValue();

            // Signature Algorithm
            ReadOnlyMemory<byte>? signatureAlgorithmParameters = null;

            var signatureAlgorithmSequence = requestSequence.ReadSequence();
            Oid signatureAlgorithm = ResolveOid(signatureAlgorithmSequence.ReadObjectIdentifier(), knownOids);
            if (signatureAlgorithmSequence.HasData)
            {
                signatureAlgorithmParameters = signatureAlgorithmSequence.ReadEncodedValue();
            }
            signatureAlgorithmSequence.ThrowIfNotEmpty();

            // signature BIT STRING
            if (!requestSequence.TryReadPrimitiveBitString(out int unusedBitCount, out ReadOnlyMemory<byte> signature))
            {
                throw new CryptographicException("The CSR signature must use a primitive BIT STRING encoding.");
            }
            if (0 != unusedBitCount)
            {
                throw new CryptographicException("The CSR signature contains unused bits.");
            }
            requestSequence.ThrowIfNotEmpty();

            var signingConfiguration = GetSigningConfiguration(signatureAlgorithm, signatureAlgorithmParameters);

            var request = CertificateRequest.LoadSigningRequest(
                der.Span,
                signingConfiguration.HashAlgorithmName,
                out int bytesConsumed,
                CertificateRequestLoadOptions.UnsafeLoadCertificateExtensions,
                signingConfiguration.RSASignaturePadding
            );
            if (bytesConsumed != der.Length)
            {
                throw new CryptographicException("The CSR contains trailing data.");
            }

            return new Pkcs10CertificationRequest(
                request,
                signatureAlgorithm,
                signature,
                signatureAlgorithmParameters,
                knownOids
            );
        }
        catch (AsnContentException ex)
        {
            throw new CryptographicException(
                "The PKCS #10 certification request contains invalid ASN.1 data.",
                ex);
        }
    }

    private static (HashAlgorithmName HashAlgorithmName, RSASignaturePadding RSASignaturePadding) GetRsaPssSigningConfiguration(ReadOnlyMemory<byte> encodedParameters)
    {
        RsaPssParameters parameters = RsaPssParametersDecoder.Decode(encodedParameters);

        if (parameters.HashAlgorithm != parameters.MgfHashAlgorithm)
        {
            throw new NotSupportedException("RSA-PSS with an MGF1 hash that differs from the message hash is not supported.");
        }

        int expectedSaltLength = GetHashSizeInBytes(parameters.HashAlgorithm);
        if (parameters.SaltLength != expectedSaltLength)
        {
            throw new NotSupportedException($"RSA-PSS salt length {parameters.SaltLength} is not supported. The salt length must equal the hash output length of {expectedSaltLength} bytes.");
        }
        if (parameters.TrailerField != 1)
        {
            throw new NotSupportedException("Only RSA-PSS trailer field 1 is supported.");
        }

        return (parameters.HashAlgorithm, RSASignaturePadding.Pss);
    }

    private static int GetHashSizeInBytes(
        HashAlgorithmName hashAlgorithm)
    {
        if (HashAlgorithmName.SHA1 == hashAlgorithm)
            return SHA1.HashSizeInBytes;

        if (HashAlgorithmName.SHA256 == hashAlgorithm)
            return SHA256.HashSizeInBytes;

        if (HashAlgorithmName.SHA384 == hashAlgorithm)
            return SHA384.HashSizeInBytes;

        if (HashAlgorithmName.SHA512 == hashAlgorithm)
            return SHA512.HashSizeInBytes;

#if NET8_0_OR_GREATER
        if (HashAlgorithmName.SHA3_256 == hashAlgorithm)
            return SHA3_256.HashSizeInBytes;

        if (HashAlgorithmName.SHA3_384 == hashAlgorithm)
            return SHA3_384.HashSizeInBytes;

        if (HashAlgorithmName.SHA3_512 == hashAlgorithm)
            return SHA3_512.HashSizeInBytes;
#else
        if (new HashAlgorithmName("SHA3-256") == hashAlgorithm)
            return 32;

        if (new HashAlgorithmName("SHA3-384") == hashAlgorithm)
            return 48;

        if (new HashAlgorithmName("SHA3-512") == hashAlgorithm)
            return 64;
#endif

        // Algorithms for which the target BCL has no concrete hash class.
        return hashAlgorithm.Name switch
        {
            "SHA224" => 28,
            "SHA512/224" => 28,
            "SHA512/256" => 32,
            "SHA3-224" => 28,

            _ => throw new NotSupportedException(
                $"Unsupported RSA-PSS hash algorithm: {hashAlgorithm.Name}")
        };
    }

    private static (HashAlgorithmName HashAlgorithmName, RSASignaturePadding? RSASignaturePadding) GetSigningConfiguration(Oid signatureAlgorithm, ReadOnlyMemory<byte>? signatureAlgorithmParameters)
    {
        if (AlgorithmOids.RsaPss == signatureAlgorithm.Value)
        {
            if (signatureAlgorithmParameters is null)
            {
                throw new CryptographicException("RSA-PSS signature algorithm parameters are missing.");
            }

            return GetRsaPssSigningConfiguration(signatureAlgorithmParameters.Value);
        }

        // Map algorithm OID to crypto
        return signatureAlgorithm.Value switch
        {
            AlgorithmOids.Sha1WithRsaEncryption => (HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1),
            AlgorithmOids.Sha224WithRsaEncryption => (new HashAlgorithmName("SHA224"), RSASignaturePadding.Pkcs1),
            AlgorithmOids.Sha256WithRsaEncryption => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            AlgorithmOids.Sha384WithRsaEncryption => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            AlgorithmOids.Sha512WithRsaEncryption => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            AlgorithmOids.Sha512_224WithRsaEncryption => (new HashAlgorithmName("SHA512/224"), RSASignaturePadding.Pkcs1),
            AlgorithmOids.Sha512_256WithRsaEncryption => (new HashAlgorithmName("SHA512/256"), RSASignaturePadding.Pkcs1),
            AlgorithmOids.EcdsaWithSha224 => (new HashAlgorithmName("SHA224"), null),
            AlgorithmOids.EcdsaWithSha256 => (HashAlgorithmName.SHA256, null),
            AlgorithmOids.EcdsaWithSha384 => (HashAlgorithmName.SHA384, null),
            AlgorithmOids.EcdsaWithSha512 => (HashAlgorithmName.SHA512, null),
#if NET10_0_OR_GREATER
            AlgorithmOids.MLDsa44 or
            AlgorithmOids.MLDsa65 or
            AlgorithmOids.MLDsa87 => (default, null),
#endif
            _ => throw new NotSupportedException($"Unsupported signature algorithm OID: {signatureAlgorithm.Value}")
        };
    }

    private static string ToHex(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return string.Empty;

        char[] characters = new char[checked((data.Length * 3) - 1)];

        const string HexDigits = "0123456789ABCDEF";

        int position = 0;

        for (int i = 0; i < data.Length; i++)
        {
            if (i != 0)
                characters[position++] = ':';

            byte value = data[i];

            characters[position++] = HexDigits[value >> 4];
            characters[position++] = HexDigits[value & 0x0F];
        }

        return new string(characters);
    }

    /// <summary>
    /// Returns a formatted summary of this PKCS #10 certification
    /// request using the specified output format.
    /// </summary>
    /// <param name="format">
    /// The format to use when producing the summary.
    /// </param>
    /// <returns>
    /// A string containing the formatted summary of the certification request.
    /// </returns>
    /// <exception cref="ArgumentOutOfRangeException">
    /// <paramref name="format"/> is not a defined
    /// <see cref="Pkcs10Format"/> value.
    /// </exception>
    public string ToString(Pkcs10Format format)
    {
        return format switch
        {
            Pkcs10Format.Text => ToTextSummary(),
            Pkcs10Format.Json => ToJsonSummary(),
            Pkcs10Format.Compact => ToCompactSummary(),
            Pkcs10Format.OpenSsl => ToOpenSslStyle(),
            _ => throw new ArgumentOutOfRangeException(nameof(format), format, "Unsupported PKCS #10 output format.")
        };
    }

    private string ToTextSummary()
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("----- PKCS #10 Certification Request -----");
        sb.AppendLine(CultureInfo.InvariantCulture, $"Subject: {Request.SubjectName.Name}");

        sb.AppendLine();
        sb.AppendLine("Public Key:");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  Algorithm OID: {FormatOid(Request.PublicKey.Oid)}");

        try
        {
            var publicKey = GetPublicKeyInfo();

            sb.AppendLine(CultureInfo.InvariantCulture, $"  Type: {publicKey.Type}");
            if (publicKey.KeySize is int keySize)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"  Key Size: {keySize} bits");
            }
        }
        catch (Exception ex) when (ex is
            CryptographicException or
            PlatformNotSupportedException
        )
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"  [Error decoding key: {ex.Message}]");
        }

        sb.AppendLine();
        sb.AppendLine("Signature:");
        sb.AppendLine(CultureInfo.InvariantCulture, $"  Algorithm OID: {FormatOid(SignatureAlgorithm)}");

        var san = Request.SubjectAlternativeName?.ToSubjectAlternativeName(_knownOids);
        if (san is not null)
        {
            sb.AppendLine();
            sb.AppendLine("Subject Alternative Name:");

            if (san.DnsNames.Count > 0)
                sb.AppendLine(CultureInfo.InvariantCulture, $"  DNS: {String.Join(", ", san.DnsNames)}");

            if (san.IpAddresses.Count > 0)
                sb.AppendLine(CultureInfo.InvariantCulture, $"  IP: {String.Join(", ", san.IpAddresses)}");

            if (san.Emails.Count > 0)
                sb.AppendLine(CultureInfo.InvariantCulture, $"  Email: {String.Join(", ", san.Emails)}");

            if (san.Uris.Count > 0)
                sb.AppendLine(CultureInfo.InvariantCulture, $"  URI: {String.Join(", ", san.Uris)}");

            if (san.RegisteredIds.Count > 0)
            {
                sb.AppendLine("  Registered IDs:");
                foreach (var oid in san.RegisteredIds)
                {
                    sb.AppendLine(CultureInfo.InvariantCulture, $"    {FormatOid(oid)}");
                }
            }
        }

        var extendedKeyUsage = Request.ExtendedKeyUsage;
        if (extendedKeyUsage.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("Extended Key Usage:");
            foreach (var oid in extendedKeyUsage)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"  {FormatOid(oid)}");
            }
        }


        return sb.ToString();
    }

    private string ToJsonSummary()
    {
        var publicKey = GetPublicKeyInfo();
        var san = Request.SubjectAlternativeName?.ToSubjectAlternativeName(_knownOids);
        var obj = new
        {
            Subject = Request.SubjectName.Name,
            PublicKey = new
            {
                AlgorithmOid = Request.PublicKey.Oid.Value,
                KeyType = publicKey.Type,
                KeySize = publicKey.KeySize,
            },
            SignatureAlgorithmOid = SignatureAlgorithm.Value,
            SAN = san is null ? null : new
            {
                DNS = san.DnsNames,
                IP = san.IpAddresses,
                Email = san.Emails,
                URI = san.Uris,
                RegisteredIds = san.RegisteredIds.Cast<Oid>().Select(oid => oid.Value)
            },
            ExtendedKeyUsage = Request.ExtendedKeyUsage.Cast<Oid>().Select(oid => oid.Value)
        };

        return JsonSerializer.Serialize(obj, JsonSummaryOptions);
    }

    private string ToCompactSummary()
    {
        return $"CSR[Subject={Request.SubjectName.Name}, Algo={FormatOid(SignatureAlgorithm)}, KeyAlgo={FormatOid(Request.PublicKey.Oid)}, SAN={Request.SubjectAlternativeName?.ToSubjectAlternativeName(_knownOids) != null}, EKU={Request.ExtendedKeyUsage.Count}]";
    }

    private string ToOpenSslStyle()
    {
        var sb = new System.Text.StringBuilder();

        sb.AppendLine("Certificate Request:");
        sb.AppendLine("    Data:");
        sb.AppendLine(CultureInfo.InvariantCulture, $"        Subject: {Request.SubjectName.Name}");

        sb.AppendLine("        Subject Public Key Info:");
        sb.AppendLine(CultureInfo.InvariantCulture, $"            Public Key Algorithm: {FormatOid(Request.PublicKey.Oid)}");

        try
        {
            var publicKey = GetPublicKeyInfo();
            sb.Append(CultureInfo.InvariantCulture, $"            {publicKey.Type} Public-Key:");
            if (publicKey.KeySize is not null)
            {
                sb.Append(CultureInfo.InvariantCulture, $" ({publicKey.KeySize} bit)");
            }
            sb.AppendLine();
            sb.AppendLine(CultureInfo.InvariantCulture, $"            Public-Key Value: {ToHex(publicKey.Value.Span)}");
            if ("EC" == publicKey.Type)
            {
                using var ec = Request.PublicKey.GetECDsaPublicKey() ?? throw new CryptographicException("The CSR does not contain an ECDSA public key.");
                var parameters = ec.ExportParameters(false);
                string curveOid = parameters.Curve.Oid.Value ?? "Unknown";
                string curveName = parameters.Curve.Oid.FriendlyName ?? "Unknown";
                sb.AppendLine(CultureInfo.InvariantCulture, $"            ASN1 OID: {curveOid}");
                sb.AppendLine(CultureInfo.InvariantCulture, $"            NIST Curve: {curveName}");
            }
        }
        catch (Exception ex) when (ex is
            CryptographicException or
            PlatformNotSupportedException
        )
        {
            sb.AppendLine(CultureInfo.InvariantCulture, $"            [Error decoding public key: {ex.Message}]");
        }

        sb.AppendLine("        Attributes:");

        if (Request.CertificateExtensions.Count > 0)
        {
            sb.AppendLine("            Requested Extensions:");
            // SAN
            var san = Request.SubjectAlternativeName?.ToSubjectAlternativeName(_knownOids);
            if (san is not null)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"                {FormatOid(ExtensionOids.SubjectAlternativeName, OidGroup.ExtensionOrAttribute)}:");

                if (san.DnsNames.Count > 0)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"                    DNS:{String.Join(", ", san.DnsNames)}");

                if (san.IpAddresses.Count > 0)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"                    IP:{String.Join(", ", san.IpAddresses)}");

                if (san.Emails.Count > 0)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"                    Email:{String.Join(", ", san.Emails)}");

                if (san.Uris.Count > 0)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"                    URI:{String.Join(", ", san.Uris)}");

                if (san.RegisteredIds.Count > 0)
                {
                    sb.AppendLine("                    Registered IDs:");
                    foreach (var oid in san.RegisteredIds)
                    {
                        sb.AppendLine(CultureInfo.InvariantCulture, $"                        {FormatOid(oid)}");
                    }
                }
            }
            // EKU
            var extendedKeyUsage = Request.ExtendedKeyUsage;
            if (extendedKeyUsage.Count > 0)
            {
                sb.AppendLine(CultureInfo.InvariantCulture, $"                {FormatOid(ExtensionOids.ExtendedKeyUsage, OidGroup.ExtensionOrAttribute)}:");
                foreach (var oid in extendedKeyUsage)
                {
                    sb.AppendLine(CultureInfo.InvariantCulture, $"                    {FormatOid(oid)}");
                }
            }
        }
        sb.AppendLine(CultureInfo.InvariantCulture, $"    Signature Algorithm: {FormatOid(SignatureAlgorithm)}");
        sb.AppendLine(CultureInfo.InvariantCulture, $"    Signature Value: {ToHex(Signature.Span)}");

        return sb.ToString();
    }

    private static string FormatOid(string oidValue, OidGroup group)
    {
        try
        {
            return FormatOid(Oid.FromOidValue(oidValue, group));
        }
        catch (CryptographicException)
        {
            return $"({oidValue})";
        }
    }

    private static string FormatOid(Oid oid)
    {
        string oidValue = oid.Value ??
            throw new CryptographicException("OID does not contain a value.");

        return String.IsNullOrEmpty(oid.FriendlyName)
            ? $"({oidValue})"
            : $"{oid.FriendlyName} ({oidValue})";
    }

    private (
        string Type,
        int? KeySize,
        ReadOnlyMemory<byte> Value
    )
    GetPublicKeyInfo()
    {
        string? oidValue = Request.PublicKey.Oid.Value;

        if (AlgorithmOids.IsRsa(oidValue))
        {
            using var rsa = Request.PublicKey.GetRSAPublicKey() ??
                throw new CryptographicException("The CSR does not contain an RSA public key.");

            return (
                "RSA",
                rsa.KeySize,
                Request.PublicKey.EncodedKeyValue.RawData
            );
        }

        if (AlgorithmOids.EcPublicKey == oidValue)
        {
            using var ec = Request.PublicKey.GetECDsaPublicKey() ??
                throw new CryptographicException("The CSR does not contain an ECDSA public key.");

            return (
                "EC",
                ec.KeySize,
                Request.PublicKey.EncodedKeyValue.RawData
            );
        }

#if NET10_0_OR_GREATER
        if (AlgorithmOids.IsMLDsa(oidValue))
        {
#if NET10_0
#pragma warning disable SYSLIB5006
#endif
            using var mlDsa = Request.PublicKey.GetMLDsaPublicKey() ??
                throw new CryptographicException("The CSR does not contain an ML-DSA public key.");

            return (
                "ML-DSA",
                null,
                Request.PublicKey.EncodedKeyValue.RawData
            );

#if NET10_0
#pragma warning restore SYSLIB5006
#endif
        }
#endif

        return (
            "Unknown",
            null,
            Request.PublicKey.EncodedKeyValue.RawData);
    }
}

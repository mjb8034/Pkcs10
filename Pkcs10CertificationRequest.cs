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
    /// Supported signature algorithms: SHA-256, SHA-384, and SHA-512
    /// with RSA PKCS #1 v1.5; ECDSA with SHA-224, SHA-256, SHA-384, and
    /// SHA-512; and ML-DSA-44, ML-DSA-65, and ML-DSA-87.
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
    /// The certification request uses an unsupported signature algorithm.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// The certification request is malformed, contains trailing data,
    /// contains an invalid signature encoding, or fails cryptographic validation.
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

            // Signature
            ReadOnlyMemory<byte>? signatureAlgorithmParameters = null;

            // signatureAlgorithm
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

            var signingConfiguration = GetSigningConfiguration(signatureAlgorithm);

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

    private static (HashAlgorithmName HashAlgorithmName, RSASignaturePadding? RSASignaturePadding) GetSigningConfiguration(Oid signatureAlgorithm)
    {
        // Map algorithm OID to crypto
        return signatureAlgorithm.Value switch
        {
            AlgorithmOids.Sha256WithRsaEncryption => (HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            AlgorithmOids.Sha384WithRsaEncryption => (HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            AlgorithmOids.Sha512WithRsaEncryption => (HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            AlgorithmOids.EcdsaWithSha224 => (new HashAlgorithmName("SHA224"), null),
            AlgorithmOids.EcdsaWithSha256 => (HashAlgorithmName.SHA256, null),
            AlgorithmOids.EcdsaWithSha384 => (HashAlgorithmName.SHA384, null),
            AlgorithmOids.EcdsaWithSha512 => (HashAlgorithmName.SHA512, null),
            AlgorithmOids.MLDsa44 or
            AlgorithmOids.MLDsa65 or
            AlgorithmOids.MLDsa87 => (default, null),
            _ => throw new NotSupportedException($"Unsupported signature algorithm OID: {signatureAlgorithm.Value}")
        };
    }

    private static string ToHex(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return string.Empty;

        int length = checked((data.Length * 3) - 1);

        return string.Create(
            length,
            data,
            static (destination, source) =>
            {
                const string HexDigits = "0123456789ABCDEF";

                int position = 0;

                for (int i = 0; i < source.Length; i++)
                {
                    if (0 != i)
                    {
                        destination[position++] = ':';
                    }

                    byte value = source[i];

                    destination[position++] = HexDigits[value >> 4];
                    destination[position++] = HexDigits[value & 0x0F];
                }
            }
        );
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
            if (Request.PublicKey.Oid.Value == AlgorithmOids.RsaEncryption)
            {
                using var rsa = Request.PublicKey.GetRSAPublicKey() ?? throw new CryptographicException("The CSR does not contain an RSA public key.");
                sb.AppendLine("  Type: RSA");
                sb.AppendLine(CultureInfo.InvariantCulture, $"  Key Size: {rsa.KeySize} bits");
            }
            else if (Request.PublicKey.Oid.Value == AlgorithmOids.EcPublicKey)
            {
                using var ec = Request.PublicKey.GetECDsaPublicKey() ?? throw new CryptographicException("The CSR does not contain an ECDSA public key.");
                sb.AppendLine("  Type: EC");
                sb.AppendLine(CultureInfo.InvariantCulture, $"  Key Size: {ec.KeySize} bits");
            }
            else if (AlgorithmOids.IsMLDsa(Request.PublicKey.Oid.Value))
            {
#pragma warning disable SYSLIB5006 // Type is for evaluation purposes only and is subject to change or removal in future updates. Suppress this diagnostic to proceed.
                using var mlDsa = Request.PublicKey.GetMLDsaPublicKey() ?? throw new CryptographicException("The CSR does not contain an ML-DSA public key.");
                sb.AppendLine("  Type: ML-DSA");
                sb.AppendLine(CultureInfo.InvariantCulture, $"  Key Size: {mlDsa.Algorithm.PublicKeySizeInBytes} bytes");
#pragma warning restore SYSLIB5006 // Type is for evaluation purposes only and is subject to change or removal in future updates. Suppress this diagnostic to proceed.
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
                sb.AppendLine(CultureInfo.InvariantCulture, $"  DNS: {string.Join(", ", san.DnsNames)}");

            if (san.IpAddresses.Count > 0)
                sb.AppendLine(CultureInfo.InvariantCulture, $"  IP: {string.Join(", ", san.IpAddresses)}");

            if (san.Emails.Count > 0)
                sb.AppendLine(CultureInfo.InvariantCulture, $"  Email: {string.Join(", ", san.Emails)}");

            if (san.Uris.Count > 0)
                sb.AppendLine(CultureInfo.InvariantCulture, $"  URI: {string.Join(", ", san.Uris)}");

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
        var san = Request.SubjectAlternativeName?.ToSubjectAlternativeName(_knownOids);
        var obj = new
        {
            Subject = Request.SubjectName.Name,
            PublicKey = new
            {
                AlgorithmOid = Request.PublicKey.Oid.Value,
                KeyType = Request.PublicKey.Oid.Value switch
                {
                    AlgorithmOids.RsaEncryption => "RSA",
                    AlgorithmOids.EcPublicKey => "EC",
                    AlgorithmOids.MLDsa44 or
                    AlgorithmOids.MLDsa65 or
                    AlgorithmOids.MLDsa87 => "ML-DSA",
                    _ => "Unknown"
                },
                KeySize = GetPublicKeySize(),
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

    private int? GetPublicKeySize()
    {
        return Request.PublicKey.Oid.Value switch
        {
            AlgorithmOids.RsaEncryption => GetRsaKeySize(),
            AlgorithmOids.EcPublicKey => GetEcKeySize(),
            _ => null
        };

        int GetRsaKeySize()
        {
            using var rsa = Request.PublicKey.GetRSAPublicKey() ?? throw new CryptographicException("The CSR does not contain an RSA public key.");
            return rsa.KeySize;
        }

        int GetEcKeySize()
        {
            using var ec = Request.PublicKey.GetECDsaPublicKey() ?? throw new CryptographicException("The CSR does not contain an ECDSA public key.");
            return ec.KeySize;
        }
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
            if (Request.PublicKey.Oid.Value == AlgorithmOids.RsaEncryption)
            {
                using var rsa = Request.PublicKey.GetRSAPublicKey() ?? throw new CryptographicException("The CSR does not contain an RSA public key.");
                sb.AppendLine(CultureInfo.InvariantCulture, $"            RSA Public-Key: ({rsa.KeySize} bit)");
                sb.AppendLine(CultureInfo.InvariantCulture, $"            pub: {ToHex(Request.PublicKey.EncodedKeyValue.RawData)}");
            }
            else if (Request.PublicKey.Oid.Value == AlgorithmOids.EcPublicKey)
            {
                using var ec = Request.PublicKey.GetECDsaPublicKey() ?? throw new CryptographicException("The CSR does not contain an ECDSA public key.");
                sb.AppendLine(CultureInfo.InvariantCulture, $"            EC Public-Key: ({ec.KeySize} bit)");
                var parameters = ec.ExportParameters(false);
                string curveOid = parameters.Curve.Oid.Value ?? "Unknown";
                string curveName = parameters.Curve.Oid.FriendlyName ?? "Unknown";

                sb.AppendLine(CultureInfo.InvariantCulture, $"            Public-Key Value: {ToHex(Request.PublicKey.EncodedKeyValue.RawData)}");
                sb.AppendLine(CultureInfo.InvariantCulture, $"            ASN1 OID: {curveOid}");
                sb.AppendLine(CultureInfo.InvariantCulture, $"            NIST Curve: {curveName}");
            }
            else if (AlgorithmOids.IsMLDsa(Request.PublicKey.Oid.Value))
            {
#pragma warning disable SYSLIB5006 // Type is for evaluation purposes only and is subject to change or removal in future updates. Suppress this diagnostic to proceed.
                using var mlDsa = Request.PublicKey.GetMLDsaPublicKey() ?? throw new CryptographicException("The CSR does not contain an ML-DSA public key.");
                sb.AppendLine(CultureInfo.InvariantCulture, $"            ML-DSA Public Key: ({mlDsa.Algorithm.Name})");
                sb.AppendLine(CultureInfo.InvariantCulture, $"            Public-Key Value: {ToHex(Request.PublicKey.EncodedKeyValue.RawData)}");
#pragma warning restore SYSLIB5006 // Type is for evaluation purposes only and is subject to change or removal in future updates. Suppress this diagnostic to proceed.
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
                    sb.AppendLine(CultureInfo.InvariantCulture, $"                    DNS:{string.Join(", ", san.DnsNames)}");

                if (san.IpAddresses.Count > 0)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"                    IP:{string.Join(", ", san.IpAddresses)}");

                if (san.Emails.Count > 0)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"                    Email:{string.Join(", ", san.Emails)}");

                if (san.Uris.Count > 0)
                    sb.AppendLine(CultureInfo.InvariantCulture, $"                    URI:{string.Join(", ", san.Uris)}");

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
        string oidValue = oid.Value ?? throw new CryptographicException("OID does not contain a value.");

        return string.IsNullOrEmpty(oid.FriendlyName)
            ? $"({oidValue})"
            : $"{oid.FriendlyName} ({oidValue})";
    }
}

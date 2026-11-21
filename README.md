# Pkcs10

A native .NET library for parsing, validating, inspecting, and formatting PKCS #10 certificate signing requests (CSRs) using `System.Security.Cryptography` types.

## Features

- Parses DER-encoded PKCS #10 certification requests.
- Validates the request and exposes it as a standard .NET `CertificateRequest`.
- Exposes the signature algorithm, signature, and signature-algorithm parameters.
- Supports RSA PKCS #1 v1.5 with SHA-256, SHA-384, and SHA-512.
- Supports ECDSA with SHA-224, SHA-256, SHA-384, and SHA-512.
- Supports ML-DSA-44, ML-DSA-65, and ML-DSA-87.
- Provides convenient access to requested Subject Alternative Name (SAN) and Extended Key Usage (EKU) extensions.
- Supports application-defined OIDs while preserving caller-supplied `Oid` instances and friendly names.
- Provides convenient `OidCollection.Contains` extensions.
- Produces text, JSON, compact, and OpenSSL-style diagnostic summaries.

## Requirements

- .NET 10.0 or later

## Installation

Install from NuGet:

```shell
dotnet add package Pkcs10
```

Or with the NuGet Package Manager Console:

```powershell
Install-Package Pkcs10
```

## Basic usage

```csharp
using Pkcs10;

byte[] csrBytes = File.ReadAllBytes("request.csr");

Pkcs10CertificationRequest csr =
    Pkcs10CertificationRequest.FromDer(csrBytes);

Console.WriteLine(csr.Request.SubjectName.Name);
Console.WriteLine(csr.SignatureAlgorithm.Value);
Console.WriteLine(csr.ToString(Pkcs10Format.Text));
```

`Request` is the standard .NET `System.Security.Cryptography.X509Certificates.CertificateRequest`, so existing .NET cryptographic APIs can be used directly.

## Subject Alternative Names

The library provides extension members for accessing common requested X.509 extensions from `CertificateRequest`.

```csharp
var sanExtension = csr.Request.SubjectAlternativeName;

if (sanExtension is not null)
{
    var san = sanExtension.ToSubjectAlternativeName();

    foreach (string dnsName in san.DnsNames)
        Console.WriteLine(dnsName);

    foreach (var ipAddress in san.IpAddresses)
        Console.WriteLine(ipAddress);
}
```

The SAN model supports:

- DNS names
- IP addresses
- RFC 822 email addresses
- URIs
- registered IDs

Unsupported GeneralName forms can either cause parsing to fail or be ignored, depending on the `rejectUnsupportedNames` argument to `ToSubjectAlternativeName`.

## Extended Key Usage

Requested EKUs can be accessed directly from the .NET `CertificateRequest`:

```csharp
using Pkcs10.Security.Cryptography;

if (csr.Request.ExtendedKeyUsage.Contains(EkuOids.ServerAuthentication))
{
    Console.WriteLine("Server Authentication requested");
}
```

`OidCollectionExtensions.Contains` compares OID values, so callers do not need to manually enumerate an `OidCollection`.

## Application-defined OIDs

Applications can supply known OIDs when parsing a request. When a matching OID is encountered, the supplied `Oid` instance is reused, preserving its friendly name and object identity.

```csharp
using System.Security.Cryptography;
using Pkcs10;

Oid deviceType = new("1.3.6.1.4.1.99999.1.1", "Example Device Type");
OidCollection knownOids = [deviceType];

Pkcs10CertificationRequest csr =
    Pkcs10CertificationRequest.FromDer(csrBytes, knownOids);
```

The same collection can be supplied when decoding registered IDs in a Subject Alternative Name:

```csharp
var san = csr.Request.SubjectAlternativeName?
    .ToSubjectAlternativeName(knownOids);

if (san?.RegisteredIds.Contains(deviceType) == true)
{
    Console.WriteLine("Example Device Type requested");
}
```

The `1.3.6.1.4.1.99999` enterprise number used above is illustrative only. Use OIDs assigned to your organization or application.

## Diagnostic formatting

A parsed request can be rendered in several diagnostic formats:

```csharp
Console.WriteLine(csr.ToString(Pkcs10Format.Text));
Console.WriteLine(csr.ToString(Pkcs10Format.Compact));
Console.WriteLine(csr.ToString(Pkcs10Format.Json));
Console.WriteLine(csr.ToString(Pkcs10Format.OpenSsl));
```

These formats are diagnostic summaries. They are not serialization formats for round-tripping a PKCS #10 request.

## Signature algorithms

The PKCS #10 parser currently supports:

| Key/signature family | Supported algorithms |
| --- | --- |
| RSA PKCS #1 v1.5 | SHA-256, SHA-384, SHA-512 |
| ECDSA | SHA-224, SHA-256, SHA-384, SHA-512 |
| ML-DSA | ML-DSA-44, ML-DSA-65, ML-DSA-87 |

Requests using an unsupported signature algorithm cause `NotSupportedException` to be thrown. Malformed, invalid, or cryptographically invalid requests cause `CryptographicException` to be thrown.

## Design

Pkcs10 is intended to complement the .NET cryptography API rather than replace it. Parsed requests expose standard types such as:

- `CertificateRequest`
- `Oid` and `OidCollection`
- `X509Extension`
- `X509SubjectAlternativeNameExtension`
- `IPAddress`

This keeps application code interoperable with `System.Security.Cryptography` without introducing a separate cryptographic object model.

## License

Pkcs10 is licensed under the MIT License. See [LICENSE](LICENSE).

Copyright © 2026 Matthew J. Bobowski.

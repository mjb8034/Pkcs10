# Revision History

## 1.0.2

### Added

- Support for validating RSA-PSS signed PKCS #10 certification requests.
- Support for RSA PKCS #1 v1.5 signatures using SHA-1, SHA-224,
  SHA-512/224, and SHA-512/256.
- Public algorithm OID constants for the newly recognized hash,
  RSA signature, RSA-PSS, and MGF1 identifiers.

### Changed

- RSA public keys using the RSASSA-PSS algorithm identifier are now
  recognized as RSA keys in request summaries.

## 1.0.1.1

- Added support for .NET 11.0.

## 1.0.1

- Added optional wildcard subtree matching to the `OidCollection.Contains` extensions.
- Preserved exact OID matching as the default behavior.

## 1.0.0.3

- Added support for .NET 7.0.

## 1.0.0.2

- Added support for .NET 8.0 and .NET 9.0.
- Continued support for .NET 10.0.
- Limited experimental ML-DSA support to .NET 10.0 or later.

## 1.0.0.1

- Improved README documentation and usage examples.
- Improved PEM parser documentation.
- Updated NuGet package metadata.

## 1.0.0

- Initial release.

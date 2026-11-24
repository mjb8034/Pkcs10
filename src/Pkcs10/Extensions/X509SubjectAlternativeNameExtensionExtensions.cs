using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using static Pkcs10.Security.Cryptography.Utilities;

namespace Pkcs10.Security.Cryptography.X509Certificates;

/// <summary>
/// Provides extension methods for converting
/// <see cref="X509SubjectAlternativeNameExtension"/> values
/// to a structured representation.
/// </summary>
public static class X509SubjectAlternativeNameExtensionExtensions
{
    private static readonly Asn1Tag Rfc822NameTag = new(TagClass.ContextSpecific, 1);
    private static readonly Asn1Tag DnsNameTag = new(TagClass.ContextSpecific, 2);
    private static readonly Asn1Tag UriTag = new(TagClass.ContextSpecific, 6);
    private static readonly Asn1Tag IpAddressTag = new(TagClass.ContextSpecific, 7);
    private static readonly Asn1Tag RegisteredIdTag = new(TagClass.ContextSpecific, 8);

    /// <summary>
    /// Decodes an X.509 Subject Alternative Name extension into a
    /// <see cref="SubjectAlternativeName"/> model.
    /// </summary>
    /// <param name="extension">
    /// The X.509 Subject Alternative Name extension to decode.
    /// </param>
    /// <param name="knownOids">
    /// An optional collection used to resolve friendly names for
    /// registered-ID values.
    /// </param>
    /// <param name="rejectUnsupportedNames">
    /// <see langword="true"/> to throw if the extension contains a
    /// GeneralName form that <see cref="SubjectAlternativeName"/>
    /// cannot represent; otherwise, unsupported forms are skipped.
    /// </param>
    /// <returns>
    /// The decoded Subject Alternative Name model.
    /// </returns>
    /// <exception cref="ArgumentNullException">
    /// <paramref name="extension"/> is <see langword="null"/>.
    /// </exception>
    /// <exception cref="ArgumentException">
    /// <paramref name="extension"/> is not a Subject Alternative Name
    /// extension.
    /// </exception>
    /// <exception cref="CryptographicException">
    /// The extension contains malformed ASN.1, an invalid value, no
    /// GeneralName entries, or an unsupported GeneralName form when
    /// <paramref name="rejectUnsupportedNames"/> is
    /// <see langword="true"/>.
    /// </exception>
    public static SubjectAlternativeName ToSubjectAlternativeName(
        this X509SubjectAlternativeNameExtension extension,
        OidCollection? knownOids = default,
        bool rejectUnsupportedNames = true)
    {
        ArgumentNullException.ThrowIfNull(extension);

        try
        {
            var dnsNames = extension.EnumerateDnsNames().ToList();
            var ipAddresses = extension.EnumerateIPAddresses().ToList();
            var emails = new List<string>();
            var uris = new List<string>();
            OidCollection registeredIds = [];

            var reader = new AsnReader(extension.RawData, AsnEncodingRules.DER);

            AsnReader generalNames = reader.ReadSequence();

            int nameCount = 0;

            while (generalNames.HasData)
            {
                Asn1Tag tag = generalNames.PeekTag();

                if (tag.HasSameClassAndValue(Rfc822NameTag))
                {
                    emails.Add(
                        generalNames.ReadCharacterString(
                            UniversalTagNumber.IA5String,
                            Rfc822NameTag));

                }
                else if (tag.HasSameClassAndValue(DnsNameTag))
                {   // DNS is decoded by X509SubjectAlternativeNameExtension.
                    generalNames.ReadEncodedValue();
                }
                else if (tag.HasSameClassAndValue(UriTag))
                {
                    uris.Add(
                        generalNames.ReadCharacterString(
                            UniversalTagNumber.IA5String,
                            UriTag));

                }
                else if (tag.HasSameClassAndValue(IpAddressTag))
                {   // IP is decoded by X509SubjectAlternativeNameExtension.
                    generalNames.ReadEncodedValue();
                }
                else if (tag.HasSameClassAndValue(RegisteredIdTag))
                {
                    string oidValue = generalNames.ReadObjectIdentifier(RegisteredIdTag);
                    registeredIds.Add(ResolveOid(oidValue, knownOids));
                }
                else if (rejectUnsupportedNames)
                {
                    throw new CryptographicException($"The Subject Alternative Name contains unsupported " + $"GeneralName tag [{tag.TagValue}].");
                }
                else
                {
                    // Consume the complete unsupported GeneralName TLV.
                    generalNames.ReadEncodedValue();
                }
                nameCount++;
            }

            generalNames.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();

            if (0 == nameCount)
            {
                throw new CryptographicException("The Subject Alternative Name does not contain any names.");
            }

            return new SubjectAlternativeName(
                dnsNames,
                ipAddresses,
                emails,
                uris,
                registeredIds);
        }
        catch (AsnContentException ex)
        {
            throw new CryptographicException(
                "The Subject Alternative Name extension contains invalid ASN.1 data.",
                ex);
        }
        catch (FormatException ex)
        {
            throw new CryptographicException(
                "The Subject Alternative Name extension contains an invalid value.",
                ex);
        }
        catch (ArgumentException ex)
        {
            throw new CryptographicException(
                "The Subject Alternative Name extension contains an invalid value.",
                ex);
        }
    }

}
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Pkcs10.Security.Cryptography.X509Certificates;

/// <summary>
/// Provides extension members for accessing X.509 extensions
/// requested by a <see cref="CertificateRequest"/>.
/// </summary>
[System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1034:Nested types should not be visible", Justification = "The .NET SDK has a documented issue where C# 14 extension members are incorrectly interpreted by the analyzer as nested types.")]
public static class CertificateRequestExtensions
{
    extension(CertificateRequest request)
    {
        /// <summary>
        /// Gets the extended key usages requested by the certification request.
        /// </summary>
        /// <returns>
        /// The requested extended key usage OIDs, or an empty
        /// <see cref="OidCollection"/> if the request does not contain an
        /// Extended Key Usage extension.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The certificate request is <see langword="null"/>.
        /// </exception>
        public OidCollection ExtendedKeyUsage
        {
            get
            {
                ArgumentNullException.ThrowIfNull(request);

                OidCollection oids = [];
                // Find EKU extension and return EnhancedKeyUsages.
                foreach (var extension in request.CertificateExtensions)
                {
                    if (ExtensionOids.ExtendedKeyUsage == extension.Oid?.Value)
                    {
                        if (extension is X509EnhancedKeyUsageExtension ekuExtension)
                        {
                            oids = ekuExtension.EnhancedKeyUsages;
                        }
                        else
                        {
                            oids = new X509EnhancedKeyUsageExtension(extension, extension.Critical).EnhancedKeyUsages;
                        }
                        break;
                    }
                }
                return oids;
            }
        }

        /// <summary>
        /// Gets the Subject Alternative Name extension requested by the
        /// certification request.
        /// </summary>
        /// <returns>
        /// The requested Subject Alternative Name extension, or
        /// <see langword="null"/> if the request does not contain one.
        /// </returns>
        /// <exception cref="ArgumentNullException">
        /// The certificate request is <see langword="null"/>.
        /// </exception>
        public X509SubjectAlternativeNameExtension? SubjectAlternativeName
        {
            get
            {
                ArgumentNullException.ThrowIfNull(request);

                X509SubjectAlternativeNameExtension? san = null;
                // Find SAN in request.CertificateExtensions using existing X509Extension decoder.
                foreach (var extension in request.CertificateExtensions)
                {
                    if (ExtensionOids.SubjectAlternativeName == extension.Oid?.Value)
                    {
                        if (extension is X509SubjectAlternativeNameExtension sanExtension)
                        {
                            san = sanExtension;
                        }
                        else
                        {
                            san = new X509SubjectAlternativeNameExtension();
                            san.CopyFrom(extension);
                        }
                        break;
                    }
                }
                return san;
            }
        }
    }
}

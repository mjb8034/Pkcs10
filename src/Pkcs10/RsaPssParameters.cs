using System.Formats.Asn1;
using System.Security.Cryptography;

namespace Pkcs10.Security.Cryptography;

internal readonly record struct RsaPssParameters(
    HashAlgorithmName HashAlgorithm,
    HashAlgorithmName MgfHashAlgorithm,
    int SaltLength,
    int TrailerField
);

internal static class RsaPssParametersDecoder
{
    private static readonly Asn1Tag HashAlgorithmTag = new(
        TagClass.ContextSpecific,
        tagValue: 0,
        isConstructed: true
    );

    private static readonly Asn1Tag MaskGenAlgorithmTag = new(
        TagClass.ContextSpecific,
        tagValue: 1,
        isConstructed: true
    );

    private static readonly Asn1Tag SaltLengthTag = new(
        TagClass.ContextSpecific,
        tagValue: 2,
        isConstructed: true
    );

    private static readonly Asn1Tag TrailerFieldTag = new(
        TagClass.ContextSpecific,
        tagValue: 3,
        isConstructed: true
    );

    internal static RsaPssParameters Decode(ReadOnlyMemory<byte> encodedParameters)
    {
        var reader = new AsnReader(encodedParameters, AsnEncodingRules.DER);
        AsnReader parameters = reader.ReadSequence();

        // RFC 8017 defaults.
        HashAlgorithmName hashAlgorithm = HashAlgorithmName.SHA1;
        HashAlgorithmName mgfHashAlgorithm = HashAlgorithmName.SHA1;

        int saltLength = SHA1.HashSizeInBytes;
        int trailerField = 1;

        if (parameters.HasData &&
            parameters.PeekTag().HasSameClassAndValue(HashAlgorithmTag))
        {
            AsnReader explicitHashAlgorithm = parameters.ReadSequence(HashAlgorithmTag);
            hashAlgorithm = ReadHashAlgorithmIdentifier(explicitHashAlgorithm);
            explicitHashAlgorithm.ThrowIfNotEmpty();
        }

        if (parameters.HasData &&
            parameters.PeekTag().HasSameClassAndValue(MaskGenAlgorithmTag))
        {
            AsnReader explicitMaskGenAlgorithm = parameters.ReadSequence(MaskGenAlgorithmTag);
            mgfHashAlgorithm = ReadMaskGenAlgorithmIdentifier(explicitMaskGenAlgorithm);
            explicitMaskGenAlgorithm.ThrowIfNotEmpty();
        }

        if (parameters.HasData &&
            parameters.PeekTag().HasSameClassAndValue(SaltLengthTag))
        {
            AsnReader explicitSaltLength = parameters.ReadSequence(SaltLengthTag);
            saltLength = ReadNonNegativeInt32(explicitSaltLength, "RSA-PSS salt length");
            explicitSaltLength.ThrowIfNotEmpty();
        }

        if (parameters.HasData &&
            parameters.PeekTag().HasSameClassAndValue(TrailerFieldTag))
        {
            AsnReader explicitTrailerField = parameters.ReadSequence(TrailerFieldTag);
            trailerField = ReadNonNegativeInt32(explicitTrailerField, "RSA-PSS trailer field");
            explicitTrailerField.ThrowIfNotEmpty();
        }

        // Any remaining value is unknown, duplicated, or out of order.
        parameters.ThrowIfNotEmpty();
        reader.ThrowIfNotEmpty();

        return new RsaPssParameters(hashAlgorithm, mgfHashAlgorithm, saltLength, trailerField);
    }

    private static HashAlgorithmName ReadMaskGenAlgorithmIdentifier(AsnReader explicitMaskGenAlgorithm)
    {
        AsnReader algorithmIdentifier = explicitMaskGenAlgorithm.ReadSequence();
        string algorithmOid = algorithmIdentifier.ReadObjectIdentifier();

        if (AlgorithmOids.Mgf1 != algorithmOid)
        {
            throw new NotSupportedException(
                $"Unsupported RSA-PSS mask generation algorithm OID: {algorithmOid}");
        }

        if (!algorithmIdentifier.HasData)
        {
            throw new CryptographicException(
                "The MGF1 AlgorithmIdentifier does not contain its required hash algorithm parameters.");
        }

        // MGF1 parameters contain another AlgorithmIdentifier
        // identifying MGF1's underlying hash.
        ReadOnlyMemory<byte> encodedHashAlgorithm = algorithmIdentifier.ReadEncodedValue();
        algorithmIdentifier.ThrowIfNotEmpty();
        var hashAlgorithmReader = new AsnReader(encodedHashAlgorithm, AsnEncodingRules.DER);
        HashAlgorithmName hashAlgorithm = ReadHashAlgorithmIdentifier(hashAlgorithmReader);
        hashAlgorithmReader.ThrowIfNotEmpty();

        return hashAlgorithm;
    }

    private static HashAlgorithmName ReadHashAlgorithmIdentifier(AsnReader reader)
    {
        AsnReader algorithmIdentifier = reader.ReadSequence();

        string algorithmOid = algorithmIdentifier.ReadObjectIdentifier();

        // RFC-compatible hash AlgorithmIdentifier values can use
        // omitted parameters or an explicit ASN.1 NULL.
        if (algorithmIdentifier.HasData)
        {
            algorithmIdentifier.ReadNull();
        }
        algorithmIdentifier.ThrowIfNotEmpty();

        return algorithmOid switch
        {
            AlgorithmOids.Sha1 => HashAlgorithmName.SHA1,
            AlgorithmOids.Sha224 => new HashAlgorithmName("SHA224"),
            AlgorithmOids.Sha256 => HashAlgorithmName.SHA256,
            AlgorithmOids.Sha384 => HashAlgorithmName.SHA384,
            AlgorithmOids.Sha512 => HashAlgorithmName.SHA512,
            AlgorithmOids.Sha512_224 => new HashAlgorithmName("SHA512/224"),
            AlgorithmOids.Sha512_256 => new HashAlgorithmName("SHA512/256"),
            AlgorithmOids.Sha3_224 => new HashAlgorithmName("SHA3-224"),
#if NET8_0_OR_GREATER
            AlgorithmOids.Sha3_256 => HashAlgorithmName.SHA3_256,
            AlgorithmOids.Sha3_384 => HashAlgorithmName.SHA3_384,
            AlgorithmOids.Sha3_512 => HashAlgorithmName.SHA3_512,
#else
            AlgorithmOids.Sha3_256 => new HashAlgorithmName("SHA3-256"),
            AlgorithmOids.Sha3_384 => new HashAlgorithmName("SHA3-384"),
            AlgorithmOids.Sha3_512 => new HashAlgorithmName("SHA3-512"),
#endif
            _ => throw new NotSupportedException(
                $"Unsupported RSA-PSS hash algorithm OID: {algorithmOid}")
        };
    }

    private static int ReadNonNegativeInt32(AsnReader reader, string fieldName)
    {
        if (!reader.TryReadInt32(out int value) || value < 0)
        {
            throw new CryptographicException($"{fieldName} is outside the supported range.");
        }

        return value;
    }
}

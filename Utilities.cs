using System.Security.Cryptography;

namespace Pkcs10.Security.Cryptography;

internal static class Utilities
{
    // Resolves an OID to a caller-supplied canonical instance when available;
    // otherwise creates a new OID instance.
    internal static Oid ResolveOid(string oidValue, OidCollection? knownOids)
    {
        if (knownOids is not null)
        {
            foreach (var oid in knownOids)
            {
                if (oid.Value == oidValue)
                {
                    return oid;
                }
            }
        }

        return new Oid(oidValue);
    }
}

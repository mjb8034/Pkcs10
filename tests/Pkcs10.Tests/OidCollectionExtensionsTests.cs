using System.ComponentModel;
using System.Security.Cryptography;
using Pkcs10.Security.Cryptography;

namespace Pkcs10.Tests;

public class OidCollectionExtensionsTests
{
    //
    // Normal matching behavior
    //

    [Theory]
    // Exact matching with None.
    [InlineData("1.2.3.4", "1.2.3.4", OidMatchMode.None, true)]
    [InlineData("1.2.3.4", "1.2.3.5", OidMatchMode.None, false)]
    [InlineData("1.2.3.4", "1.2.3.*", OidMatchMode.None, false)]

    // Wildcard mode without a wildcard still performs exact matching.
    [InlineData("1.2.3.4", "1.2.3.4", OidMatchMode.Wildcard, true)]
    [InlineData("1.2.3.4", "1.2.3.5", OidMatchMode.Wildcard, false)]

    // Immediate and deeper descendants.
    [InlineData("1.2.3.4", "1.2.3.*", OidMatchMode.Wildcard, true)]
    [InlineData("1.2.3.999", "1.2.3.*", OidMatchMode.Wildcard, true)]
    [InlineData("1.2.3.4.5", "1.2.3.*", OidMatchMode.Wildcard, true)]
    [InlineData("1.2.3.4.5.6", "1.2.3.*", OidMatchMode.Wildcard, true)]

    // The parent itself is not a descendant.
    [InlineData("1.2.3", "1.2.3.*", OidMatchMode.Wildcard, false)]

    // Similar and adjacent branches must not match.
    [InlineData("1.2.30", "1.2.3.*", OidMatchMode.Wildcard, false)]
    [InlineData("1.2.30.4", "1.2.3.*", OidMatchMode.Wildcard, false)]
    [InlineData("1.2.4", "1.2.3.*", OidMatchMode.Wildcard, false)]
    [InlineData("1.2.4.3", "1.2.3.*", OidMatchMode.Wildcard, false)]
    public void Contains_ReturnsExpectedResult(
        string member,
        string value,
        OidMatchMode matchMode,
        bool expected)
    {
        OidCollection collection = CreateCollection(member);

        bool actual = collection.Contains(value, matchMode);

        Assert.Equal(expected, actual);
    }

    //
    // Invalid wildcard syntax
    //

    [Theory]
    [InlineData("*")]
    [InlineData(".*")]
    [InlineData("1.2.3*")]
    [InlineData("1.2.*.3")]
    [InlineData("1.2.*.3.*")]
    [InlineData("1.2.3.**")]
    [InlineData("1.2.3.*.*")]
    public void Contains_Wildcard_InvalidPatternThrows(string value)
    {
        OidCollection collection = CreateCollection("1.2.3.4");

        ArgumentException exception =
            Assert.Throws<ArgumentException>(
                () => collection.Contains(value, OidMatchMode.Wildcard));

        Assert.Equal("value", exception.ParamName);
    }

    //
    // None means wildcard-looking input remains literal.
    //

    [Theory]
    [InlineData("*")]
    [InlineData(".*")]
    [InlineData("1.2.3*")]
    [InlineData("1.2.*.3")]
    [InlineData("1.2.*.3.*")]
    [InlineData("1.2.3.**")]
    [InlineData("1.2.3.*.*")]
    [InlineData("1.2.3.*")]
    public void Contains_None_DoesNotInterpretWildcardSyntax(string value)
    {
        OidCollection collection = CreateCollection("1.2.3.4");

        bool actual = collection.Contains(value, OidMatchMode.None);

        Assert.False(actual);
    }

    //
    // Original overloads
    //

    [Theory]
    [InlineData("1.2.3.4", true)]
    [InlineData("1.2.3.5", false)]
    [InlineData("1.2.3.*", false)]
    public void Contains_StringOriginalOverload_UsesExactMatching(
        string value,
        bool expected)
    {
        OidCollection collection = CreateCollection("1.2.3.4");

        bool actual = collection.Contains(value);

        Assert.Equal(expected, actual);
    }

    [Theory]
    [InlineData("1.2.3.4", true)]
    [InlineData("1.2.3.5", false)]
    public void Contains_OidOriginalOverload_UsesExactMatching(
        string value,
        bool expected)
    {
        OidCollection collection = CreateCollection("1.2.3.4");

        bool actual = collection.Contains(new Oid(value));

        Assert.Equal(expected, actual);
    }

    //
    // Collection behavior
    //

    [Fact]
    public void Contains_ReturnsTrueWhenAnyItemExactlyMatches()
    {
        OidCollection collection = CreateCollection(
            "1.2.3.1",
            "1.2.3.2",
            "1.2.3.3");

        bool actual = collection.Contains("1.2.3.2");

        Assert.True(actual);
    }

    [Fact]
    public void Contains_WildcardReturnsTrueWhenAnyItemIsDescendant()
    {
        OidCollection collection = CreateCollection(
            "1.2.2.1",
            "1.2.3.4.5",
            "1.2.4.1");

        bool actual =
            collection.Contains("1.2.3.*", OidMatchMode.Wildcard);

        Assert.True(actual);
    }

    [Theory]
    [InlineData(OidMatchMode.None)]
    [InlineData(OidMatchMode.Wildcard)]
    public void Contains_EmptyCollectionReturnsFalse(OidMatchMode matchMode)
    {
        OidCollection collection = [];

        bool actual = collection.Contains("1.2.3", matchMode);

        Assert.False(actual);
    }

    //
    // Null argument contracts
    //

    [Fact]
    public void Contains_String_NullCollectionThrows()
    {
        OidCollection collection = null!;

        ArgumentNullException exception =
            Assert.Throws<ArgumentNullException>(
                () => collection.Contains("1.2.3"));

        Assert.Equal("collection", exception.ParamName);
    }

    [Fact]
    public void Contains_String_NullValueThrows()
    {
        OidCollection collection = [];

        ArgumentNullException exception =
            Assert.Throws<ArgumentNullException>(
                () => collection.Contains((string)null!));

        Assert.Equal("value", exception.ParamName);
    }

    [Fact]
    public void Contains_Oid_NullCollectionThrows()
    {
        OidCollection collection = null!;

        ArgumentNullException exception =
            Assert.Throws<ArgumentNullException>(
                () => collection.Contains(new Oid("1.2.3")));

        Assert.Equal("collection", exception.ParamName);
    }

    [Fact]
    public void Contains_Oid_NullOidThrows()
    {
        OidCollection collection = [];

        ArgumentNullException exception =
            Assert.Throws<ArgumentNullException>(
                () => collection.Contains((Oid)null!));

        Assert.Equal("oid", exception.ParamName);
    }

    //
    // Invalid enum argument contract
    //

    [Fact]
    public void Contains_String_InvalidMatchModeThrows()
    {
        OidCollection collection = CreateCollection("1.2.3");

        InvalidEnumArgumentException exception =
            Assert.Throws<InvalidEnumArgumentException>(
                () => collection.Contains(
                    "1.2.3",
                    (OidMatchMode)42));

        Assert.Equal("matchMode", exception.ParamName);
    }

    [Fact]
    public void Contains_Oid_InvalidMatchModeThrows()
    {
        OidCollection collection = CreateCollection("1.2.3");

        InvalidEnumArgumentException exception =
            Assert.Throws<InvalidEnumArgumentException>(
                () => collection.Contains(
                    new Oid("1.2.3"),
                    (OidMatchMode)42));

        Assert.Equal("matchMode", exception.ParamName);
    }

    private static OidCollection CreateCollection(params string[] values)
    {
        OidCollection collection = [];

        foreach (string value in values)
        {
            collection.Add(new Oid(value));
        }

        return collection;
    }
}
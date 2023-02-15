using Shane32.Argon2;

namespace Tests;

public class Argon2LibraryTests
{
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task FullTest(bool useSecret)
    {
        var knownSecret = useSecret ? System.Text.Encoding.UTF8.GetBytes("This is a secret") : null;

        // Select a set of parameters to use that require at least 0.2 seconds of hashing time
        var parameters = await Argon2Library.SelectParametersAsync(
            parallelism: 2,
            minTime: TimeSpan.FromSeconds(0.2),
            hashLengthBits: 256,
            saltLengthBits: 128,
            knownSecret: knownSecret);

        // Create a hash
        var hash = await Argon2Library.HashAsync("password", parameters);
        Assert.StartsWith("$a2id$", hash, StringComparison.Ordinal);
        Assert.True(Argon2Library.IsArgon2Hash(hash));
        Assert.False(Argon2Library.IsArgon2Hash("invalid hash"));

        // Verify a hash
        Assert.True(await Argon2Library.VerifyAsync("password", hash, knownSecret));

        // Verify an invalid hash
        Assert.False(await Argon2Library.VerifyAsync("password2", hash, knownSecret));

        // Verify that an invalid format throws
        await Assert.ThrowsAsync<FormatException>(() => Argon2Library.VerifyAsync("password", "invalid hash", knownSecret));
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task SeparateSaltTest(bool useSecret)
    {
        var knownSecret = useSecret ? System.Text.Encoding.UTF8.GetBytes("This is a secret") : null;

        // Select a set of parameters to use that require at least 0.2 seconds of hashing time
        var parameters = await Argon2Library.SelectParametersAsync(
            parallelism: 2,
            minTime: TimeSpan.FromSeconds(0.2),
            hashLengthBits: 256,
            saltLengthBits: 128,
            knownSecret: knownSecret);

        // Create a salt
        var salt = Argon2Library.CreateArgonSalt(parameters);
        Assert.StartsWith("$a2id$", salt, StringComparison.Ordinal);
        Assert.True(Argon2Library.IsArgon2Salt(salt));
        Assert.False(Argon2Library.IsArgon2Salt("invalid hash"));
        var hash = await Argon2Library.HashAsync("password", salt, 256, knownSecret);
        Assert.NotNull(hash);

        // Verify a hash
        Assert.True(await Argon2Library.VerifyAsync("password", hash, salt, knownSecret));

        // Verify an invalid hash
        Assert.False(await Argon2Library.VerifyAsync("password2", hash, salt, knownSecret));

        // Verify that an invalid format throws
        await Assert.ThrowsAsync<FormatException>(() => Argon2Library.HashAsync("password", "invalid salt", 256, knownSecret));
    }
}

# Shane32.Argon2

[![NuGet](https://img.shields.io/nuget/v/Shane32.Argon2.svg)](https://www.nuget.org/packages/Shane32.Argon2)
[![Coverage Status](https://coveralls.io/repos/github/Shane32/Argon2/badge.svg?branch=master)](https://coveralls.io/github/Shane32/Argon2?branch=master)

## Usage

```csharp
using Shane32.Argon2;

// Select a set of parameters to use that require at least 0.2 seconds of hashing time
var parallelism = 2;
var hashLengthBits = 256;
var minTime = TimeSpan.FromSeconds(0.2);
var parameters = await Argon2Library.SelectParametersAsync(parallelism, hashLengthBits, minTime);

// Create a hash with custom parameters
var hash = await Argon2Library.HashAsync(parameters, "password");

// Verify a hash
var ok = await Argon2Library.VerifyAsync(hash, "password");
```

## Dependencies

This uses the [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography)
underlying library to create the Argon2 hash.

## Notes

The [Konscious.Security.Cryptography.Argon2](https://github.com/kmaragon/Konscious.Security.Cryptography)
library is a C# implementation of Argon2 and may be subject to side-channel attacks.

The Argon2id variant is used when creating hashes.

## Credits

Glory to Jehovah, Lord of Lords and King of Kings, creator of Heaven and Earth,
who through his Son Jesus Christ, has reedemed me to become a child of God. -Shane32

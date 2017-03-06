Task("Test-AES128-ECB")
    .IsDependentOn("Build")
    .Does(() =>
{
    var encryptedFile = "./" + (Guid.NewGuid()).ToString() + ".aes";
    var decryptedFile = "./" + (Guid.NewGuid()).ToString() + ".aesdec";

    var encryptExitCode = StartProcess("./x64/" + configuration + "/AES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-e")
            .AppendQuoted("SOME 128-BIT KEY")
            .Append("ECB")
            .AppendQuoted("./Test Files/Shakespeare.txt")
            .AppendQuoted(encryptedFile)
        )
    );

    if(encryptExitCode != 0) throw new Exception("Encryption failed with exit code " + encryptExitCode);

    var decryptExitCode = StartProcess("./x64/" + configuration + "/AES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-d")
            .AppendQuoted("SOME 128-BIT KEY")
            .Append("ECB")
            .AppendQuoted(encryptedFile)
            .AppendQuoted(decryptedFile)
        )
    );

    DeleteFile(encryptedFile);
    if(decryptExitCode != 0) throw new Exception("Decryption failed with exit code " + decryptExitCode);

    var original = CalculateFileHash("./Test Files/Shakespeare.txt").ToHex();
    var decrypted = CalculateFileHash(decryptedFile).ToHex();

    DeleteFile(decryptedFile);

    Information("Original Plaintext:  " + original);
    Information("Decrypted Plaintext: " + decrypted);

    if(original != decrypted)
    {
        throw new Exception("Decrypted ciphertext is different from original plaintext");
    }
});

Task("Test-AES128-CBC")
    .IsDependentOn("Build")
    .Does(() =>
{
    var encryptedFile = "./" + (Guid.NewGuid()).ToString() + ".aes";
    var decryptedFile = "./" + (Guid.NewGuid()).ToString() + ".aesdec";

    var encryptExitCode = StartProcess("./x64/" + configuration + "/AES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-e")
            .AppendQuoted("SOME 128-BIT KEY")
            .Append("CBC")
            .AppendQuoted("./Test Files/Shakespeare.txt")
            .AppendQuoted(encryptedFile)
        )
    );

    if(encryptExitCode != 0) throw new Exception("Encryption failed with exit code " + encryptExitCode);

    var decryptExitCode = StartProcess("./x64/" + configuration + "/AES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-d")
            .AppendQuoted("SOME 128-BIT KEY")
            .Append("CBC")
            .AppendQuoted(encryptedFile)
            .AppendQuoted(decryptedFile)
        )
    );

    DeleteFile(encryptedFile);
    if(decryptExitCode != 0) throw new Exception("Decryption failed with exit code " + decryptExitCode);

    var original = CalculateFileHash("./Test Files/Shakespeare.txt").ToHex();
    var decrypted = CalculateFileHash(decryptedFile).ToHex();

    DeleteFile(decryptedFile);

    Information("Original Plaintext:  " + original);
    Information("Decrypted Plaintext: " + decrypted);

    if(original != decrypted)
    {
        throw new Exception("Decrypted ciphertext is different from original plaintext");
    }
});

Task("Test-AES128-PaddingEdgeCase")
    .IsDependentOn("Build")
    .Does(() => 
{
    var encryptedFile = "./" + (Guid.NewGuid()).ToString() + ".aes";
    var decryptedFile = "./" + (Guid.NewGuid()).ToString() + ".aesdec";

    var encryptExitCode = StartProcess("./x64/" + configuration + "/AES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-e")
            .AppendQuoted("SOME 128-BIT KEY")
            .Append("ECB")
            .AppendQuoted("./Test Files/alphabet.txt")
            .AppendQuoted(encryptedFile)
        )
    );

    if(encryptExitCode != 0) throw new Exception("Encryption failed with exit code " + encryptExitCode);

    var decryptExitCode = StartProcess("./x64/" + configuration + "/AES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-d")
            .AppendQuoted("SOME 128-BIT KEY")
            .Append("ECB")
            .AppendQuoted(encryptedFile)
            .AppendQuoted(decryptedFile)
        )
    );

    DeleteFile(encryptedFile);
    if(decryptExitCode != 0) throw new Exception("Decryption failed with exit code " + decryptExitCode);

    var original = CalculateFileHash("./Test Files/alphabet.txt").ToHex();
    var decrypted = CalculateFileHash(decryptedFile).ToHex();

    DeleteFile(decryptedFile);

    Information("Original Plaintext:  " + original);
    Information("Decrypted Plaintext: " + decrypted);

    if(original != decrypted)
    {
        throw new Exception("Decrypted ciphertext is different from original plaintext");
    }
});

Task("Test-AES128")
    .IsDependentOn("Test-AES128-ECB")
    .IsDependentOn("Test-AES128-CBC")
	.IsDependentOn("Test-AES128-PaddingEdgeCase");
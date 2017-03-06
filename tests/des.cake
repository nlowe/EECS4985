Task("Test-DES-ECB")
    .IsDependentOn("Build")
    .Does(() =>
{
    var encryptedFile = "./" + (Guid.NewGuid()).ToString() + ".des";
    var decryptedFile = "./" + (Guid.NewGuid()).ToString() + ".desdec";

    var encryptExitCode = StartProcess("./x64/" + configuration + "/DES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-e")
            .AppendQuoted("Pa$$w0rd")
            .Append("ECB")
            .AppendQuoted("./Test Files/Shakespeare.txt")
            .AppendQuoted(encryptedFile)
        )
    );

    if(encryptExitCode != 0) throw new Exception("Encryption failed with exit code " + encryptExitCode);

    var decryptExitCode = StartProcess("./x64/" + configuration + "/DES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-d")
            .AppendQuoted("Pa$$w0rd")
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

Task("Test-DES-CBC")
    .IsDependentOn("Build")
    .Does(() =>
{
    var encryptedFile = "./" + (Guid.NewGuid()).ToString() + ".des";
    var decryptedFile = "./" + (Guid.NewGuid()).ToString() + ".desdec";

    var encryptExitCode = StartProcess("./x64/" + configuration + "/DES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-e")
            .AppendQuoted("Pa$$w0rd")
            .Append("CBC")
            .AppendQuoted("./Test Files/Shakespeare.txt")
            .AppendQuoted(encryptedFile)
        )
    );

    if(encryptExitCode != 0) throw new Exception("Encryption failed with exit code " + encryptExitCode);

    var decryptExitCode = StartProcess("./x64/" + configuration + "/DES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-d")
            .AppendQuoted("Pa$$w0rd")
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

Task("Test-DES-CanDecryptProfessorFile")
    .IsDependentOn("Build")
    .Does(() =>
{
    var decryptedFile = "./" + (Guid.NewGuid()).ToString() + ".desdec";

    var encryptExitCode = StartProcess("./x64/" + configuration + "/DES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-d")
            .AppendQuoted("Pa$$w0rd")
            .Append("ECB")
            .AppendQuoted("./Test Files/Shakespeare.lgt.des")
            .AppendQuoted(decryptedFile)
        )
    );

    if(encryptExitCode != 0) throw new Exception("Encryption failed with exit code " + encryptExitCode);

    var decrypted = CalculateFileHash(decryptedFile).ToHex();

    DeleteFile(decryptedFile);
    Information("Decrypted Plaintext: " + decrypted);

    if(decrypted.ToUpper() != "F3D607A3BB724DD2C820AB3DBC4DADB53D4D97DF01784A7B54E887DFC4BEEFB8")
    {
        throw new Exception("Something broke (decrypted file is not correct)");
    }
});

Task("Test-DES-PaddingEdgeCase")
    .IsDependentOn("Build")
    .Does(() => 
{
    var encryptedFile = "./" + (Guid.NewGuid()).ToString() + ".des";
    var decryptedFile = "./" + (Guid.NewGuid()).ToString() + ".desdec";

    var encryptExitCode = StartProcess("./x64/" + configuration + "/DES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-e")
            .AppendQuoted("Pa$$w0rd")
            .Append("ECB")
            .AppendQuoted("./Test Files/alphabet.txt")
            .AppendQuoted(encryptedFile)
        )
    );

    if(encryptExitCode != 0) throw new Exception("Encryption failed with exit code " + encryptExitCode);

    var decryptExitCode = StartProcess("./x64/" + configuration + "/DES.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("-d")
            .AppendQuoted("Pa$$w0rd")
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

Task("Test-DES")
    .IsDependentOn("Test-DES-ECB")
    .IsDependentOn("Test-DES-CBC")
    .IsDependentOn("Test-DES-CanDecryptProfessorFile")
	.IsDependentOn("Test-DES-PaddingEdgeCase");
void generateFile(string path, int mb)
{
    if(mb <= 0) throw new ArgumentException("Invalid size");

    // Based on http://stackoverflow.com/a/4432207/1200316
    Random rng = new Random();

    byte[] buff = new byte[1024 * 1024];
    using(var writer = System.IO.File.OpenWrite(path))
    {
        for(int i = 0; i < mb; i++)
        {
            rng.NextBytes(buff);
            writer.Write(buff, 0, 1024 * 1024);
        }
    }
}

void runDES(int mb, string mode)
{
    var plain = "./" + (Guid.NewGuid()).ToString() + ".bin";
    var ciphertext = "./" + (Guid.NewGuid()).ToString() + ".bin.des";
    var decrypted = "./" + (Guid.NewGuid()).ToString() + ".desdec.bin";

    try
    {
        generateFile(plain, mb);

        var exitCode = StartProcess("./x64/" + configuration + "/DES.exe", new ProcessSettings ()
            .WithArguments(args => args
                .Append("-e")
                .AppendQuoted("Pa$$w0rd")
                .Append(mode)
                .AppendQuoted(plain)
                .AppendQuoted(ciphertext)
            )
        );

        if(exitCode != 0) throw new Exception("Encryption failed with exit code " + exitCode);

        exitCode = StartProcess("./x64/" + configuration + "/DES.exe", new ProcessSettings ()
            .WithArguments(args => args
                .Append("-d")
                .AppendQuoted("Pa$$w0rd")
                .Append(mode)
                .AppendQuoted(ciphertext)
                .AppendQuoted(decrypted)
            )
        );

        if(exitCode != 0) throw new Exception("Encryption failed with exit code " + exitCode);
    }
    finally
    {
        if(FileExists(plain)) DeleteFile(plain);
        if(FileExists(ciphertext)) DeleteFile(ciphertext);
        if(FileExists(decrypted)) DeleteFile(decrypted);
    }
}

Task("Benchmark-DES-ECB")
    .IsDependentOn("Build")
    .Does(() => 
{
    Information("Benchmarking DES in ECB mode starting with a 1mb file in steps of 8mb up to 128mb");
    runDES(1, "ECB");
    for(int i=8; i<=128; i+=8)
    {
        runDES(i, "ECB");
    }
});

Task("Benchmark-DES-CBC")
    .IsDependentOn("Build")
    .Does(() => 
{
    Information("Benchmarking DES in CBC mode starting with a 1mb file in steps of 8mb up to 128mb");
    runDES(1, "CBC");
    for(int i=8; i<=128; i+=8)
    {
        runDES(i, "CBC");
    }
});

Task("Benchmark-DES")
    .IsDependentOn("Benchmark-DES-ECB")
    .IsDependentOn("Benchmark-DES-CBC");

Task("Benchmark")
    .IsDependentOn("Benchmark-DES");
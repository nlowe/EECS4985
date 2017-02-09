Task("Benchmark-DES")
    .Does(() => 
{
    var benchmarkExitCode = StartProcess("./x64/" + configuration + "/benchmarks.exe", new ProcessSettings ()
        .WithArguments(args => args
            .Append("des")
        )
    );

    if(benchmarkExitCode != 0) throw new Exception("Encryption failed with exit code " + benchmarkExitCode);
});

Task("Benchmark")
    .IsDependentOn("Benchmark-DES");
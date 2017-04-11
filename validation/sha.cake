Task("Validate-SHA512")
    .IsDependentOn("Build")
    .Does(() =>
{
    var failures = 0;
    foreach(var test in GetFiles("./validation/SHA512*.rsp"))
    {
        failures += RunHashTest("./x64/" + configuration + "/cavp.exe", test, "sha512");
    }

    if(failures != 0) throw new Exception("Validation of SHA512 Failed");
});

Task("Validate-SHA")
    .IsDependentOn("Validate-SHA512");
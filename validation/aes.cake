Task("Validate-AES128")
    .Does(() => 
{
    var failures = 0;
    
    foreach(var test in GetFiles("./validation/ECB*128.rsp"))
    {
        failures += RunTest("./x64/" + configuration + "/cavp.exe", test, "aes128");
    }

    foreach(var test in GetFiles("./validation/CBC*128.rsp"))
    {
        failures += RunTest("./x64/" + configuration + "/cavp.exe", test, "aes128", true);        
    }

    if(failures != 0) throw new Exception("Validation of AES128 Failed");
});

Task("Validate-AES192")
    .Does(() => 
{
    var failures = 0;
    
    foreach(var test in GetFiles("./validation/ECB*192.rsp"))
    {
        failures += RunTest("./x64/" + configuration + "/cavp.exe", test, "aes192");
    }

    foreach(var test in GetFiles("./validation/CBC*192.rsp"))
    {
        failures += RunTest("./x64/" + configuration + "/cavp.exe", test, "aes192", true);        
    }

    if(failures != 0) throw new Exception("Validation of AES192 Failed");
});

Task("Validate-AES256")
    .Does(() => 
{
    var failures = 0;
    
    foreach(var test in GetFiles("./validation/ECB*256.rsp"))
    {
        failures += RunTest("./x64/" + configuration + "/cavp.exe", test, "aes256");
    }

    foreach(var test in GetFiles("./validation/CBC*256.rsp"))
    {
        failures += RunTest("./x64/" + configuration + "/cavp.exe", test, "aes256", true);        
    }

    if(failures != 0) throw new Exception("Validation of AES256 Failed");
});

Task("Validate-AES")
    .IsDependentOn("Validate-AES128")
    .IsDependentOn("Validate-AES192")
    .IsDependentOn("Validate-AES256");
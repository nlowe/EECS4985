#addin "Cake.Powershell"

#l benchmark.cake
#l tests/des.cake
#l tests/aes128.cake
#l validation/common.cake

var target = Argument("target", "Default");
var configuration = Argument("configuration", "Release");

var weakKeySetting = Argument("DisallowWeakKeys", "Yes");
var semiWeakKeySetting = Argument("DisallowSemiWeakKeys", "Yes");
var possiblyWeakKeySetting = Argument("DisallowPossiblyWeakKeys", "Warn");

Task("Clean")
    .Does(() =>
{
    CleanDirectories("./**/x64");
});

Task("Build")
    .Does(() =>
{
    var weakKeyProp         = weakKeySetting == "Yes" ?
        "ENFORCE_NO_WEAK_KEYS" : weakKeySetting == "Warn" ?
            "WARN_WEAK_KEYS" : "NOENFORCE_WEAK_KEYS";
    var semiWeakKeyProp     = semiWeakKeySetting == "Yes" ?
        "ENFORCE_NO_SEMI_WEAK_KEYS" : semiWeakKeySetting == "Warn" ?
            "WARN_SEMI_WEAK_KEYS" : "NOENFORCE_SEMI_WEAK_KEYS";
    var possiblyWeakKeyProp = possiblyWeakKeySetting == "Yes" ?
        "ENFORCE_NO_POSSIBLY_WEAK_KEYS" : possiblyWeakKeySetting == "Warn" ?
            "WARN_POSSIBLY_WEAK_KEYS" : "NOENFORCE_POSSIBLY_WEAK_KEYS";

    Information("Weak Key Setting: " + weakKeyProp);
    Information("Semi-Weak Key Setting: " + semiWeakKeyProp);
    Information("Possibly-Weak Key Setting: " + possiblyWeakKeyProp);

    MSBuild("./EECS4985.sln", cfg => cfg
        .SetConfiguration(configuration)
        .UseToolVersion(MSBuildToolVersion.VS2015)
        .SetMSBuildPlatform(MSBuildPlatform.x64)
        .WithProperty(weakKeyProp, "1")
        .WithProperty(semiWeakKeyProp, "1")
        .WithProperty(possiblyWeakKeyProp, "1")
    );
});



Task("Test")
    .IsDependentOn("Test-DES")
    .IsDependentOn("Test-AES128")
    .IsDependentOn("Validate");

Task("Concat")
    .Does(() =>
{
    StartPowershellFile("./tools/Concat-Files.ps1");
});

Task("Default")
  .IsDependentOn("Build");

RunTarget(target);

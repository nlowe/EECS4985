#r "System.Web"
#addin "Cake.Http"

#l benchmark.cake
#l tests/des.cake
#l tests/aes128.cake
#l validation/common.cake

var target = Argument("target", "Default");
var configuration = Argument("configuration", "Release");

var weakKeySetting = Argument("DisallowWeakKeys", "Yes");
var semiWeakKeySetting = Argument("DisallowSemiWeakKeys", "Yes");
var possiblyWeakKeySetting = Argument("DisallowPossiblyWeakKeys", "Warn");

public void GetPDFTools()
{
    DownloadFile("https://downloads.sourceforge.net/project/gnuwin32/enscript/1.6.3-9/enscript-1.6.3-9-bin.zip", "./tools/enscript.zip");
    Unzip("./tools/enscript.zip", "./tools/enscript");

    DownloadFile("https://sourceforge.net/projects/gnuwin32/files/libiconv/1.9.2-1/libiconv-1.9.2-1-bin.zip", "./tools/enscript/libiconv.zip");
    Unzip("./tools/enscript/libiconv.zip", "./tools/enscript/libiconv");
    CopyFiles("./tools/enscript/libiconv/bin/*.*", "./tools/enscript/bin");
    CopyFile("./tools/enscript/bin/libiconv2.dll", "./tools/enscript/bin/libiconv-2.dll");

    DownloadFile("https://sourceforge.net/projects/gnuwin32/files/libintl/0.11.5-2/libintl-0.11.5-2-bin.zip", "./tools/enscript/libintl.zip");
    Unzip("./tools/enscript/libintl.zip", "./tools/enscript/libintl");
    CopyFiles("./tools/enscript/libintl/bin/*.*", "./tools/enscript/bin");

    DownloadFile("https://github.com/ArtifexSoftware/ghostpdl-downloads/releases/download/gs920/gs920w64.exe", "./tools/enscript/gs.exe");
    EnsureDirectoryExists("./tools/enscript/gs");
    StartProcess("./tools/7z/7z.exe", new ProcessSettings().WithArguments(arg => { arg
        .Append("x")
        .Append("-y")
        .Append("-otools\\enscript\\gs")
        .Append("tools\\enscript\\gs.exe");
    }));
    CopyFiles("./tools/enscript/gs/bin/*.*", "./tools/enscript/bin");
}

public IEnumerable<FilePath> GetManyFiles(params string[] globs)
{
    List<FilePath> result = new List<FilePath>();

    foreach(var glob in globs)
    {
        result.AddRange(GetFiles(glob));
    }

    return result;
}

public void MakePDF(string path, string src)
{
    if(!DirectoryExists("./tools/enscript"))
    {
        GetPDFTools();
    }

    Verbose("Generating PostScript Document");
    StartProcess("./tools/enscript/bin/enscript.exe", new ProcessSettings()
        .UseWorkingDirectory("./tools/enscript/bin")
        .WithArguments(arg => { arg
            .Append("--no-header")
            .Append("--color=1")
            .Append("--output=tmp.ps")
            .Append("--margins=2:2:2:2")
            .Append("-Ecpp")
            .Append("-fCourier8")
            .Append("-M Letter")
            .AppendQuoted(src);
        })
    );

    Verbose("Generating PDF");
    StartProcess("./tools/enscript/bin/gswin64c.exe", new ProcessSettings()
        .UseWorkingDirectory("./tools/enscript/bin")
        .WithArguments(arg => { arg
            .Append("-dBATCH")
            .Append("-dNOPAUSE")
            .Append("-sDEVICE=pdfwrite")
            .Append("-sOutputFile=\"" + path + "\"")
            .Append("tmp.ps");
        })
    );

    DeleteFile("./tools/enscript/bin/tmp.ps");
}

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

Task("Concat-AES")
    .Does(() => 
{
    var target = File("./aes.cxx");
    var pdf = File("./aes.cxx.pdf");
    if(FileExists(target))
    {
        DeleteFile(target);
    }

    if(FileExists(pdf))
    {
        DeleteFile(pdf);
    }

    var root = MakeAbsolute(Directory(".").Path);
    var cxx = new StringBuilder();

    foreach(var file in GetManyFiles("./AES/*.cpp", "./AES/*.h", "./libcrypto/*.cpp", "./libcrypto/*.h", "./libcrypto/AES/**/*.cpp", "./libcrypto/AES/**/*.h"))
    {
        var p = root.GetRelativePath(MakeAbsolute(file));
        Verbose("Appending " + p);
        cxx.AppendLine("//////////////////////////////////////////////////////////");
        cxx.AppendLine("//    " + p);
        cxx.AppendLine("//////////////////////////////////////////////////////////");
        cxx.AppendLine();
        cxx.AppendLine(System.IO.File.ReadAllText(file.FullPath));
        cxx.AppendLine();
        cxx.AppendLine();
    }

    System.IO.File.WriteAllText(target.Path.FullPath, cxx.ToString().Trim());
    MakePDF(MakeAbsolute(pdf.Path).FullPath, MakeAbsolute(target.Path).FullPath);
    Information("Created " + target);
});

Task("Concat")
    .IsDependentOn("Concat-AES");

Task("Default")
  .IsDependentOn("Build");

RunTarget(target);

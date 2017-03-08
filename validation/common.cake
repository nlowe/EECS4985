#l aes.cake

int RunTest(FilePath cavp, FilePath test, string algorithmName, bool cbc = false)
{
    Information("Running CAV " + test.FullPath);

    int failures = 0;
    var lines = System.IO.File.ReadAllLines(test.FullPath);

    var modeString = "e";

    var key = "";
    var iv = "";
    var plaintext = "";
    var ciphertext = "";

    foreach(var line in lines)
    {
        if(string.IsNullOrWhiteSpace(line) || line.StartsWith("#")) continue;
        else if(line.Contains("DECRYPT")) modeString = "d";
        else if(line.StartsWith("KEY")) key = line.Split('=')[1].Trim();
        else if(line.StartsWith("IV")) iv = line.Split('=')[1].Trim();
        else if(line.StartsWith("PLAINTEXT")) plaintext = line.Split('=')[1].Trim();
        else if(line.StartsWith("CIPHERTEXT")) ciphertext = line.Split('=')[1].Trim();

        if(!string.IsNullOrEmpty(key) && !string.IsNullOrEmpty(plaintext) && !string.IsNullOrEmpty(ciphertext))
        {
            if(cbc && !string.IsNullOrEmpty(iv))
            {
               var rc = StartProcess(cavp, new ProcessSettings().WithArguments(args => args
                    .Append(algorithmName)
                    .Append(modeString)
                    .Append(key)
                    .Append(modeString == "e" ? plaintext : ciphertext)
                    .Append(modeString == "e" ? ciphertext : plaintext)
                    .Append(iv)
                ));
                Information(algorithmName + " " + modeString + " K=" + key + " IV=" + iv + " P=" + plaintext + " C=" + ciphertext + (rc == 0 ? "...PASS" : "...FAIL"));

                if(rc != 0)                
                {
                    Warning("CAVP Failed with RC " + rc);
                    failures++;
                }

                key = plaintext = ciphertext = iv = "";
            }
            else if(!cbc)
            {
                var rc = StartProcess(cavp, new ProcessSettings().WithArguments(args => args
                    .Append(algorithmName)
                    .Append(modeString)
                    .Append(key)
                    .Append(modeString == "e" ? plaintext : ciphertext)
                    .Append(modeString == "e" ? ciphertext : plaintext)
                    .Append(iv)
                ));
                Information(algorithmName + " " + modeString + " K=" + key + " P=" + plaintext + " C=" + ciphertext + (rc == 0 ? "...PASS" : "...FAIL"));

                if(rc != 0)                
                {
                    Warning("CAVP Failed with RC " + rc);
                    failures++;
                }

                key = plaintext = ciphertext = "";
            }
        }
    }

    return failures;
}

Task("Validate")
    .IsDependentOn("Build")
    .IsDependentOn("Validate-AES");
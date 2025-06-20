$files = Get-ChildItem -Path "src/main/java/burp" -Filter "I*.java"
foreach ($file in $files) {
    $content = Get-Content $file.FullName
    $newContent = $content -replace "package burp;", "package main.java.burp;"
    Set-Content -Path $file.FullName -Value $newContent
    Write-Host "Updated: $($file.Name)"
} 
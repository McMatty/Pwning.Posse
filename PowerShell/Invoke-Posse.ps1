
Clear-Host

try 
{    
    Set-Location "C:\github\Pwning posse\Pwning.Posse.Analyzer\Pwning.Posse.Analyzer\bin\Debug\netstandard2.0"   
    Add-Type -AssemblyName Pwning.Posse.Common
    $o = Add-Type -AssemblyName Pwning.Posse.Tracker -PassThru


}
catch 
{
   Write-Host "Message: $($_.Exception.Message)"
   Write-Host "StackTrace: $($_.Exception.StackTrace)"
   Write-Host "LoaderExceptions: $($_.Exception.LoaderExceptions)"
}
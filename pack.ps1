# install: choco install nuget.commandline
nuget restore source\NHibernate.AspNetCore.Identity.sln
$vsDir = Invoke-Expression "& '$(${env:ProgramFiles(x86)})\Microsoft Visual Studio\Installer\vswhere.exe' -latest -nologo -format value -property installationPath"
$msbuild = Join-Path -Path $vsDir -ChildPath 'MSBuild\15.0\Bin\msbuild.exe'
Invoke-Expression "& '$msbuild' source\NHibernate.AspNetCore.Identity.sln /t:'Clean;Rebuild' /p:Configuration=Release"
packages\NUnit.Runners.2.6.4\tools\nunit-console-x86.exe source\NHibernate.AspNetCore.Identity.Tests\bin\Release\NHibernate.AspNetCore.Identity.Tests.dll
nuget pack source\NHibernate.AspNetCore.Identity\NHibernate.AspNetCore.Identity.csproj -Prop Configuration=Release
pause
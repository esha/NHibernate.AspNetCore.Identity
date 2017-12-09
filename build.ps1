# install: choco install nuget.commandline
nuget restore source\NHibernate.AspNetCore.Identity.sln
$vsDir = Invoke-Expression "& '$(${env:ProgramFiles(x86)})\Microsoft Visual Studio\Installer\vswhere.exe' -latest -nologo -format value -property installationPath"
$msbuild = Join-Path -Path $vsDir -ChildPath 'MSBuild\15.0\Bin\msbuild.exe'
Invoke-Expression "& '$msbuild' source\NHibernate.AspNetCore.Identity.sln"
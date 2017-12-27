@setlocal

@rem Initialize Visual Studio build environment:
@rem - Visual Studio 2017 Community/Professional/Enterprise is the preferred option
@rem - Visual Studio 2015 is the fallback option (which might or might not work)
@set tools=
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio 14.0\Common7\Tools\vsvars32.bat"
@if exist %tmptools% set tools=%tmptools%
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio\2017\Community\Common7\Tools\VsMSBuildCmd.bat"
@if exist %tmptools% set tools=%tmptools%
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio\2017\Professional\Common7\Tools\VsMSBuildCmd.bat"
@if exist %tmptools% set tools=%tmptools%
@set tmptools="c:\Program Files (x86)\Microsoft Visual Studio\2017\Enterprise\Common7\Tools\VsMSBuildCmd.bat"
@if exist %tmptools% set tools=%tmptools%
@if not defined tools goto :error
call %tools%
@echo on

@rem Delete output directory
rmdir /S /Q net461

@rem Clean solution
msbuild ..\src\Pkcs11Interop.X509Store.sln ^
	/p:Configuration=Release /p:Platform="Any CPU" /p:TargetFrameworkVersion=v4.6.1 ^
	/target:Clean || goto :error

@rem Build Pkcs11Interop.X509Store project
msbuild ..\src\Pkcs11Interop.X509Store\Pkcs11Interop.X509Store.csproj ^
	/p:Configuration=Release /p:Platform=AnyCPU /p:TargetFrameworkVersion=v4.6.1 ^
	/target:Build || goto :error

@rem Copy result to output directory
mkdir net461 || goto :error
copy ..\src\Pkcs11Interop.X509Store\bin\Release\Pkcs11Interop.X509Store.dll net461 || goto :error
copy ..\src\Pkcs11Interop.X509Store\bin\Release\Pkcs11Interop.X509Store.xml net461 || goto :error

@echo *** BUILD NET461 SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** BUILD NET461 FAILED ***
@endlocal
@exit /b 1

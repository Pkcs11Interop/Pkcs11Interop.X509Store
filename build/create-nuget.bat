@setlocal

set NUGET=c:\nuget\nuget.exe 

@rem Delete output directory
rmdir /S /Q nuget

@rem Create output directories
mkdir nuget\lib\net461 || goto :error

@rem Copy assemblies to output directories
copy net461\Pkcs11Interop.X509Store.dll nuget\lib\net461 || goto :error
copy net461\Pkcs11Interop.X509Store.xml nuget\lib\net461 || goto :error

@rem Copy license to output directory
copy ..\src\Pkcs11Interop.X509Store\LICENSE.txt nuget || goto :error
copy ..\src\Pkcs11Interop.X509Store\NOTICE.txt nuget || goto :error

@rem Create package
copy Pkcs11Interop.X509Store.nuspec nuget || goto :error
%NUGET% pack nuget\Pkcs11Interop.X509Store.nuspec || goto :error

@echo *** CREATE NUGET SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** CREATE NUGET FAILED ***
@endlocal
@exit /b 1

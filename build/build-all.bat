@setlocal

call build-net461.bat || goto :error

@echo *** BUILD ALL SUCCESSFUL ***
@endlocal
@exit /b 0

:error
@echo *** BUILD ALL FAILED ***
@endlocal
@exit /b 1

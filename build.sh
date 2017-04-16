#!/bin/bash
pushd tests/AuthenticodeLint.Core.Tests
dotnet restore AuthenticodeLint.Core.Tests.csproj
dotnet test 
RES=$?
popd
exit $RES

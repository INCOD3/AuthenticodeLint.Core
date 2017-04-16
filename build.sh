#!/bin/bash
dotnet restore AuthenticodeLint.sln
dotnet test tests/AuthenticodeLint.Core.Tests/AuthenticodeLint.Core.Tests.csproj
RES=$?
exit $RES

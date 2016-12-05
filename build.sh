#!/bin/bash
dotnet restore
cd tests/AuthenticodeLint.Core.Tests
dotnet test 
RES=$?
exit $RES

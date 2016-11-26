AuthenticodeLint.Core
===========

# About

AuthenticodeLint.Core is a work-in-progress rewrite and port of the [AuthenticodeLint][1]
project to .NET Core. As AuthenticodeLint relied heavily on Win32 APIs, a simple port would
not work. This project aims to not depend on any external libraries of the operating system,
if possible. It includes a fully managed and platform agnostic PE reader, ASN.1 parser, and 
x509 parser.
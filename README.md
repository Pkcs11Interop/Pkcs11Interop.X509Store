Pkcs11Interop.X509Store
=======================
**Easy to use PKCS#11 based X.509 certificate store**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/Pkcs11Interop/Pkcs11Interop.X509Store/blob/master/LICENSE.md)
[![NuGet](https://img.shields.io/badge/nuget-pkcs11interop-blue.svg)](https://www.nuget.org/packages/Pkcs11Interop.X509Store/)
[![Twitter](https://img.shields.io/badge/twitter-p11interop-blue.svg)](https://twitter.com/p11interop)

## Table of Contents

* [Overview](#overview)
* [Documentation](#documentation)
* [Download](#download)
* [License](#license)
* [Support](#support)
* [Related projects](#related-projects)
* [About](#about)

## Overview

PKCS#11 is cryptography standard maintained by the OASIS PKCS 11 Technical Committee (originally published by RSA Laboratories) that defines ANSI C API to access smart cards and other types of cryptographic hardware.

Pkcs11Interop is managed library written in C# that brings full power of PKCS#11 API to the .NET environment. It loads unmanaged PKCS#11 library provided by the cryptographic device vendor and makes its functions accessible to .NET application.

Pkcs11Interop.X509Store is managed library built on top of Pkcs11Interop. It's main goal is to provide easy to use PKCS#11 based read-only X.509 certificate store that can be easily integrated with standard .NET ecosystem.

**WARNING: Pkcs11Interop.X509Store is still in a very early stage of development and its API may change with any subsequent release.**

## Documentation

Pkcs11Interop.X509Store API is fully documented with the inline XML documentation that is displayed by the most of the modern IDEs during the application development.

## Download

Archives with the source code and binaries can be downloaded from [our releases page](https://github.com/Pkcs11Interop/Pkcs11Interop.X509Store/releases/). [Official NuGet packages](https://www.nuget.org/packages/Pkcs11Interop.X509Store/) are published in nuget.org repository. All official items are signed with [GnuPG key or code-signing certificate of Jaroslav Imrich](https://www.jimrich.sk/crypto/).

## License

Pkcs11Interop.X509Store is available under the terms of the [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0).  
[Human friendly license summary](https://tldrlegal.com/l/apache2) is available at tldrlegal.com but the [full license text](LICENSE.md) always prevails.

## Support

Pkcs11Interop.X509Store is still in a very early stage of development so if you need help, please open an issue in our public [issue tracker](https://github.com/Pkcs11Interop/Pkcs11Interop.X509Store/issues).

## Related projects

* [Pkcs11Interop](http://www.pkcs11interop.net/)  
  Managed .NET wrapper for unmanaged PKCS#11 libraries.
* [Pkcs11Admin](http://www.pkcs11admin.net/)  
  GUI tool for administration of PKCS#11 enabled devices based on Pkcs11Interop library.
* [PKCS11-LOGGER](https://github.com/Pkcs11Interop/pkcs11-logger)  
  PKCS#11 logging proxy module useful for debugging of PKCS#11 enabled applications.
* [SoftHSM2-for-Windows](https://github.com/disig/SoftHSM2-for-Windows)  
  Pure software implementation of a cryptographic store accessible through a PKCS#11 interface.

## About

Pkcs11Interop.X509Store has been written for the Pkcs11Interop project by [Jaroslav Imrich](http://www.jimrich.sk).  
Please visit project website - [pkcs11interop.net](http://www.pkcs11interop.net) - for more information.

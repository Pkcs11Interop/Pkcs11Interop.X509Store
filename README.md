Pkcs11Interop.X509Store
=======================
**Easy to use PKCS#11 based X.509 certificate store**

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](https://github.com/Pkcs11Interop/Pkcs11Interop.X509Store/blob/master/LICENSE.md)
[![AppVeyor](https://ci.appveyor.com/api/projects/status/l5hr66s6dnmajh0y/branch/master?svg=true)](https://ci.appveyor.com/project/pkcs11interop/pkcs11interop-x509store/branch/master)
[![NuGet](https://img.shields.io/badge/nuget-pkcs11interop.x509store-blue.svg)](https://www.nuget.org/packages/Pkcs11Interop.X509Store/)
[![Stack Overflow](https://img.shields.io/badge/stack-pkcs11interop-blue.svg)](https://stackoverflow.com/questions/tagged/pkcs11interop)
[![Twitter](https://img.shields.io/badge/twitter-p11interop-blue.svg)](https://twitter.com/p11interop)

## Overview

The PKCS#11 API offers unparalleled versatility and functionality across platforms and cryptographic scenarios. However, its inherent complexity, rooted in C language design and low-level concepts, can present a steep learning curve for developers. [Pkcs11Interop](https://github.com/Pkcs11Interop/Pkcs11Interop) emerged as a .NET wrapper for PKCS#11, aiming to provide a more developer-friendly interface while retaining the full power of the underlying PKCS#11 API. Despite its advancements, Pkcs11Interop still demands a deep understanding of cryptographic principles and the PKCS#11 specification, making it challenging to use correctly. To bridge this gap, Pkcs11Interop.X509Store comes into play.

Pkcs11Interop.X509Store is born out of the necessity to simplify the integration of PKCS#11 into .NET applications. Designed to cover common use cases seamlessly, Pkcs11Interop.X509Store eliminates the need for developers to delve into low-level PKCS#11 intricacies. By abstracting away the complexities, it provides a straightforward, intuitive interface that seamlessly integrates with other .NET classes.

## Documentation

Pkcs11Interop.X509Store API is fully documented with the inline XML documentation that is displayed by the most of the modern IDEs during the application development.

The following topics are covered by standalone documents:
* [Basic PKCS#11 related terms](doc/01_BASIC_TERMS.md)
* [Architecture of the Pkcs11Interop.X509Store library](doc/02_ARCHITECTURE.md)
* [Getting started with Pkcs11Interop.X509Store](doc/03_GETTING_STARTED.md)
* [Pkcs11Interop.X509Store code samples](doc/04_CODE_SAMPLES.md)
* [Frequently Asked Questions](doc/05_FAQ.md)

## Download

[Official NuGet packages](https://www.nuget.org/packages/Pkcs11Interop.X509Store/) are published in nuget.org repository.  
Archives with the source code and binaries can be downloaded from [our releases page](https://github.com/Pkcs11Interop/Pkcs11Interop.X509Store/releases/).  
All official items are signed with [GnuPG key or code-signing certificate of Jaroslav Imrich](https://www.jimrich.sk/crypto/).

## License

Pkcs11Interop.X509Store is available under the terms of the [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0).  
[Human friendly license summary](https://www.tldrlegal.com/license/apache-license-2-0-apache-2-0) is available at tldrlegal.com but the [full license text](LICENSE.md) always prevails.

## Support

Have you found a bug, want to suggest a new feature, or just need help?  
Don't hesitate to open an issue in our public [issue tracker](https://github.com/Pkcs11Interop/Pkcs11Interop.X509Store/issues).

## Related projects

* [Pkcs11Interop](https://www.pkcs11interop.net/)  
  Managed .NET wrapper for unmanaged PKCS#11 libraries.
* [Pkcs11Admin](https://www.pkcs11admin.net/)  
  GUI tool for administration of PKCS#11 enabled devices based on Pkcs11Interop library.
* [PKCS11-LOGGER](https://github.com/Pkcs11Interop/pkcs11-logger)  
  PKCS#11 logging proxy module useful for debugging of PKCS#11 enabled applications.
* [SoftHSM2-for-Windows](https://github.com/disig/SoftHSM2-for-Windows)  
  Pure software implementation of a cryptographic store accessible through a PKCS#11 interface.
* [Bouncy HSM](https://github.com/harrison314/BouncyHsm)  
  HSM and smartcard simulator with HTML UI, REST API and PKCS#11 interface.

## About

Pkcs11Interop.X509Store has been written for the Pkcs11Interop project by [Jaroslav Imrich](https://www.jimrich.sk).  
Please visit project website - [pkcs11interop.net](https://www.pkcs11interop.net) - for more information.

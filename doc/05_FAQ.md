# Frequently Asked Questions

## When should I use Pkcs11Interop.X509Store?

Pkcs11Interop.X509Store is a suitable choice if you are developing an application intended for **platforms beyond just Windows**. Your application will perform signing or encryption with RSA or EC keys associated with an X.509 certificate, and those keys will be stored in a hardware device such as a smartcard or HSM.

## When should I avoid using Pkcs11Interop.X509Store?

Pkcs11Interop.X509Store may not be the ideal choice if you are developing an application intended **only for Windows** and your cryptographic device has proper integration with the Windows OS via [CAPI/CNG](https://en.wikipedia.org/wiki/Microsoft_CryptoAPI) (CSP, KSP, minidriver, etc.). In that case, it is better to use the built-in [`X509Store`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store) instead.

## What operating systems are supported?

Pkcs11Interop.X509Store is periodically tested on Windows, Linux and macOS. It works on both 32-bit and 64-bit platforms.

## What .NET runtimes are supported?

Pkcs11Interop.X509Store is compatible with .NET Framework 4.6.2 and newer, .NET 5 and newer, and a [few other runtimes](https://www.nuget.org/packages/Pkcs11Interop.X509Store#supportedframeworks-body-tab).

## What algorithms are supported?

Pkcs11Interop.X509Store supports the following digital signature schemes:
  - `ECDSA` with at least `MD5`, `SHA1`, `SHA256`, `SHA384` and `SHA512` hashes
  - `RSASSA-PKCS1-v1_5` (RSA PKCS#1) with `MD5`, `SHA1`, `SHA256`, `SHA384` and `SHA512` hashes
  - `RSASSA-PSS` (RSA PSS) with `SHA1`, `SHA256`, `SHA384` and `SHA512` hashes

Pkcs11Interop.X509Store also supports following encryption schemes:
  - `RSAES-PKCS1-v1_5` (RSA PKCS#1)
  - `RSAES-OAEP` (RSA OAEP) with `SHA1`, `SHA256`, `SHA384` and `SHA512` hashes

Please note that your PKCS#11 library might not support all of these algorithms.

## How does Pkcs11Interop.X509Store pair certificate and key objects?

In order for Pkcs11Interop.X509Store to work correctly with a certificate and its corresponding private and public keys stored on your cryptographic device, all three objects must have exactly the same value of the `CKA_ID` attribute. If needed, you can edit the value of this attribute using the [Pkcs11Admin](https://www.pkcs11admin.net) application.

## Can Pkcs11Interop.X509Store work with keys that are not associated with X.509 certificate?

No, it cannot. The idea here is to provide an experience similar to the built-in [`X509Store`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store) class, which also works only with certificates. If you only have keys stored on your device and you want to use them with Pkcs11Interop.X509Store, you can use [XCA](https://hohnstaedt.de/xca/) to generate a self-signed certificate.

## Can Pkcs11Interop.X509Store work with symmetric keys (e.g. 3DES keys, AES keys, etc.)?

No, it cannot. The idea here is to provide an experience similar to the built-in [`X509Store`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509store) class, which also works only with certificates. If you need to work with symmetric keys, you'll need to use the [Pkcs11Interop](https://github.com/Pkcs11Interop/Pkcs11Interop) library directly.

## Can Pkcs11Interop.X509Store create new objects on my cryptographic device?

No, it cannot. Pkcs11Interop.X509Store currently operates with your device solely in read-only mode.

## Can I use Pkcs11Interop.X509Store in a multi-threaded application?

Yes, in general, it is safe to access the same instance of the `Pkcs11X509Store` class from multiple threads. However, when you want to use multiple instances of the `Pkcs11X509Store` class, you need to be aware of a few limitations.

When you create an instance of the `Pkcs11X509Store` class, the unmanaged PKCS#11 library is loaded into your process, and when you dispose it, the PKCS#11 library is unloaded from your process. Therefore, it is crucial to ensure that two instances of this class, working with the same PKCS#11 library, do not overlap each other.

It is also crucial to ensure that you do not dispose of an instance of the `Pkcs11X509Store` class while you are still working with any of the objects provided by it (e.g. `Pkcs11Slot`, `Pkcs11Token`, `Pkcs11X509Certificate`, etc.).

## Why does Pkcs11Interop.X509Store return `Pkcs11X509Certificate` instead of `X509Certificate2`?

It would certainly be convenient, as [`X509Certificate2`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.x509certificate2) is a built-in class used by many .NET APIs. However, `X509Certificate2` is also a relic from the early 2000s when Microsoft focused exclusively on Windows platform and did not design/implement it with extensibility in mind. While `X509Certificate2` seems reasonable at first, it cannot be extended with a custom implementation of [`AsymmetricAlgorithm`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.asymmetricalgorithm). There's been an [issue #22856](https://github.com/dotnet/runtime/issues/22856) opened in the dotnet/runtime repository since 2017 that could partially address its limitations, but personally, I do not expect it to be resolved in the foreseeable future.

## Can I use a certificate from Pkcs11Interop.X509Store for SSL connections?

No, you cannot. SSL connections in .NET are handled by platform-specific native libraries (SChannel on Windows, OpenSSL on Linux, etc.), and these libraries cannot call back to a managed implementation of [`AsymmetricAlgorithm`](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.asymmetricalgorithm) with a non-exportable private key.
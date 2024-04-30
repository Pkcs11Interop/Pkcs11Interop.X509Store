# Pkcs11Interop.X509Store code samples

Pkcs11Interop.X509Store source code contains unit tests that also serve as official code samples.

**WARNING: Our documentation and code samples do not cover the theory of security/cryptography or the strengths/weaknesses of specific algorithms. You should always understand what you are doing and why. Please do not simply copy our code samples and expect it to fully solve your usage scenario. Cryptography is an advanced topic and one should consult a solid and preferably recent reference in order to make the best of it.**

Following source files contain valuable code samples:

* Test file: [SignedCmsTest.cs](../src/Pkcs11Interop.X509Store.Tests/SignedCmsTest.cs)  
  Demonstrates how to create CMS signature with [`SignedCms` class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.pkcs.signedcms) and PKCS#11 based certificate and private key.

* Test file: [SignedXmlTest.cs](../src/Pkcs11Interop.X509Store.Tests/SignedXmlTest.cs)  
  Demonstrates how to create XML signature with [`SignedXml` class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.xml.signedxml) and PKCS#11 based certificate and private key.

* Test file: [CertificateRequestTest.cs](../src/Pkcs11Interop.X509Store.Tests/CertificateRequestTest.cs)  
  Demonstrates how to sign X.509 certificate with [`CertificateRequest` class](https://learn.microsoft.com/en-us/dotnet/api/system.security.cryptography.x509certificates.certificaterequest) and PKCS#11 based certificate and private key.

[Next page >](05_FAQ.md)
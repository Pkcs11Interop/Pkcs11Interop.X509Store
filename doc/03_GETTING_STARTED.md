# Getting started with Pkcs11Interop.X509Store

Follow the instructions provided by the vendor of your cryptographic device to install and configure the device along with all the required support software. Consult device documentation to determine the exact location of unmanaged PKCS#11 library provided by the device vendor.

Create new C# console application project in Visual Studio and install [Pkcs11Interop.X509Store NuGet package](https://www.nuget.org/packages/Pkcs11Interop.X509Store/) with [NuGet Package Manager UI](https://docs.microsoft.com/en-us/nuget/tools/package-manager-ui#finding-and-installing-a-package) or any other tool of your choice. Replace contents of `Program.cs` file in your project with the following code which displays basic information about your unmanaged PKCS#11 library and the resources it can access.

**WARNING: Don't forget to replace the value of `pkcs11LibraryPath` variable.**

```csharp
using System;
using System.Text;
using Net.Pkcs11Interop.X509Store;

namespace ConsoleApp1
{
    internal class Program
    {
        // Implement your own provider of PIN codes
        private class MyPinProvider : IPinProvider
        {
            // This method is executed automatically whenever Pkcs11X509Store needs a PIN code for PKCS#11 token
            public GetPinResult GetTokenPin(Pkcs11X509StoreInfo storeInfo, Pkcs11SlotInfo slotInfo, Pkcs11TokenInfo tokenInfo)
            {
                if (tokenInfo.HasProtectedAuthenticationPath)
                {
                    Console.Write("Please use protected authentication path to enter token PIN...");
                    return new GetPinResult(cancel: false, pin: null);
                }
                else
                {
                    string pin = null;
                    while (string.IsNullOrEmpty(pin))
                    {
                        Console.Write("Please enter token PIN and press ENTER: ");
                        pin = Console.ReadLine();
                    }

                    return new GetPinResult(cancel: false, pin: Encoding.UTF8.GetBytes(pin));
                }
            }

            // This method is executed automatically whenever Pkcs11X509Store needs a PIN code for a private key stored on PKCS#11 token
            public GetPinResult GetKeyPin(Pkcs11X509StoreInfo storeInfo, Pkcs11SlotInfo slotInfo, Pkcs11TokenInfo tokenInfo, Pkcs11X509CertificateInfo certificateInfo)
            {
                Console.WriteLine("Cancelling request for key PIN...");
                return new GetPinResult(cancel: true, pin: null);
            }
        }

        static void Main(string[] args)
        {
            // Specify the path to unmanaged PKCS#11 library provided by the cryptographic device vendor
            string pkcs11LibraryPath = @"c:\SoftHSM2\lib\softhsm2-x64.dll";

            // Specify the provider of PIN codes for PKCS#11 tokens and keys
            IPinProvider pinProvider = new MyPinProvider();

            // Load PKCS#11 library and initialize the store
            using (var pkcs11Store = new Pkcs11X509Store(pkcs11LibraryPath, pinProvider))
            {
                // Show general information about the loaded library
                Console.WriteLine("Library");
                Console.WriteLine("  Path:               " + pkcs11Store.Info.LibraryPath);
                Console.WriteLine("  Manufacturer:       " + pkcs11Store.Info.Manufacturer);
                Console.WriteLine("  Description:        " + pkcs11Store.Info.Description);

                // Get list of all available slots
                foreach (var slot in pkcs11Store.Slots)
                {
                    Console.WriteLine();

                    // Show basic information about the slot
                    Console.WriteLine("Slot");
                    Console.WriteLine("  Manufacturer:       " + slot.Info.Manufacturer);
                    Console.WriteLine("  Description:        " + slot.Info.Description);

                    // Continue only if there is a token present in the slot
                    if (slot.Token == null)
                        continue;

                    // Show basic information about the token
                    Console.WriteLine("Token");
                    Console.WriteLine("  Manufacturer:       " + slot.Token.Info.Manufacturer);
                    Console.WriteLine("  Model:              " + slot.Token.Info.Model);
                    Console.WriteLine("  Serial number:      " + slot.Token.Info.SerialNumber);
                    Console.WriteLine("  Label:              " + slot.Token.Info.Label);
                    Console.WriteLine("  Initialized:        " + slot.Token.Info.Initialized);

                    // Continue only if the token is initialized and thus usable
                    if (!slot.Token.Info.Initialized)
                        continue;

                    // Show basic information about the certificates stored on the token
                    foreach (var certificate in slot.Token.Certificates)
                    {
                        Console.WriteLine("Certificate");
                        Console.WriteLine("  Subject:            " + certificate.Info.ParsedCertificate.Subject);
                        Console.WriteLine("  Issuer:             " + certificate.Info.ParsedCertificate.Issuer);
                        Console.WriteLine("  Serial number:      " + certificate.Info.ParsedCertificate.SerialNumber);
                        Console.WriteLine("  Not before:         " + certificate.Info.ParsedCertificate.NotBefore);
                        Console.WriteLine("  Not after:          " + certificate.Info.ParsedCertificate.NotAfter);
                        Console.WriteLine("  Thumbprint:         " + certificate.Info.ParsedCertificate.Thumbprint);
                        Console.WriteLine("  Key type:           " + certificate.Info.KeyType);
                        Console.WriteLine("  Public key found:   " + certificate.HasPublicKeyObject);
                        Console.WriteLine("  Private key found:  " + certificate.HasPrivateKeyObject);
                    }
                }
            }
        }
    }
}

```

When you execute your application you should get output similar to this one:

```
Library
  Path:               c:\SoftHSM2\lib\softhsm2-x64.dll
  Manufacturer:       SoftHSM
  Description:        Implementation of PKCS11

Slot
  Manufacturer:       SoftHSM project
  Description:        SoftHSM slot ID 0x5b7c1004
Token
  Manufacturer:       SoftHSM project
  Model:              SoftHSM v2
  Serial number:      2266f7585b7c1004
  Label:              First token
  Initialized:        True
Please enter token PIN and press ENTER: 11111111
Certificate
  Subject:            CN=TEST CA, L=Bratislava, C=SK
  Issuer:             CN=TEST CA, L=Bratislava, C=SK
  Serial number:      01
  Not before:         12/27/2017 1:00:00 AM
  Not after:          12/27/2117 12:59:59 AM
  Thumbprint:         8747C52EEBAB2BB1BCF2B65E690E34AE4AC04A81
  Key type:           RSA
  Public key found:   False
  Private key found:  False
Certificate
  Subject:            CN=TEST USER ECDSA, L=Bratislava, C=SK
  Issuer:             CN=TEST CA, L=Bratislava, C=SK
  Serial number:      03
  Not before:         12/27/2017 1:00:00 AM
  Not after:          12/27/2117 12:59:59 AM
  Thumbprint:         15345A1E84D0EF4CFEA09011A53522A75FF3D4A9
  Key type:           EC
  Public key found:   True
  Private key found:  True
Certificate
  Subject:            CN=TEST USER RSA, L=Bratislava, C=SK
  Issuer:             CN=TEST CA, L=Bratislava, C=SK
  Serial number:      02
  Not before:         12/27/2017 1:00:00 AM
  Not after:          12/27/2117 12:59:59 AM
  Thumbprint:         B4005885C700ADF1383652D03A39F9E079949688
  Key type:           RSA
  Public key found:   True
  Private key found:  True

Slot
  Manufacturer:       SoftHSM project
  Description:        SoftHSM slot ID 0x1
Token
  Manufacturer:       SoftHSM project
  Model:              SoftHSM v2
  Serial number:
  Label:
  Initialized:        False
```

That's it! You have successfully used unmanaged PKCS#11 library in your .NET application.

[Next page >](04_CODE_SAMPLES.md)
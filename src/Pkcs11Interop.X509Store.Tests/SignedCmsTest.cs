using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Text;
using Net.Pkcs11Interop.X509Store.Tests.SoftHsm2;
using NUnit.Framework;

namespace Net.Pkcs11Interop.X509Store.Tests
{
    [TestFixture()]
    public class SignedCmsTest
    {
#if NETCOREAPP3_0_OR_GREATER
        [Test()]
        public void BasicSignedCmsTest()
        {
            // Load PKCS#11 based store
            using (var pkcs11Store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                // Find signing certificate
                Pkcs11X509Certificate pkcs11Cert = Helpers.GetCertificate(pkcs11Store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                // Get PKCS#11 based private key
                AsymmetricAlgorithm pkcs11PrivKey = pkcs11Cert.GetPrivateKey();

                // Create signature with SignedCms class and PKCS#11 based private key
                byte[] dataToSign = Encoding.UTF8.GetBytes("Hello world!");
                ContentInfo contentInfo = new ContentInfo(dataToSign);
                SignedCms signedCms = new SignedCms(contentInfo);
                CmsSigner cmsSigner = new CmsSigner(SubjectIdentifierType.IssuerAndSerialNumber, pkcs11Cert.Info.ParsedCertificate, pkcs11PrivKey);
                signedCms.ComputeSignature(cmsSigner);
                byte[] encodedCms = signedCms.Encode();

                // Verify signature
                signedCms = new SignedCms();
                signedCms.Decode(encodedCms);
                signedCms.CheckSignature(true);
            }
        }
#endif
    }
}

/*
 *  Copyright 2017-2022 The Pkcs11Interop Project
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 *  Written for the Pkcs11Interop project by:
 *  Jaroslav IMRICH <jimrich@jimrich.sk>
 */

using System;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Net.Pkcs11Interop.X509Store.Tests.SoftHsm2;
using NUnit.Framework;

namespace Net.Pkcs11Interop.X509Store.Tests
{
    [TestFixture()]
    public class CertificateRequestTest
    {
        [Test()]
        public void BasicRsaCertificateRequestTest()
        {
            // Load PKCS#11 based store
            using (var pkcs11Store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                // Find signing certificate (CA certificate)
                Pkcs11X509Certificate pkcs11CertOfCertificateAuthority = Helpers.GetCertificate(pkcs11Store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                // Generate new key pair for end entity
                RSA rsaKeyPairOfEndEntity = RSA.Create(2048);

                // Define certificate request
                CertificateRequest certificateRequest = new CertificateRequest(
                    new X500DistinguishedName("C=SK,L=Bratislava,CN=BasicRsaCertificateRequestTest"),
                    rsaKeyPairOfEndEntity,
                    HashAlgorithmName.SHA256,
                    RSASignaturePadding.Pkcs1);
                    
                // Define certificate extensions
                certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));
                certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

                // Issue X.509 certificate for end entity
                X509Certificate2 certificateOfEndEntity = certificateRequest.Create(
                    pkcs11CertOfCertificateAuthority.Info.ParsedCertificate.SubjectName,
                    X509SignatureGenerator.CreateForRSA(pkcs11CertOfCertificateAuthority.GetRSAPrivateKey(), RSASignaturePadding.Pkcs1),
                    DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow.AddDays(365),
                    new BigInteger(1).ToByteArray());

                // Verify signature on X.509 certificate for end entity
                Assert.IsTrue(CaCertSignedEndEntityCert(pkcs11CertOfCertificateAuthority.Info.ParsedCertificate.RawData, certificateOfEndEntity.RawData));

                // Asociate end entity certificate with its private key
                certificateOfEndEntity = certificateOfEndEntity.CopyWithPrivateKey(rsaKeyPairOfEndEntity);

                // Export end entity certificate to PKCS#12 file
                string basePath = Helpers.GetBasePath();
                string pkcs12FilePath = Path.Combine(basePath, "BasicRsaCertificateRequestTest.p12");
                File.WriteAllBytes(pkcs12FilePath, certificateOfEndEntity.Export(X509ContentType.Pkcs12, "password"));
            }
        }

        [Test()]
        public void BasicEcdsaCertificateRequestTest()
        {
            // Load PKCS#11 based store
            using (var pkcs11Store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                // Find signing certificate (CA certificate)
                Pkcs11X509Certificate pkcs11CertOfCertificateAuthority = Helpers.GetCertificate(pkcs11Store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserEcdsaLabel);

                // Generate new key pair for end entity
                ECDsa ecKeyPairOfEndEntity = ECDsa.Create(ECCurve.NamedCurves.nistP256);

                // Define certificate request
                CertificateRequest certificateRequest = new CertificateRequest(
                    new X500DistinguishedName("C=SK,L=Bratislava,CN=BasicEcdsaCertificateRequestTest"),
                    ecKeyPairOfEndEntity,
                    HashAlgorithmName.SHA256);

                // Define certificate extensions
                certificateRequest.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
                certificateRequest.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));
                certificateRequest.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

                // Issue X.509 certificate for end entity
                X509Certificate2 certificateOfEndEntity = certificateRequest.Create(
                    pkcs11CertOfCertificateAuthority.Info.ParsedCertificate.SubjectName,
                    X509SignatureGenerator.CreateForECDsa(pkcs11CertOfCertificateAuthority.GetECDsaPrivateKey()),
                    DateTimeOffset.UtcNow,
                    DateTimeOffset.UtcNow.AddDays(365),
                    new BigInteger(1).ToByteArray());

                // Verify signature on X.509 certificate for end entity
                Assert.IsTrue(CaCertSignedEndEntityCert(pkcs11CertOfCertificateAuthority.Info.ParsedCertificate.RawData, certificateOfEndEntity.RawData));

                // Asociate end entity certificate with its private key
                certificateOfEndEntity = certificateOfEndEntity.CopyWithPrivateKey(ecKeyPairOfEndEntity);

                // Export end entity certificate to PKCS#12 file
                string basePath = Helpers.GetBasePath();
                string pkcs12FilePath = Path.Combine(basePath, "BasicEcdsaCertificateRequestTest.p12");
                File.WriteAllBytes(pkcs12FilePath, certificateOfEndEntity.Export(X509ContentType.Pkcs12, "password"));
            }
        }

        /// <summary>
        /// Verify that CA certificate signed end entity certificate
        /// </summary>
        /// <param name="caCertData">DER encoded CA certificate</param>
        /// <param name="eeCertData">DER encoded end entity certificate</param>
        /// <returns>True if CA certificate signed end entity certificate; false otherwise</returns>
        private bool CaCertSignedEndEntityCert(byte[] caCertData, byte[] eeCertData)
        {
            var certParser = new Org.BouncyCastle.X509.X509CertificateParser();
            var caCert = certParser.ReadCertificate(caCertData);
            var eeCert = certParser.ReadCertificate(eeCertData);

            try
            {
                eeCert.Verify(caCert.GetPublicKey());
                return true;
            }
            catch (Org.BouncyCastle.Security.InvalidKeyException)
            {
                return false;
            }
        }
    }
}

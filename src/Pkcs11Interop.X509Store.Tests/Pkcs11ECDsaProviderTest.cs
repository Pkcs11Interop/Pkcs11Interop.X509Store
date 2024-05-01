/*
 *  Copyright 2017-2024 The Pkcs11Interop Project
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

using System.Security.Cryptography;
using System.Text;
using Net.Pkcs11Interop.X509Store.Tests.SoftHsm2;
using NUnit.Framework;
using NUnit.Framework.Legacy;

namespace Net.Pkcs11Interop.X509Store.Tests
{
    public class Pkcs11ECDsaProviderTest
    {
        private HashAlgorithmName[] _hashNames = new HashAlgorithmName[] { HashAlgorithmName.MD5, HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 };
        private byte[] _data1 = Encoding.UTF8.GetBytes("Hello world!");
        private byte[] _data2 = Encoding.UTF8.GetBytes("Hola mundo!");

        [Test]
        public void EcdsaSelfTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert1 = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserEcdsaLabel);
                Pkcs11X509Certificate cert2 = Helpers.GetCertificate(store, SoftHsm2Manager.Token2Label, SoftHsm2Manager.Token2TestUserEcdsaLabel);

                foreach (var cert in new Pkcs11X509Certificate[] { cert1, cert2 })
                {
                    ECDsa p11PrivKey = cert.GetECDsaPrivateKey();
                    ClassicAssert.IsNotNull(p11PrivKey);
                    ECDsa p11PubKey = cert.GetECDsaPublicKey();
                    ClassicAssert.IsNotNull(p11PubKey);

                    foreach (HashAlgorithmName hashAlgName in _hashNames)
                    {
                        byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                        byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                        byte[] signature = p11PrivKey.SignHash(hash1);
                        ClassicAssert.IsNotNull(signature);
                        bool result1 = p11PubKey.VerifyHash(hash1, signature);
                        ClassicAssert.IsTrue(result1);
                        bool result2 = p11PubKey.VerifyHash(hash2, signature);
                        ClassicAssert.IsFalse(result2);
                    }
                }
            }
        }

        [Test]
        public void EcdsaPlatformTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserEcdsaLabel);

                ECDsa p11PrivKey = cert.GetECDsaPrivateKey();
                ClassicAssert.IsNotNull(p11PrivKey);
                ECDsa p11PubKey = cert.GetECDsaPublicKey();
                ClassicAssert.IsNotNull(p11PubKey);
                ECDsa cngKey = CryptoObjects.GetTestUserPlatformEcdsaProvider();
                ClassicAssert.IsNotNull(cngKey);

                foreach (HashAlgorithmName hashAlgName in _hashNames)
                {
                    byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                    byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                    byte[] p11Signature = p11PrivKey.SignHash(hash1);
                    ClassicAssert.IsNotNull(p11Signature);
                    bool result1 = cngKey.VerifyHash(hash1, p11Signature);
                    ClassicAssert.IsTrue(result1);
                    bool result2 = cngKey.VerifyHash(hash2, p11Signature);
                    ClassicAssert.IsFalse(result2);

                    byte[] cngSignature = cngKey.SignHash(hash1);
                    ClassicAssert.IsNotNull(cngSignature);
                    bool result3 = p11PubKey.VerifyHash(hash1, cngSignature);
                    ClassicAssert.IsTrue(result3);
                    bool result4 = p11PubKey.VerifyHash(hash2, cngSignature);
                    ClassicAssert.IsFalse(result4);
                }
            }
        }

        [Test]
        public void PrivateKeyObjectNotFoundTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, new CancellingPinProvider()))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token2Label, SoftHsm2Manager.Token2TestUserEcdsaLabel);
                ClassicAssert.IsFalse(cert.HasPrivateKeyObject);
                ClassicAssert.IsTrue(cert.HasPublicKeyObject);

                ECDsa ecdsa = cert.GetECDsaPublicKey();

                foreach (HashAlgorithmName hashAlgName in _hashNames)
                    ClassicAssert.Catch(typeof(PrivateKeyObjectNotFoundException), () => { ecdsa.SignHash(_data1); });
            }
        }

        [Test]
        public void PublicKeyObjectNotFoundTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token3Label, SoftHsm2Manager.Token3TestUserEcdsaLabel);
                ClassicAssert.IsTrue(cert.HasPrivateKeyObject);
                ClassicAssert.IsFalse(cert.HasPublicKeyObject);

                ECDsa ecdsa = cert.GetECDsaPrivateKey();

                foreach (HashAlgorithmName hashAlgName in _hashNames)
                    ClassicAssert.Catch(typeof(PublicKeyObjectNotFoundException), () => { ecdsa.VerifyHash(_data1, _data2); });
            }
        }
    }
}

/*
 *  Copyright 2017-2021 The Pkcs11Interop Project
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

namespace Net.Pkcs11Interop.X509Store.Tests
{
    [TestFixture()]
    public class Pkcs11RsaProviderTest
    {
        private HashAlgorithmName[] _hashNamesPkcs1 = new HashAlgorithmName[] { HashAlgorithmName.MD5, HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 };
        private HashAlgorithmName[] _hashNamesPss = new HashAlgorithmName[] { HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 };
        private byte[] _data1 = Encoding.UTF8.GetBytes("Hello world!");
        private byte[] _data2 = Encoding.UTF8.GetBytes("Hola mundo!");

        [Test()]
        public void RsaPkcs1SelfTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert1 = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);
                Pkcs11X509Certificate cert2 = Helpers.GetCertificate(store, SoftHsm2Manager.Token2Label, SoftHsm2Manager.Token2TestUserRsaLabel);

                foreach (var cert in new Pkcs11X509Certificate[] { cert1, cert2 })
                {
                    RSA p11PrivKey = cert.GetRSAPrivateKey();
                    Assert.IsNotNull(p11PrivKey);
                    RSA p11PubKey = cert.GetRSAPublicKey();
                    Assert.IsNotNull(p11PubKey);

                    foreach (HashAlgorithmName hashAlgName in _hashNamesPkcs1)
                    {
                        byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                        byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                        byte[] signature = p11PrivKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pkcs1);
                        Assert.IsNotNull(signature);
                        bool result1 = p11PubKey.VerifyHash(hash1, signature, hashAlgName, RSASignaturePadding.Pkcs1);
                        Assert.IsTrue(result1);
                        bool result2 = p11PubKey.VerifyHash(hash2, signature, hashAlgName, RSASignaturePadding.Pkcs1);
                        Assert.IsFalse(result2);
                    }
                }
            }
        }

        [Test()]
        public void RsaPkcs1PlatformTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                RSA p11PrivKey = cert.GetRSAPrivateKey();
                Assert.IsNotNull(p11PrivKey);
                RSA p11PubKey = cert.GetRSAPublicKey();
                Assert.IsNotNull(p11PubKey);
                RSA cngKey = CryptoObjects.GetTestUserPlatformRsaProvider();
                Assert.IsNotNull(cngKey);

                foreach (HashAlgorithmName hashAlgName in _hashNamesPkcs1)
                {
                    byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                    byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                    byte[] p11Signature = p11PrivKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pkcs1);
                    Assert.IsNotNull(p11Signature);
                    bool result1 = cngKey.VerifyHash(hash1, p11Signature, hashAlgName, RSASignaturePadding.Pkcs1);
                    Assert.IsTrue(result1);
                    bool result2 = cngKey.VerifyHash(hash2, p11Signature, hashAlgName, RSASignaturePadding.Pkcs1);
                    Assert.IsFalse(result2);

                    byte[] cngSignature = cngKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pkcs1);
                    Assert.IsNotNull(cngSignature);
                    bool result3 = p11PubKey.VerifyHash(hash1, cngSignature, hashAlgName, RSASignaturePadding.Pkcs1);
                    Assert.IsTrue(result3);
                    bool result4 = p11PubKey.VerifyHash(hash2, cngSignature, hashAlgName, RSASignaturePadding.Pkcs1);
                    Assert.IsFalse(result4);
                }
            }
        }

        [Test()]
        public void RsaPssSelfTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert1 = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);
                Pkcs11X509Certificate cert2 = Helpers.GetCertificate(store, SoftHsm2Manager.Token2Label, SoftHsm2Manager.Token2TestUserRsaLabel);

                foreach (var cert in new Pkcs11X509Certificate[] { cert1, cert2 })
                {
                    RSA p11PrivKey = cert.GetRSAPrivateKey();
                    Assert.IsNotNull(p11PrivKey);
                    RSA p11PubKey = cert.GetRSAPublicKey();
                    Assert.IsNotNull(p11PubKey);

                    foreach (HashAlgorithmName hashAlgName in _hashNamesPss)
                    {
                        byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                        byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                        byte[] signature = p11PrivKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pss);
                        Assert.IsNotNull(signature);
                        bool result1 = p11PubKey.VerifyHash(hash1, signature, hashAlgName, RSASignaturePadding.Pss);
                        Assert.IsTrue(result1);
                        bool result2 = p11PubKey.VerifyHash(hash2, signature, hashAlgName, RSASignaturePadding.Pss);
                        Assert.IsFalse(result2);
                    }
                }
            }
        }

        [Test()]
        public void RsaPssPlatformTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                RSA p11PrivKey = cert.GetRSAPrivateKey();
                Assert.IsNotNull(p11PrivKey);
                RSA p11PubKey = cert.GetRSAPublicKey();
                Assert.IsNotNull(p11PubKey);
                RSA cngKey = CryptoObjects.GetTestUserPlatformRsaProvider();
                Assert.IsNotNull(cngKey);

                foreach (HashAlgorithmName hashAlgName in _hashNamesPss)
                {
                    byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                    byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                    byte[] p11Signature = p11PrivKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pss);
                    Assert.IsNotNull(p11Signature);
                    bool result1 = cngKey.VerifyHash(hash1, p11Signature, hashAlgName, RSASignaturePadding.Pss);
                    Assert.IsTrue(result1);
                    bool result2 = cngKey.VerifyHash(hash2, p11Signature, hashAlgName, RSASignaturePadding.Pss);
                    Assert.IsFalse(result2);

                    byte[] cngSignature = cngKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pss);
                    Assert.IsNotNull(cngSignature);
                    bool result3 = p11PubKey.VerifyHash(hash1, cngSignature, hashAlgName, RSASignaturePadding.Pss);
                    Assert.IsTrue(result3);
                    bool result4 = p11PubKey.VerifyHash(hash2, cngSignature, hashAlgName, RSASignaturePadding.Pss);
                    Assert.IsFalse(result4);
                }
            }
        }
    }
}

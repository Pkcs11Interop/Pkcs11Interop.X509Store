/*
 *  Copyright 2017-2025 The Pkcs11Interop Project
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
    public class Pkcs11RsaProviderTest
    {
        private HashAlgorithmName[] _hashNamesPkcs1 = new HashAlgorithmName[] { HashAlgorithmName.MD5, HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 };
        private HashAlgorithmName[] _hashNamesPss = new HashAlgorithmName[] { HashAlgorithmName.SHA1, HashAlgorithmName.SHA256, HashAlgorithmName.SHA384, HashAlgorithmName.SHA512 };
        private RSAEncryptionPadding[] _encryptionPaddings = new RSAEncryptionPadding[] { RSAEncryptionPadding.Pkcs1, RSAEncryptionPadding.OaepSHA1 /*, RSAEncryptionPadding.OaepSHA256, RSAEncryptionPadding.OaepSHA384, RSAEncryptionPadding.OaepSHA512 */ };
        private byte[] _data1 = Encoding.UTF8.GetBytes("Hello world!");
        private byte[] _data2 = Encoding.UTF8.GetBytes("Hola mundo!");

        [Test]
        public void RsaSigningPkcs1SelfTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert1 = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);
                Pkcs11X509Certificate cert2 = Helpers.GetCertificate(store, SoftHsm2Manager.Token2Label, SoftHsm2Manager.Token2TestUserRsaLabel);

                foreach (var cert in new Pkcs11X509Certificate[] { cert1, cert2 })
                {
                    RSA p11PrivKey = cert.GetRSAPrivateKey();
                    ClassicAssert.IsNotNull(p11PrivKey);
                    RSA p11PubKey = cert.GetRSAPublicKey();
                    ClassicAssert.IsNotNull(p11PubKey);

                    foreach (HashAlgorithmName hashAlgName in _hashNamesPkcs1)
                    {
                        byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                        byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                        byte[] signature = p11PrivKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pkcs1);
                        ClassicAssert.IsNotNull(signature);
                        bool result1 = p11PubKey.VerifyHash(hash1, signature, hashAlgName, RSASignaturePadding.Pkcs1);
                        ClassicAssert.IsTrue(result1);
                        bool result2 = p11PubKey.VerifyHash(hash2, signature, hashAlgName, RSASignaturePadding.Pkcs1);
                        ClassicAssert.IsFalse(result2);
                    }
                }
            }
        }

        [Test]
        public void RsaSigningPkcs1PlatformTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                RSA p11PrivKey = cert.GetRSAPrivateKey();
                ClassicAssert.IsNotNull(p11PrivKey);
                RSA p11PubKey = cert.GetRSAPublicKey();
                ClassicAssert.IsNotNull(p11PubKey);
                RSA cngKey = CryptoObjects.GetTestUserPlatformRsaProvider();
                ClassicAssert.IsNotNull(cngKey);

                foreach (HashAlgorithmName hashAlgName in _hashNamesPkcs1)
                {
                    byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                    byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                    byte[] p11Signature = p11PrivKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pkcs1);
                    ClassicAssert.IsNotNull(p11Signature);
                    bool result1 = cngKey.VerifyHash(hash1, p11Signature, hashAlgName, RSASignaturePadding.Pkcs1);
                    ClassicAssert.IsTrue(result1);
                    bool result2 = cngKey.VerifyHash(hash2, p11Signature, hashAlgName, RSASignaturePadding.Pkcs1);
                    ClassicAssert.IsFalse(result2);

                    byte[] cngSignature = cngKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pkcs1);
                    ClassicAssert.IsNotNull(cngSignature);
                    bool result3 = p11PubKey.VerifyHash(hash1, cngSignature, hashAlgName, RSASignaturePadding.Pkcs1);
                    ClassicAssert.IsTrue(result3);
                    bool result4 = p11PubKey.VerifyHash(hash2, cngSignature, hashAlgName, RSASignaturePadding.Pkcs1);
                    ClassicAssert.IsFalse(result4);
                }
            }
        }

        [Test]
        public void RsaSigningPssSelfTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert1 = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);
                Pkcs11X509Certificate cert2 = Helpers.GetCertificate(store, SoftHsm2Manager.Token2Label, SoftHsm2Manager.Token2TestUserRsaLabel);

                foreach (var cert in new Pkcs11X509Certificate[] { cert1, cert2 })
                {
                    RSA p11PrivKey = cert.GetRSAPrivateKey();
                    ClassicAssert.IsNotNull(p11PrivKey);
                    RSA p11PubKey = cert.GetRSAPublicKey();
                    ClassicAssert.IsNotNull(p11PubKey);

                    foreach (HashAlgorithmName hashAlgName in _hashNamesPss)
                    {
                        byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                        byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                        byte[] signature = p11PrivKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pss);
                        ClassicAssert.IsNotNull(signature);
                        bool result1 = p11PubKey.VerifyHash(hash1, signature, hashAlgName, RSASignaturePadding.Pss);
                        ClassicAssert.IsTrue(result1);
                        bool result2 = p11PubKey.VerifyHash(hash2, signature, hashAlgName, RSASignaturePadding.Pss);
                        ClassicAssert.IsFalse(result2);
                    }
                }
            }
        }

        [Test]
        public void RsaSigningPssPlatformTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                RSA p11PrivKey = cert.GetRSAPrivateKey();
                ClassicAssert.IsNotNull(p11PrivKey);
                RSA p11PubKey = cert.GetRSAPublicKey();
                ClassicAssert.IsNotNull(p11PubKey);
                RSA cngKey = CryptoObjects.GetTestUserPlatformRsaProvider();
                ClassicAssert.IsNotNull(cngKey);

                foreach (HashAlgorithmName hashAlgName in _hashNamesPss)
                {
                    byte[] hash1 = Helpers.ComputeHash(_data1, hashAlgName);
                    byte[] hash2 = Helpers.ComputeHash(_data2, hashAlgName);

                    byte[] p11Signature = p11PrivKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pss);
                    ClassicAssert.IsNotNull(p11Signature);
                    bool result1 = cngKey.VerifyHash(hash1, p11Signature, hashAlgName, RSASignaturePadding.Pss);
                    ClassicAssert.IsTrue(result1);
                    bool result2 = cngKey.VerifyHash(hash2, p11Signature, hashAlgName, RSASignaturePadding.Pss);
                    ClassicAssert.IsFalse(result2);

                    byte[] cngSignature = cngKey.SignHash(hash1, hashAlgName, RSASignaturePadding.Pss);
                    ClassicAssert.IsNotNull(cngSignature);
                    bool result3 = p11PubKey.VerifyHash(hash1, cngSignature, hashAlgName, RSASignaturePadding.Pss);
                    ClassicAssert.IsTrue(result3);
                    bool result4 = p11PubKey.VerifyHash(hash2, cngSignature, hashAlgName, RSASignaturePadding.Pss);
                    ClassicAssert.IsFalse(result4);
                }
            }
        }

        [Test]
        public void RsaEncryptionSelfTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                RSA p11PrivKey = cert.GetRSAPrivateKey();
                ClassicAssert.IsNotNull(p11PrivKey);
                RSA p11PubKey = cert.GetRSAPublicKey();
                ClassicAssert.IsNotNull(p11PubKey);

                foreach (RSAEncryptionPadding encryptionPadding in _encryptionPaddings)
                {
                    byte[] encData = p11PubKey.Encrypt(_data1, encryptionPadding);
                    ClassicAssert.IsNotNull(encData);
                    byte[] decData = p11PrivKey.Decrypt(encData, encryptionPadding);
                    ClassicAssert.IsNotNull(decData);
                    CollectionAssert.AreEqual(decData, _data1);
                }
            }
        }

        [Test]
        public void RsaEncryptionPlatformTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                RSA p11PrivKey = cert.GetRSAPrivateKey();
                ClassicAssert.IsNotNull(p11PrivKey);
                RSA p11PubKey = cert.GetRSAPublicKey();
                ClassicAssert.IsNotNull(p11PubKey);
                RSA cngKey = CryptoObjects.GetTestUserPlatformRsaProvider();
                ClassicAssert.IsNotNull(cngKey);

                foreach (RSAEncryptionPadding encryptionPadding in _encryptionPaddings)
                {
                    byte[] encData1 = p11PubKey.Encrypt(_data1, encryptionPadding);
                    ClassicAssert.IsNotNull(encData1);
                    byte[] decData1 = cngKey.Decrypt(encData1, encryptionPadding);
                    ClassicAssert.IsNotNull(decData1);
                    CollectionAssert.AreEqual(decData1, _data1);

                    byte[] encData2 = cngKey.Encrypt(_data2, encryptionPadding);
                    ClassicAssert.IsNotNull(encData2);
                    byte[] decData2 = p11PrivKey.Decrypt(encData2, encryptionPadding);
                    ClassicAssert.IsNotNull(decData2);
                    CollectionAssert.AreEqual(decData2, _data2);
                }
            }
        }

        [Test]
        public void PrivateKeyObjectNotFoundTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, new CancellingPinProvider()))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token2Label, SoftHsm2Manager.Token2TestUserRsaLabel);
                ClassicAssert.IsFalse(cert.HasPrivateKeyObject);
                ClassicAssert.IsTrue(cert.HasPublicKeyObject);

                RSA rsa = cert.GetRSAPublicKey();

                foreach (HashAlgorithmName hashAlgName in _hashNamesPkcs1)
                    ClassicAssert.Catch(typeof(PrivateKeyObjectNotFoundException), () => { rsa.SignHash(Helpers.ComputeHash(_data1, hashAlgName), hashAlgName, RSASignaturePadding.Pkcs1); });

                foreach (HashAlgorithmName hashAlgName in _hashNamesPss)
                    ClassicAssert.Catch(typeof(PrivateKeyObjectNotFoundException), () => { rsa.SignHash(Helpers.ComputeHash(_data1, hashAlgName), hashAlgName, RSASignaturePadding.Pss); });

                foreach (RSAEncryptionPadding encryptionPadding in _encryptionPaddings)
                    ClassicAssert.Catch(typeof(PrivateKeyObjectNotFoundException), () => { rsa.Decrypt(_data1, encryptionPadding); });
            }
        }

        [Test]
        public void PublicKeyObjectNotFoundTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = Helpers.GetCertificate(store, SoftHsm2Manager.Token3Label, SoftHsm2Manager.Token3TestUserRsaLabel);
                ClassicAssert.IsTrue(cert.HasPrivateKeyObject);
                ClassicAssert.IsFalse(cert.HasPublicKeyObject);

                RSA rsa = cert.GetRSAPrivateKey();

                foreach (HashAlgorithmName hashAlgName in _hashNamesPkcs1)
                    ClassicAssert.Catch(typeof(PublicKeyObjectNotFoundException), () => { rsa.VerifyHash(_data1, _data2, hashAlgName, RSASignaturePadding.Pkcs1); });

                foreach (HashAlgorithmName hashAlgName in _hashNamesPss)
                    ClassicAssert.Catch(typeof(PublicKeyObjectNotFoundException), () => { rsa.VerifyHash(_data1, _data2, hashAlgName, RSASignaturePadding.Pss); });

                foreach (RSAEncryptionPadding encryptionPadding in _encryptionPaddings)
                    ClassicAssert.Catch(typeof(PublicKeyObjectNotFoundException), () => { rsa.Encrypt(_data1, encryptionPadding); });
            }
        }
    }
}

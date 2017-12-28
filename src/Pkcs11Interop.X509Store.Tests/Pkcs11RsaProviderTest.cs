/*
 *  Copyright 2017 The Pkcs11Interop Project
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

using System.Linq;
using System.Security.Cryptography;
using System.Text;
using Net.Pkcs11Interop.X509Store.Tests.SoftHsm2;
using NUnit.Framework;

namespace Net.Pkcs11Interop.X509Store.Tests
{
    [TestFixture()]
    public class Pkcs11RsaProviderTest
    {
        private byte[] _data1 = null;
        private byte[] _hash1 = null;
        private byte[] _data2 = null;
        private byte[] _hash2 = null;

        public Pkcs11RsaProviderTest()
        {
            _data1 = Encoding.UTF8.GetBytes("Hello world!");
            _hash1 = new SHA256Managed().ComputeHash(_data1);
            _data2 = Encoding.UTF8.GetBytes("Hola mundo!");
            _hash2 = new SHA256Managed().ComputeHash(_data2);
        }

        private static Pkcs11X509Certificate GetCertificate(Pkcs11X509Store store, string tokenLabel, string certLabel)
        {
            Pkcs11Token token = store.Slots.FirstOrDefault(p => p.Token.Info.Label == tokenLabel)?.Token;
            return token?.Certificates.FirstOrDefault(p => p.Info.Label == certLabel);
        }

        [Test()]
        public void Pkcs1SelfTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                RSA p11PrivKey = cert.GetRSAPrivateKey();
                Assert.IsNotNull(p11PrivKey);
                RSA p11PubKey = cert.GetRSAPublicKey();
                Assert.IsNotNull(p11PubKey);

                byte[] signature = p11PrivKey.SignHash(_hash1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.IsNotNull(signature);
                bool result1 = p11PubKey.VerifyHash(_hash1, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.IsTrue(result1);
                bool result2 = p11PubKey.VerifyHash(_hash2, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.IsFalse(result2);
            }
        }

        [Test()]
        public void Pkcs1CngTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                Pkcs11X509Certificate cert = GetCertificate(store, SoftHsm2Manager.Token1Label, SoftHsm2Manager.Token1TestUserRsaLabel);

                RSA p11PrivKey = cert.GetRSAPrivateKey();
                Assert.IsNotNull(p11PrivKey);
                RSA p11PubKey = cert.GetRSAPublicKey();
                Assert.IsNotNull(p11PubKey);
                RSA cngKey = CryptoObjects.GetTestUserRsaCngProvider();
                Assert.IsNotNull(cngKey);

                byte[] p11Signature = p11PrivKey.SignHash(_hash1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.IsNotNull(p11Signature);
                bool result1 = cngKey.VerifyHash(_hash1, p11Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.IsTrue(result1);
                bool result2 = cngKey.VerifyHash(_hash2, p11Signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.IsFalse(result2);

                byte[] cngSignature = cngKey.SignHash(_hash1, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.IsNotNull(cngSignature);
                bool result3 = p11PubKey.VerifyHash(_hash1, cngSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.IsTrue(result3);
                bool result4 = p11PubKey.VerifyHash(_hash2, cngSignature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                Assert.IsFalse(result4);
            }
        }
    }
}

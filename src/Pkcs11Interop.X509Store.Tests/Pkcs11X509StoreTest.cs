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

using System.Security.Cryptography;
using System.Text;
using Net.Pkcs11Interop.X509Store.Tests.SoftHsm2;
using NUnit.Framework;

namespace Net.Pkcs11Interop.X509Store.Tests
{
    [TestFixture()]
    public class Pkcs11X509StoreTest
    {
        [Test()]
        public void BasicTest()
        {
            using (var store = new Pkcs11X509Store(SoftHsm2Manager.LibraryPath, SoftHsm2Manager.PinProvider))
            {
                foreach (Pkcs11Slot slot in store.Slots)
                {
                    if (slot.Token == null)
                        continue;

                    foreach (Pkcs11X509Certificate cert in slot.Token.Certificates)
                    {
                        RSA privKey = cert.GetRSAPrivateKey();
                        if (privKey == null)
                            continue;

                        byte[] data = Encoding.UTF8.GetBytes("Hello world!");
                        byte[] hash = new SHA256Managed().ComputeHash(data);
                        byte[] signature = privKey.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

                        RSA pubKey = cert.GetRSAPublicKey();

                        bool result = pubKey.VerifyHash(hash, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                    }
                }
            }
        }
    }
}

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

using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using Net.Pkcs11Interop.X509Store.Tests.SoftHsm2;

namespace Net.Pkcs11Interop.X509Store.Tests
{
    /// <summary>
    /// Helper methods for tests
    /// </summary>
    public static class Helpers
    {
        public static Pkcs11X509Certificate GetCertificate(Pkcs11X509Store store, string tokenLabel, string certLabel)
        {
            Pkcs11Token token = store.Slots.FirstOrDefault(p => p.Token.Info.Label == tokenLabel)?.Token;
            return token?.Certificates.FirstOrDefault(p => p.Info.Label == certLabel);
        }

        public static byte[] ComputeHash(byte[] data, HashAlgorithmName hashAlgName)
        {
            if (hashAlgName == HashAlgorithmName.MD5)
            {
                using (HashAlgorithm hashAlg = MD5.Create())
                    return hashAlg.ComputeHash(data);
            }
            else if (hashAlgName == HashAlgorithmName.SHA1)
            {
                using (HashAlgorithm hashAlg = SHA1.Create())
                    return hashAlg.ComputeHash(data);
            }
            else if (hashAlgName == HashAlgorithmName.SHA256)
            {
                using (HashAlgorithm hashAlg = SHA256.Create())
                    return hashAlg.ComputeHash(data);
            }
            else if (hashAlgName == HashAlgorithmName.SHA384)
            {
                using (HashAlgorithm hashAlg = SHA384.Create())
                    return hashAlg.ComputeHash(data);
            }
            else if (hashAlgName == HashAlgorithmName.SHA512)
            {
                using (HashAlgorithm hashAlg = SHA512.Create())
                    return hashAlg.ComputeHash(data);
            }
            else
            {
                throw new NotSupportedException($"Hash algorithm {hashAlgName.Name} is not supported.");
            }
        }

        /// <summary>
        /// Gets absolute path of directory where the test assembly is located
        /// </summary>
        /// <returns>Absolute path of directory where the test assembly is located</returns>
        public static string GetBasePath()
        {
            return Path.GetDirectoryName(typeof(SoftHsm2Manager).Assembly.Location);
        }
    }
}

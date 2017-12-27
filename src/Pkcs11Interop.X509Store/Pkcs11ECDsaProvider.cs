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

using System;
using System.Security.Cryptography;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// PKCS#11 based implementation of the Elliptic Curve Digital Signature Algorithm (ECDSA)
    /// </summary>
    public class Pkcs11ECDsaProvider : ECDsa
    {
        /// <summary>
        /// Internal context for Pkcs11X509Certificate2 class
        /// </summary>
        private Pkcs11X509CertificateContext _certContext = null;

        /// <summary>
        /// Creates new instance of Pkcs11ECDsaProvider class
        /// </summary>
        /// <param name="certContext">Internal context for Pkcs11X509Certificate2 class</param>
        internal Pkcs11ECDsaProvider(Pkcs11X509CertificateContext certContext)
        {
            _certContext = certContext ?? throw new ArgumentNullException(nameof(certContext));
        }

        /// <summary>
        /// Generates a digital signature for the specified hash value
        /// </summary>
        /// <param name="hash">The hash value of the data that is being signed</param>
        /// <returns>A digital signature that consists of the given hash value encrypted with the private key</returns>
        public override byte[] SignHash(byte[] hash)
        {
            // TODO - Implement
            throw new NotImplementedException();
        }

        /// <summary>
        /// Verifies a digital signature against the specified hash value
        /// </summary>
        /// <param name="hash">The hash value of a block of data</param>
        /// <param name="signature">The digital signature to be verified</param>
        /// <returns>True if the hash value equals the decrypted signature, false otherwise</returns>
        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            // TODO - Implement
            throw new NotImplementedException();
        }
    }
}

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
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

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
            base.KeySizeValue = _certContext.CertificateInfo.ParsedCertificate.GetECDsaPublicKey().KeySize;
            base.LegalKeySizesValue = new KeySizes[] { new KeySizes(base.KeySizeValue, base.KeySizeValue, 0) };
        }

        /// <summary>
        /// Generates a digital signature for the specified hash value
        /// </summary>
        /// <param name="hash">The hash value of the data that is being signed</param>
        /// <returns>A digital signature that consists of the given hash value encrypted with the private key</returns>
        public override byte[] SignHash(byte[] hash)
        {
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            using (ISession session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
            using (IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_ECDSA))
            {
                if (_certContext.KeyUsageRequiresLogin)
                    return session.Sign(mechanism, _certContext.PrivKeyHandle, PinProviderUtils.GetKeyPin(_certContext), hash);
                else
                    return session.Sign(mechanism, _certContext.PrivKeyHandle, hash);
            }
        }

        /// <summary>
        /// Verifies a digital signature against the specified hash value
        /// </summary>
        /// <param name="hash">The hash value of a block of data</param>
        /// <param name="signature">The digital signature to be verified</param>
        /// <returns>True if the hash value equals the decrypted signature, false otherwise</returns>
        public override bool VerifyHash(byte[] hash, byte[] signature)
        {
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            if (signature == null || signature.Length == 0)
                throw new ArgumentNullException(nameof(signature));

            using (ISession session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
            using (IMechanism mechanism = session.Factories.MechanismFactory.Create(CKM.CKM_ECDSA))
            {
                session.Verify(mechanism, _certContext.PubKeyHandle, hash, signature, out bool isValid);
                return isValid;
            }
        }

        /// <summary>
        /// Computes the hash value of a specified portion of a byte array by using a specified hashing algorithm
        /// </summary>
        /// <param name="data">The data to be hashed</param>
        /// <param name="offset">The index of the first byte in data that is to be hashed</param>
        /// <param name="count">The number of bytes to hash</param>
        /// <param name="hashAlgorithm">The algorithm to use in hash the data</param>
        /// <returns>The hashed data</returns>
        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            if (data == null || data.Length == 0)
                throw new ArgumentNullException(nameof(data));

            if (offset < 0 || offset >= data.Length)
                throw new ArgumentException($"Invalid value of {nameof(offset)} parameter");

            if (count < 1 || (offset + count) > data.Length)
                throw new ArgumentException($"Invalid value of {nameof(count)} parameter");

            if (hashAlgorithm == null)
                throw new ArgumentNullException(nameof(hashAlgorithm));

            using (var hashAlg = HashAlgorithm.Create(hashAlgorithm.Name))
            {
                return hashAlg.ComputeHash(data, offset, count);
            }
        }

        /// <summary>
        /// Computes the hash value of a specified binary stream by using a specified hashing algorithm
        /// </summary>
        /// <param name="data">The binary stream to hash</param>
        /// <param name="hashAlgorithm">The hash algorithm</param>
        /// <returns>The hashed data</returns>
        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            if (data == null) // Note: data.Length might throw NotSupportedException
                throw new ArgumentNullException(nameof(data));

            if (hashAlgorithm == null)
                throw new ArgumentNullException(nameof(hashAlgorithm));

            using (var hashAlg = HashAlgorithm.Create(hashAlgorithm.Name))
            {
                return hashAlg.ComputeHash(data);
            }
        }
    }
}

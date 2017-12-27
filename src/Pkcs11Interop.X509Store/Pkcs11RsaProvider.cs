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
using System.Collections.Generic;
using System.Security.Cryptography;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// PKCS#11 based implementation of the RSA algorithm
    /// </summary>
    public class Pkcs11RsaProvider : RSA
    {
        /// <summary>
        /// Internal context for Pkcs11X509Certificate2 class
        /// </summary>
        private Pkcs11X509CertificateContext _certContext = null;

        /// <summary>
        /// Creates new instance of Pkcs11RsaProvider class
        /// </summary>
        /// <param name="certContext">Internal context for Pkcs11X509Certificate2 class</param>
        internal Pkcs11RsaProvider(Pkcs11X509CertificateContext certContext)
        {
            _certContext = certContext ?? throw new ArgumentNullException(nameof(certContext));
        }

        /// <summary>
        /// Computes the signature for the specified hash value by encrypting it with the private key using the specified padding
        /// </summary>
        /// <param name="hash">The hash value of the data to be signed</param>
        /// <param name="hashAlgorithm">The hash algorithm used to create the hash value of the data</param>
        /// <param name="padding">The padding</param>
        /// <returns>The RSA signature for the specified hash value</returns>
        public override byte[] SignHash(byte[] hash, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            // TODO - Implement RSASignaturePadding.Pss
            if (padding != RSASignaturePadding.Pkcs1)
                throw new NotSupportedException("Only PKCS#1 v1.5 RSA signature is supported");

            byte[] pkcs1DigestInfo = CreatePkcs1DigestInfo(hash, hashAlgorithm);
            if (pkcs1DigestInfo == null)
                throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm.Name));

            using (Session session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
            using (var mechanism = new Mechanism(CKM.CKM_RSA_PKCS))
                return session.Sign(mechanism, _certContext.PrivKeyHandle, pkcs1DigestInfo);
        }

        /// <summary>
        /// Verifies that a digital signature is valid by determining the hash value in the signature using the specified hash algorithm and padding, and comparing it to the provided hash value
        /// </summary>
        /// <param name="hash">he hash value of the signed data</param>
        /// <param name="signature">The signature data to be verified</param>
        /// <param name="hashAlgorithm">The hash algorithm used to create the hash value</param>
        /// <param name="padding">The padding mode</param>
        /// <returns>True if the signature is valid, false otherwise</returns>
        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgorithm, RSASignaturePadding padding)
        {
            // TODO - Implement RSASignaturePadding.Pss
            if (padding != RSASignaturePadding.Pkcs1)
                throw new NotSupportedException("Only PKCS#1 v1.5 RSA signature is supported");

            byte[] pkcs1DigestInfo = CreatePkcs1DigestInfo(hash, hashAlgorithm);
            if (pkcs1DigestInfo == null)
                throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm));

            using (Session session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
            using (var mechanism = new Mechanism(CKM.CKM_RSA_PKCS))
            {
                session.Verify(mechanism, _certContext.PubKeyHandle, pkcs1DigestInfo, signature, out bool isValid);
                return isValid;
            }
        }

        /// <summary>
        /// Decrypts the input data using the private key
        /// </summary>
        /// <param name="rgb">The cipher text to be decrypted</param>
        /// <returns>The resulting decryption of the rgb parameter in plain text</returns>
        public override byte[] DecryptValue(byte[] rgb)
        {
            // Note: NotSupportedException should be thrown starting with the .NET Framework 4.6.
            throw new NotSupportedException();
        }

        /// <summary>
        /// Encrypts the input data using the public key
        /// </summary>
        /// <param name="rgb">The plain text to be encrypted</param>
        /// <returns>The resulting encryption of the rgb parameter as cipher text</returns>
        public override byte[] EncryptValue(byte[] rgb)
        {
            // Note: NotSupportedException should be thrown starting with the .NET Framework 4.6.
            throw new NotSupportedException();
        }

        /// <summary>
        /// Exports the parameters (key) for RSA algorithm
        /// </summary>
        /// <param name="includePrivateParameters">Flag indicating whether to include private parameters</param>
        /// <returns>The parameters (key) for RSA algorithm</returns>
        public override RSAParameters ExportParameters(bool includePrivateParameters)
        {
            if (includePrivateParameters)
                throw new NotSupportedException("Private key cannot be exported");

            using (Session session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
            {
                var readTemplate = new List<CKA>() { CKA.CKA_PUBLIC_EXPONENT, CKA.CKA_MODULUS };

                List<ObjectAttribute> objectAttributes = session.GetAttributeValue(_certContext.PrivKeyHandle, readTemplate);

                return new RSAParameters()
                {
                    Exponent = objectAttributes[0].GetValueAsByteArray(),
                    Modulus = objectAttributes[1].GetValueAsByteArray()
                };
            }
        }

        /// <summary>
        /// Imports the parameters (key) for RSA algorithm
        /// </summary>
        /// <param name="parameters">The parameters (key) for RSA algorithm</param>
        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Creates DER encoded PKCS#1 DigestInfo structure defined in RFC 8017
        /// </summary>
        /// <param name="hash">Hash value</param>
        /// <param name="hashAlgorithm">Hash algorithm</param>
        /// <returns>DER encoded PKCS#1 DigestInfo structure or null</returns>
        private static byte[] CreatePkcs1DigestInfo(byte[] hash, HashAlgorithmName hashAlgorithm)
        {
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            byte[] pkcs1DigestInfo = null;

            if (hashAlgorithm == HashAlgorithmName.MD5)
            {
                if (hash.Length != 16)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x1E, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA1)
            {
                if (hash.Length != 20)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x1F, 0x30, 0x07, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                if (hash.Length != 32)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x2F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                if (hash.Length != 48)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x3F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x04, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                if (hash.Length != 64)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x4F, 0x30, 0x0B, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else
            {
                throw new ArgumentException("Invalid hash algorithm");
            }

            return pkcs1DigestInfo;
        }
    }
}

/*
 *  Copyright 2017-2018 The Pkcs11Interop Project
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
using System.Security.Cryptography.X509Certificates;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Net.Pkcs11Interop.HighLevelAPI.MechanismParams;

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
            base.KeySizeValue = _certContext.CertificateInfo.ParsedCertificate.GetRSAPublicKey().KeySize;
            base.LegalKeySizesValue = new KeySizes[] { new KeySizes(base.KeySizeValue, base.KeySizeValue, 0) };
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
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            if (hashAlgorithm == null)
                throw new ArgumentNullException(nameof(hashAlgorithm));

            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            if (padding == RSASignaturePadding.Pkcs1)
            {
                byte[] pkcs1DigestInfo = CreatePkcs1DigestInfo(hash, hashAlgorithm);
                if (pkcs1DigestInfo == null)
                    throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm.Name));

                using (Session session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
                using (var mechanism = new Mechanism(CKM.CKM_RSA_PKCS))
                {
                    if (_certContext.KeyUsageRequiresLogin)
                        return session.Sign(mechanism, _certContext.PrivKeyHandle, pkcs1DigestInfo, PinProviderUtils.GetKeyPin(_certContext));
                    else
                        return session.Sign(mechanism, _certContext.PrivKeyHandle, pkcs1DigestInfo);
                }
            }
            else if (padding == RSASignaturePadding.Pss)
            {
                CkRsaPkcsPssParams pssMechanismParams = CreateCkRsaPkcsPssParams(hash, hashAlgorithm);
                if (pssMechanismParams == null)
                    throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm.Name));

                using (Session session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
                using (var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_PSS, pssMechanismParams))
                {
                    if (_certContext.KeyUsageRequiresLogin)
                        return session.Sign(mechanism, _certContext.PrivKeyHandle, hash, PinProviderUtils.GetKeyPin(_certContext));
                    else
                        return session.Sign(mechanism, _certContext.PrivKeyHandle, hash);
                }
            }
            else
            {
                throw new NotSupportedException(string.Format("Padding {0} is not supported", padding));
            }
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
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            if (signature == null || signature.Length == 0)
                throw new ArgumentNullException(nameof(signature));

            if (hashAlgorithm == null)
                throw new ArgumentNullException(nameof(hashAlgorithm));

            if (padding == null)
                throw new ArgumentNullException(nameof(padding));

            if (padding == RSASignaturePadding.Pkcs1)
            {
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
            else if (padding == RSASignaturePadding.Pss)
            {
                CkRsaPkcsPssParams pssMechanismParams = CreateCkRsaPkcsPssParams(hash, hashAlgorithm);
                if (pssMechanismParams == null)
                    throw new NotSupportedException(string.Format("Algorithm {0} is not supported", hashAlgorithm.Name));

                using (Session session = _certContext.TokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
                using (var mechanism = new Mechanism(CKM.CKM_RSA_PKCS_PSS, pssMechanismParams))
                {
                    session.Verify(mechanism, _certContext.PubKeyHandle, hash, signature, out bool isValid);
                    return isValid;
                }
            }
            else
            {
                throw new NotSupportedException(string.Format("Padding {0} is not supported", padding));
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
                throw new NotSupportedException("Private key export is not supported");

            RSA rsaPubKey = _certContext.CertificateInfo.ParsedCertificate.GetRSAPublicKey();
            return rsaPubKey.ExportParameters(false);
        }

        /// <summary>
        /// Imports the parameters (key) for RSA algorithm
        /// </summary>
        /// <param name="parameters">The parameters (key) for RSA algorithm</param>
        public override void ImportParameters(RSAParameters parameters)
        {
            throw new NotSupportedException("Key import is not supported");
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

                pkcs1DigestInfo = new byte[] { 0x30, 0x20, 0x30, 0x0C, 0x06, 0x08, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA1)
            {
                if (hash.Length != 20)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2B, 0x0E, 0x03, 0x02, 0x1A, 0x05, 0x00, 0x04, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                if (hash.Length != 32)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x31, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                if (hash.Length != 48)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x41, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                if (hash.Length != 64)
                    throw new ArgumentException("Invalid lenght of hash value");

                pkcs1DigestInfo = new byte[] { 0x30, 0x51, 0x30, 0x0D, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                Array.Copy(hash, 0, pkcs1DigestInfo, pkcs1DigestInfo.Length - hash.Length, hash.Length);
            }

            return pkcs1DigestInfo;
        }

        /// <summary>
        /// Creates parameters for CKM_RSA_PKCS_PSS mechanism
        /// </summary>
        /// <param name="hash">Hash value</param>
        /// <param name="hashAlgorithm">Hash algorithm</param>
        /// <returns>Parameters for CKM_RSA_PKCS_PSS mechanism or null</returns>
        private static CkRsaPkcsPssParams CreateCkRsaPkcsPssParams(byte[] hash, HashAlgorithmName hashAlgorithm)
        {
            if (hash == null || hash.Length == 0)
                throw new ArgumentNullException(nameof(hash));

            CkRsaPkcsPssParams pssParams = null;

            if (hashAlgorithm == HashAlgorithmName.SHA1)
            {
                if (hash.Length != 20)
                    throw new ArgumentException("Invalid lenght of hash value");

                pssParams = new CkRsaPkcsPssParams(
                    hashAlg: (ulong)CKM.CKM_SHA_1,
                    mgf: (ulong)CKG.CKG_MGF1_SHA1,
                    len: (ulong)hash.Length
                );
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA256)
            {
                if (hash.Length != 32)
                    throw new ArgumentException("Invalid lenght of hash value");

                pssParams = new CkRsaPkcsPssParams(
                    hashAlg: (ulong)CKM.CKM_SHA256,
                    mgf: (ulong)CKG.CKG_MGF1_SHA256,
                    len: (ulong)hash.Length
                );
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA384)
            {
                if (hash.Length != 48)
                    throw new ArgumentException("Invalid lenght of hash value");

                pssParams = new CkRsaPkcsPssParams(
                    hashAlg: (ulong)CKM.CKM_SHA384,
                    mgf: (ulong)CKG.CKG_MGF1_SHA384,
                    len: (ulong)hash.Length
                );
            }
            else if (hashAlgorithm == HashAlgorithmName.SHA512)
            {
                if (hash.Length != 64)
                    throw new ArgumentException("Invalid lenght of hash value");

                pssParams = new CkRsaPkcsPssParams(
                    hashAlg: (ulong)CKM.CKM_SHA512,
                    mgf: (ulong)CKG.CKG_MGF1_SHA512,
                    len: (ulong)hash.Length
                );
            }

            return pssParams;
        }
    }
}

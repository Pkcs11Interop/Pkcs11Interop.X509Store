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
using System.Collections.Generic;
using System.Security.Cryptography;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// X.509 certificate stored on PKCS#11 token
    /// </summary>
    public class Pkcs11X509Certificate
    {
        /// <summary>
        /// Internal context for Pkcs11X509Certificate2 class
        /// </summary>
        private Pkcs11X509CertificateContext _certContext = null;

        /// <summary>
        /// Detailed information about X.509 certificate stored on PKCS#11 token
        /// </summary>
        public Pkcs11X509CertificateInfo Info
        {
            get
            {
                return _certContext.CertificateInfo;
            }
        }

        /// <summary>
        /// Flag indicating whether private key object corresponding to certificate object was found on token
        /// </summary>
        public bool HasPrivateKeyObject
        {
            get
            {
                return (_certContext.PrivKeyHandle != null);
            }
        }

        /// <summary>
        /// Flag indicating whether public key object corresponding to certificate object was found on token
        /// </summary>
        public bool HasPublicKeyObject
        {
            get
            {
                return (_certContext.PubKeyHandle != null);
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11X509Certificate2 class
        /// </summary>
        /// <param name="certHandle">High level PKCS#11 object handle of certificate object</param>
        /// <param name="tokenContext">Internal context for Pkcs11Token class</param>
        internal Pkcs11X509Certificate(IObjectHandle certHandle, Pkcs11TokenContext tokenContext)
        {
            if (certHandle == null)
                throw new ArgumentNullException(nameof(certHandle));

            if (tokenContext == null)
                throw new ArgumentNullException(nameof(tokenContext));

            _certContext = GetCertificateContext(certHandle, tokenContext);
        }

        /// <summary>
        /// Constructs internal context for Pkcs11X509Certificate class
        /// </summary>
        /// <param name="certHandle">High level PKCS#11 object handle of certificate object</param>
        /// <param name="tokenContext">Internal context for Pkcs11Token class</param>
        /// <returns>Internal context for Pkcs11X509Certificate class</returns>
        private Pkcs11X509CertificateContext GetCertificateContext(IObjectHandle certHandle, Pkcs11TokenContext tokenContext)
        {
            using (ISession session = tokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
            {
                List<IObjectAttribute> objectAttributes = session.GetAttributeValue(certHandle, new List<CKA>() { CKA.CKA_ID, CKA.CKA_LABEL, CKA.CKA_VALUE });

                byte[] ckaId = objectAttributes[0].GetValueAsByteArray();
                string ckaLabel = objectAttributes[1].GetValueAsString();
                byte[] ckaValue = objectAttributes[2].GetValueAsByteArray();

                var certInfo = new Pkcs11X509CertificateInfo(ckaId, ckaLabel, ckaValue);

                IObjectHandle privKeyHandle = FindKey(session, CKO.CKO_PRIVATE_KEY, ckaId, ckaLabel);
                IObjectHandle pubKeyHandle = FindKey(session, CKO.CKO_PUBLIC_KEY, ckaId, ckaLabel);

                bool keyUsageRequiresLogin = (privKeyHandle == null) ? false : GetCkaAlwaysAuthenticateValue(session, privKeyHandle);

                return new Pkcs11X509CertificateContext(certInfo, certHandle, privKeyHandle, pubKeyHandle, keyUsageRequiresLogin, tokenContext);
            }
        }

        /// <summary>
        /// Gets value of CKA_ALWAYS_AUTHENTICATE attribute of private key object
        /// </summary>
        /// <param name="session">PKCS#11 session for finding operation</param>
        /// <param name="privKeyHandle">Handle of private key object</param>
        /// <returns>Value of CKA_ALWAYS_AUTHENTICATE</returns>
        private bool GetCkaAlwaysAuthenticateValue(ISession session, IObjectHandle privKeyHandle)
        {
            try
            {
                List<IObjectAttribute> objectAttributes = session.GetAttributeValue(privKeyHandle, new List<CKA>() { CKA.CKA_ALWAYS_AUTHENTICATE });
                return objectAttributes[0].GetValueAsBool();
            }
            catch
            {
                // When CKA_ALWAYS_AUTHENTICATE cannot be read we can assume its value is CK_FALSE
                return false;
            }
        }

        /// <summary>
        /// Finds handle of key object present on token
        /// </summary>
        /// <param name="session">PKCS#11 session for finding operation</param>
        /// <param name="keyClass">Value of CKA_CLASS attribute used in search template</param>
        /// <param name="ckaId">Value of CKA_ID attribute used in search template</param>
        /// <param name="ckaLabel">Value of CKA_LABEL attribute used in search template</param>
        /// <returns>Handle of key object present on token or null</returns>
        private IObjectHandle FindKey(ISession session, CKO keyClass, byte[] ckaId, string ckaLabel)
        {
            IObjectHandle keyHandle = null;

            var searchTemplate = new List<IObjectAttribute>()
            {
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, keyClass),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                session.Factories.ObjectAttributeFactory.Create(CKA.CKA_ID, ckaId),
            };

            foreach (IObjectHandle foundObjectHandle in session.FindAllObjects(searchTemplate))
            {
                keyHandle = foundObjectHandle;
                break;
            }

            return keyHandle;
        }

        /// <summary>
        /// Gets the System.Security.Cryptography.RSA implementation for private key
        /// </summary>
        /// <returns>System.Security.Cryptography.RSA implementation for private key or null if RSA private key is not present on token</returns>
        public RSA GetRSAPrivateKey()
        {
            if (_certContext.CertificateInfo.KeyType != AsymmetricKeyType.RSA || !this.HasPrivateKeyObject)
                return null;

            return new Pkcs11RsaProvider(_certContext);
        }

        /// <summary>
        /// Gets the System.Security.Cryptography.RSA implementation for public key
        /// </summary>
        /// <returns>System.Security.Cryptography.RSA implementation for public key or null if RSA public key is not present on token</returns>
        public RSA GetRSAPublicKey()
        {
            if (_certContext.CertificateInfo.KeyType != AsymmetricKeyType.RSA || !this.HasPublicKeyObject)
                return null;

            return new Pkcs11RsaProvider(_certContext);
        }

        /// <summary>
        /// Gets the System.Security.Cryptography.ECDsa implementation for private key
        /// </summary>
        /// <returns>System.Security.Cryptography.ECDsa implementation for private key or null if ECDsa private key is not present on token</returns>
        public ECDsa GetECDsaPrivateKey()
        {
            if (_certContext.CertificateInfo.KeyType != AsymmetricKeyType.EC || !this.HasPrivateKeyObject)
                return null;

            return new Pkcs11ECDsaProvider(_certContext);
        }

        /// <summary>
        /// Gets the System.Security.Cryptography.ECDsa implementation for public key
        /// </summary>
        /// <returns>System.Security.Cryptography.ECDsa implementation for public key or null if ECDsa public key is not present on token</returns>
        public ECDsa GetECDsaPublicKey()
        {
            if (_certContext.CertificateInfo.KeyType != AsymmetricKeyType.EC || !this.HasPublicKeyObject)
                return null;

            return new Pkcs11ECDsaProvider(_certContext);
        }

        /// <summary>
        /// Gets the System.Security.Cryptography.AsymmetricAlgorithm implementation for private key
        /// </summary>
        /// <returns>System.Security.Cryptography.AsymmetricAlgorithm implementation for private key or null if private key is not present on token</returns>
        public AsymmetricAlgorithm GetPrivateKey()
        {
            switch (_certContext.CertificateInfo.KeyType)
            {
                case AsymmetricKeyType.RSA:
                    return GetRSAPrivateKey();
                case AsymmetricKeyType.EC:
                    return GetECDsaPrivateKey();
                default:
                    return null;
            }
        }

        /// <summary>
        /// Gets the System.Security.Cryptography.AsymmetricAlgorithm implementation for public key
        /// </summary>
        /// <returns>System.Security.Cryptography.AsymmetricAlgorithm implementation for public key or null if public key is not present on token</returns>
        public AsymmetricAlgorithm GetPublicKey()
        {
            switch (_certContext.CertificateInfo.KeyType)
            {
                case AsymmetricKeyType.RSA:
                    return GetRSAPublicKey();
                case AsymmetricKeyType.EC:
                    return GetECDsaPublicKey();
                default:
                    return null;
            }
        }
    }
}

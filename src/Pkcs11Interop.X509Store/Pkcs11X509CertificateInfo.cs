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
using System.Security.Cryptography.X509Certificates;
using Net.Pkcs11Interop.Common;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Detailed information about X.509 certificate stored on PKCS#11 token
    /// </summary>
    public class Pkcs11X509CertificateInfo
    {
        /// <summary>
        /// Hex encoded identifier of PKCS#11 certificate object (value of CKA_ID attribute)
        /// </summary>
        private string _id = null;

        /// <summary>
        /// Hex encoded identifier of PKCS#11 certificate object (value of CKA_ID attribute)
        /// </summary>
        public string Id
        {
            get
            {
                return _id;
            }
        }

        /// <summary>
        /// Label of PKCS#11 certificate object (value of CKA_LABEL attribute)
        /// </summary>
        private string _label = null;

        /// <summary>
        /// Label of PKCS#11 certificate object (value of CKA_LABEL attribute)
        /// </summary>
        public string Label
        {
            get
            {
                return _label;
            }
        }

        /// <summary>
        /// DER encoded value of X.509 certificate (value of CKA_VALUE attribute)
        /// </summary>
        private byte[] _rawData = null;

        /// <summary>
        /// DER encoded value of X.509 certificate (value of CKA_VALUE attribute)
        /// </summary>
        public byte[] RawData
        {
            get
            {
                return _rawData;
            }
        }

        /// <summary>
        /// X.509 certificate parsed as System.Security.Cryptography.X509Certificates.X509Certificate2 instance for convenience
        /// </summary>
        private X509Certificate2 _parsedCertificate = null;

        /// <summary>
        /// X.509 certificate parsed as System.Security.Cryptography.X509Certificates.X509Certificate2 instance for convenience
        /// </summary>
        public X509Certificate2 ParsedCertificate
        {
            get
            {
                return _parsedCertificate;
            }
        }

        /// <summary>
        /// Type of certified asymmetric key
        /// </summary>
        private AsymmetricKeyType _keyType = AsymmetricKeyType.Other;

        /// <summary>
        /// Type of certified asymmetric key
        /// </summary>
        public AsymmetricKeyType KeyType
        {
            get
            {
                return _keyType;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11X509CertificateInfo class
        /// </summary>
        /// <param name="ckaId">Value of CKA_ID attribute</param>
        /// <param name="ckaLabel">Value of CKA_LABEL attribute</param>
        /// <param name="ckaValue">Value of CKA_VALUE attribute</param>
        internal Pkcs11X509CertificateInfo(byte[] ckaId, string ckaLabel, byte[] ckaValue)
        {
            _id = ConvertUtils.BytesToHexString(ckaId);
            _label = ckaLabel;
            _rawData = ckaValue ?? throw new ArgumentNullException(nameof(ckaValue));
            _parsedCertificate = new X509Certificate2(_rawData);

            if (_parsedCertificate.PublicKey.Oid.Value == "1.2.840.113549.1.1.1")
                _keyType = AsymmetricKeyType.RSA;
            else if (_parsedCertificate.PublicKey.Oid.Value == "1.2.840.10045.2.1")
                _keyType = AsymmetricKeyType.EC;
            else
                _keyType = AsymmetricKeyType.Other;
        }
    }
}

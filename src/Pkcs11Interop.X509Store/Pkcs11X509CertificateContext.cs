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
using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Internal context for Pkcs11X509Certificate2 class
    /// </summary>
    internal class Pkcs11X509CertificateContext
    {
        /// <summary>
        /// Detailed information about X.509 certificate stored on PKCS#11 token
        /// </summary>
        private Pkcs11X509CertificateInfo _certificateInfo = null;

        /// <summary>
        /// Detailed information about X.509 certificate stored on PKCS#11 token
        /// </summary>
        internal Pkcs11X509CertificateInfo CertificateInfo
        {
            get
            {
                return _certificateInfo;
            }
        }

        /// <summary>
        /// High level PKCS#11 object handle of certificate object
        /// </summary>
        private IObjectHandle _certHandle = null;

        /// <summary>
        /// High level PKCS#11 object handle of certificate object
        /// </summary>
        internal IObjectHandle CertHandle
        {
            get
            {
                return _certHandle;
            }
        }

        /// <summary>
        /// High level PKCS#11 object handle of private key object
        /// </summary>
        private IObjectHandle _privKeyHandle = null;

        /// <summary>
        /// High level PKCS#11 object handle of private key object
        /// </summary>
        internal IObjectHandle PrivKeyHandle
        {
            get
            {
                return _privKeyHandle;
            }
        }

        /// <summary>
        /// High level PKCS#11 object handle of public key object
        /// </summary>
        private IObjectHandle _pubKeyHandle = null;

        /// <summary>
        /// High level PKCS#11 object handle of public key object
        /// </summary>
        internal IObjectHandle PubKeyHandle
        {
            get
            {
                return _pubKeyHandle;
            }
        }

        /// <summary>
        /// Flag indicating whether key usage requires context specific login to be perfromed
        /// </summary>
        private bool _keyUsageRequiresLogin = false;

        /// <summary>
        /// Flag indicating whether key usage requires context specific login to be perfromed
        /// </summary>
        internal bool KeyUsageRequiresLogin
        {
            get
            {
                return _keyUsageRequiresLogin;
            }
        }

        /// <summary>
        /// Internal context for Pkcs11Token class
        /// </summary>
        private Pkcs11TokenContext _tokenContext = null;

        /// <summary>
        /// Internal context for Pkcs11Token class
        /// </summary>
        internal Pkcs11TokenContext TokenContext
        {
            get
            {
                return _tokenContext;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11X509Certificate2Context class
        /// </summary>
        /// <param name="certificateInfo">Detailed information about X.509 certificate stored on PKCS#11 token</param>
        /// <param name="certHandle">High level PKCS#11 object handle of certificate object</param>
        /// <param name="privKeyHandle">High level PKCS#11 object handle of private key object</param>
        /// <param name="pubKeyHandle">High level PKCS#11 object handle of public key object</param>
        /// <param name="keyUsageRequiresLogin">Flag indicating whether key usage requires context specific login to be perfromed</param>
        /// <param name="tokenContext">Internal context for Pkcs11Token class</param>
        internal Pkcs11X509CertificateContext(Pkcs11X509CertificateInfo certificateInfo, IObjectHandle certHandle, IObjectHandle privKeyHandle, IObjectHandle pubKeyHandle, bool keyUsageRequiresLogin, Pkcs11TokenContext tokenContext)
        {
            _certificateInfo = certificateInfo ?? throw new ArgumentNullException(nameof(certificateInfo));
            _certHandle = certHandle ?? throw new ArgumentNullException(nameof(certHandle));
            _privKeyHandle = privKeyHandle;
            _pubKeyHandle = pubKeyHandle;
            _keyUsageRequiresLogin = keyUsageRequiresLogin;
            _tokenContext = tokenContext ?? throw new ArgumentNullException(nameof(tokenContext));
        }
    }
}

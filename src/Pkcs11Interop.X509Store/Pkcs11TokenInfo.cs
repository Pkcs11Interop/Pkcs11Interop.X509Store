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
    /// Detailed information about PKCS#11 token (cryptographic device) that is typically present in the slot
    /// </summary>
    public class Pkcs11TokenInfo
    {
        /// <summary>
        /// Manufacturer of the token
        /// </summary>
        private string _manufacturer = null;

        /// <summary>
        /// Manufacturer of the token
        /// </summary>
        public string Manufacturer
        {
            get
            {
                return _manufacturer;
            }
        }

        /// <summary>
        /// Model of the token
        /// </summary>
        private string _model = null;

        /// <summary>
        /// Model of the token
        /// </summary>
        public string Model
        {
            get
            {
                return _model;
            }
        }

        /// <summary>
        /// Serial number of the token
        /// </summary>
        private string _serialNumber = null;

        /// <summary>
        /// Serial number of the token
        /// </summary>
        public string SerialNumber
        {
            get
            {
                return _serialNumber;
            }
        }

        /// <summary>
        /// Label of the token
        /// </summary>
        private string _label = null;

        /// <summary>
        /// Label of the token
        /// </summary>
        public string Label
        {
            get
            {
                return _label;
            }
        }

        /// <summary>
        /// Flag indicating whether token has a protected authentication path (e.g. pin pad) whereby a user can log into the token without passing a PIN through the API
        /// </summary>
        private bool _hasProtectedAuthenticationPath = false;

        /// <summary>
        /// Flag indicating whether token has a protected authentication path (e.g. pin pad) whereby a user can log into the token without passing a PIN through the API
        /// </summary>
        public bool HasProtectedAuthenticationPath
        {
            get
            {
                return _hasProtectedAuthenticationPath;
            }
        }

        /// <summary>
        /// Flag indicating whether token has been initialized and is usable
        /// </summary>
        private bool _initialized = false;

        /// <summary>
        /// Flag indicating whether token has been initialized and is usable
        /// </summary>
        public bool Initialized
        {
            get
            {
                return _initialized;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11TokenInfo class
        /// </summary>
        /// <param name="tokenInfo">Information about PKCS#11 token (CK_TOKEN_INFO)</param>
        internal Pkcs11TokenInfo(ITokenInfo tokenInfo)
        {
            if (tokenInfo == null)
                throw new ArgumentNullException(nameof(tokenInfo));

            _manufacturer = tokenInfo.ManufacturerId;
            _model = tokenInfo.Model;
            _serialNumber = tokenInfo.SerialNumber;
            _label = tokenInfo.Label;
            _hasProtectedAuthenticationPath = tokenInfo.TokenFlags.ProtectedAuthenticationPath;
            _initialized = tokenInfo.TokenFlags.TokenInitialized;
        }
    }
}

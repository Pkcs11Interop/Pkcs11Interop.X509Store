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

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Result for PIN request with instructions on how to perform login
    /// </summary>
    public class GetPinResult
    {
        /// <summary>
        /// Flag indicating whether login should be cancelled
        /// </summary>
        private bool _cancel = false;

        /// <summary>
        /// Flag indicating whether login should be cancelled
        /// </summary>
        public bool Cancel
        {
            get
            {
                return _cancel;
            }
        }

        /// <summary>
        /// Value of PIN that should be used for the login.
        /// Null value indicates that login should be perfromed using protected authentication path (e.g. pin pad).
        /// </summary>
        private byte[] _pin = null;

        /// <summary>
        /// Value of PIN that should be used for the login.
        /// Null value indicates that login should be perfromed using protected authentication path (e.g. pin pad).
        /// </summary>
        public byte[] Pin
        {
            get
            {
                return _pin;
            }
        }

        /// <summary>
        /// Creates new instance of GetPinResult class
        /// </summary>
        /// <param name="cancel">Flag indicating whether login should be cancelled</param>
        /// <param name="pin">Value of PIN that should be used for the login. Null value indicates that login should be perfromed using protected authentication path (e.g. pin pad).</param>
        public GetPinResult(bool cancel, byte[] pin)
        {
            if (cancel && pin != null)
                throw new ArgumentException("PIN value provided along with the request to cancel login");

            _cancel = cancel;
            _pin = pin;
        }
    }
}

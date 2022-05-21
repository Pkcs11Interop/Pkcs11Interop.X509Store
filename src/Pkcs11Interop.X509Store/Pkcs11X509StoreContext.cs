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
    /// Internal context for Pkcs11X509Store class
    /// </summary>
    internal class Pkcs11X509StoreContext : IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// High level PKCS#11 wrapper
        /// </summary>
        private IPkcs11Library _pkcs11Library = null;

        /// <summary>
        /// High level PKCS#11 wrapper
        /// </summary>
        internal IPkcs11Library Pkcs11Library
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _pkcs11Library;
            }
        }

        /// <summary>
        /// Detailed information about PKCS#11 based X.509 store
        /// </summary>
        private Pkcs11X509StoreInfo _storeInfo = null;

        /// <summary>
        /// Detailed information about PKCS#11 based X.509 store
        /// </summary>
        internal Pkcs11X509StoreInfo StoreInfo
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _storeInfo;
            }
        }

        /// <summary>
        /// Provider of PIN codes for PKCS#11 tokens and keys
        /// </summary>
        private IPinProvider _pinProvider = null;

        /// <summary>
        /// Provider of PIN codes for PKCS#11 tokens and keys
        /// </summary>
        internal IPinProvider PinProvider
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _pinProvider;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11X509StoreContext class
        /// </summary>
        /// <param name="pkcs11Library">High level PKCS#11 wrapper</param>
        /// <param name="storeInfo">Detailed information about PKCS#11 based X.509 store</param>
        /// <param name="pinProvider">Provider of PIN codes for PKCS#11 tokens and keys</param>
        internal Pkcs11X509StoreContext(IPkcs11Library pkcs11Library, Pkcs11X509StoreInfo storeInfo, IPinProvider pinProvider)
        {
            _pkcs11Library = pkcs11Library ?? throw new ArgumentNullException(nameof(pkcs11Library));
            _storeInfo = storeInfo ?? throw new ArgumentNullException(nameof(storeInfo));
            _pinProvider = pinProvider ?? throw new ArgumentNullException(nameof(pinProvider));
        }

        #region IDisposable

        /// <summary>
        /// Disposes object
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes object
        /// </summary>
        /// <param name="disposing">Flag indicating whether managed resources should be disposed</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    // Dispose managed objects

                    if (_pkcs11Library != null)
                    {
                        _pkcs11Library.Dispose();
                        _pkcs11Library = null;
                    }
                }

                // Dispose unmanaged objects

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~Pkcs11X509StoreContext()
        {
            Dispose(false);
        }

        #endregion
    }
}

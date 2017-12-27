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
        private Pkcs11 _pkcs11 = null;

        /// <summary>
        /// High level PKCS#11 wrapper
        /// </summary>
        internal Pkcs11 Pkcs11
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _pkcs11;
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
        /// <param name="pkcs11">High level PKCS#11 wrapper</param>
        /// <param name="storeInfo">Detailed information about PKCS#11 based X.509 store</param>
        /// <param name="pinProvider">Provider of PIN codes for PKCS#11 tokens and keys</param>
        internal Pkcs11X509StoreContext(Pkcs11 pkcs11, Pkcs11X509StoreInfo storeInfo, IPinProvider pinProvider)
        {
            _pkcs11 = pkcs11 ?? throw new ArgumentNullException(nameof(pkcs11));
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

                    if (_pkcs11 != null)
                    {
                        _pkcs11.Dispose();
                        _pkcs11 = null;
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

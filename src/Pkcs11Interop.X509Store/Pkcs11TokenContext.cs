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
    /// Internal context for Pkcs11Token class
    /// </summary>
    internal class Pkcs11TokenContext : IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// Detailed information about PKCS#11 token (cryptographic device)
        /// </summary>
        private Pkcs11TokenInfo _tokenInfo = null;

        /// <summary>
        /// Detailed information about PKCS#11 token (cryptographic device)
        /// </summary>
        internal Pkcs11TokenInfo TokenInfo
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _tokenInfo;
            }
        }

        /// <summary>
        /// High level PKCS#11 session that preserves authenticated state of the token
        /// </summary>
        private ISession _authenticatedSession = null;

        /// <summary>
        /// High level PKCS#11 session that preserves authenticated state of the token
        /// </summary>
        internal ISession AuthenticatedSession
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _authenticatedSession;
            }
        }

        /// <summary>
        /// Internal context for Pkcs11Slot class
        /// </summary>
        private Pkcs11SlotContext _slotContext = null;

        /// <summary>
        /// Internal context for Pkcs11Slot class
        /// </summary>
        internal Pkcs11SlotContext SlotContext
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _slotContext;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11TokenContext class
        /// </summary>
        /// <param name="tokenInfo">Detailed information about PKCS#11 token (cryptographic device)</param>
        /// <param name="authenticatedSession">High level PKCS#11 session that holds authenticated state of the token</param>
        /// <param name="slotContext">Internal context for Pkcs11Slot class</param>
        internal Pkcs11TokenContext(Pkcs11TokenInfo tokenInfo, ISession authenticatedSession, Pkcs11SlotContext slotContext)
        {
            _tokenInfo = tokenInfo ?? throw new ArgumentNullException(nameof(tokenInfo));
            _authenticatedSession = authenticatedSession;
            _slotContext = slotContext ?? throw new ArgumentNullException(nameof(slotContext));
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

                    if (_authenticatedSession != null)
                    {
                        _authenticatedSession.Dispose();
                        _authenticatedSession = null;
                    }
                }

                // Dispose unmanaged objects

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~Pkcs11TokenContext()
        {
            Dispose(false);
        }

        #endregion
    }
}

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
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// PKCS#11 token (cryptographic device) that is typically present in the slot
    /// </summary>
    public class Pkcs11Token : IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// Internal context for Pkcs11Token class
        /// </summary>
        private Pkcs11TokenContext _tokenContext = null;

        /// <summary>
        /// Detailed information about PKCS#11 token (cryptographic device)
        /// </summary>
        public Pkcs11TokenInfo Info
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _tokenContext.TokenInfo;
            }
        }

        /// <summary>
        /// Certificates present on token.
        /// </summary>
        private List<Pkcs11X509Certificate> _certificates = null;

        /// <summary>
        /// Certificates present on token.
        /// This property may use provider of PIN codes (IPinProvider) on access.
        /// </summary>
        public List<Pkcs11X509Certificate> Certificates
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                if (_certificates == null)
                    this.ReloadCertificates();

                return _certificates;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11Token class
        /// </summary>
        /// <param name="slotContext">Internal context for Pkcs11Slot class</param>
        internal Pkcs11Token(Pkcs11SlotContext slotContext)
        {
            if (slotContext == null)
                throw new ArgumentNullException(nameof(slotContext));

            _tokenContext = this.GetTokenContext(slotContext);
            // Note: _certificates are loaded on first access
        }

        /// <summary>
        /// Reloads certificates present on token.
        /// This method may use provider of PIN codes (IPinProvider).
        /// </summary>
        public void ReloadCertificates()
        {
            if (_disposed)
                throw new ObjectDisposedException(this.GetType().FullName);

            _certificates = FindCertificates();
        }

        /// <summary>
        /// Constructs internal context for Pkcs11Token class
        /// </summary>
        /// <param name="slotContext">Internal context for Pkcs11Slot class</param>
        /// <returns>Internal context for Pkcs11Token class</returns>
        private Pkcs11TokenContext GetTokenContext(Pkcs11SlotContext slotContext)
        {
            var tokenInfo = new Pkcs11TokenInfo(slotContext.Slot.GetTokenInfo());
            ISession masterSession = (!tokenInfo.Initialized) ? null : slotContext.Slot.OpenSession(SessionType.ReadOnly);
            return new Pkcs11TokenContext(tokenInfo, masterSession, slotContext);
        }

        /// <summary>
        /// Finds all X.509 certificates present on token
        /// </summary>
        /// <returns>All X.509 certificates present on token</returns>
        private List<Pkcs11X509Certificate> FindCertificates()
        {
            var certificates = new List<Pkcs11X509Certificate>();

            if (_tokenContext.TokenInfo.Initialized)
            {
                using (ISession session = _tokenContext.SlotContext.Slot.OpenSession(SessionType.ReadOnly))
                {
                    if (!this.SessionIsAuthenticated(session))
                    {
                        try
                        {
                            byte[] pin = PinProviderUtils.GetTokenPin(_tokenContext);
                            _tokenContext.AuthenticatedSession.Login(CKU.CKU_USER, pin);
                        }
                        catch (LoginCancelledException)
                        {
                            // Ignore and continue without login
                        }
                    }

                    var searchTemplate = new List<IObjectAttribute>()
                    {
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_CERTIFICATE),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true),
                        session.Factories.ObjectAttributeFactory.Create(CKA.CKA_CERTIFICATE_TYPE, CKC.CKC_X_509)
                    };

                    foreach (IObjectHandle certHandle in session.FindAllObjects(searchTemplate))
                    {
                        var pkcs11cert = new Pkcs11X509Certificate(certHandle, _tokenContext);
                        certificates.Add(pkcs11cert);
                    }
                }
            }

            return certificates;
        }

        /// <summary>
        /// Check whether session is authenticated
        /// </summary>
        /// <param name="session">Session to be checked</param>
        /// <returns>True if session is authenticated, false otherwise</returns>
        private bool SessionIsAuthenticated(ISession session)
        {
            ISessionInfo sessionInfo = session.GetSessionInfo();
            switch (sessionInfo.State)
            {
                case CKS.CKS_RO_PUBLIC_SESSION:
                case CKS.CKS_RW_PUBLIC_SESSION:
                    return false;
                case CKS.CKS_RO_USER_FUNCTIONS:
                case CKS.CKS_RW_USER_FUNCTIONS:
                case CKS.CKS_RW_SO_FUNCTIONS:
                    return true;
                default:
                    throw new NotSupportedException($"Session state {sessionInfo.State} is not supported");
            }
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

                    if (_tokenContext != null)
                    {
                        _tokenContext.Dispose();
                        _tokenContext = null;
                    }
                }

                // Dispose unmanaged objects

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~Pkcs11Token()
        {
            Dispose(false);
        }

        #endregion
    }
}

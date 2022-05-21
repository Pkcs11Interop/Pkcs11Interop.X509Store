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
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// PKCS#11 slot representing a logical reader that potentially contains a token
    /// </summary>
    public class Pkcs11Slot : IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// Internal context for Pkcs11Slot class
        /// </summary>
        private Pkcs11SlotContext _slotContext = null;

        /// <summary>
        /// Detailed information about PKCS#11 slot representing a logical reader
        /// </summary>
        public Pkcs11SlotInfo Info
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _slotContext.SlotInfo;
            }
        }

        /// <summary>
        /// PKCS#11 token (cryptographic device) that is typically present in the slot
        /// </summary>
        private Pkcs11Token _token = null;

        /// <summary>
        /// PKCS#11 token (cryptographic device) that is typically present in the slot
        /// </summary>
        public Pkcs11Token Token
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _token;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11Slot class
        /// </summary>
        /// <param name="slot">High level PKCS#11 slot</param>
        /// <param name="storeContext">Internal context for Pkcs11X509Store class</param>
        internal Pkcs11Slot(ISlot slot, Pkcs11X509StoreContext storeContext)
        {
            if (slot == null)
                throw new ArgumentNullException(nameof(slot));

            if (storeContext == null)
                throw new ArgumentNullException(nameof(storeContext));

            _slotContext = this.GetSlotContext(slot, storeContext);
            _token = this.GetToken();
        }

        /// <summary>
        /// Constructs internal context for Pkcs11Slot class
        /// </summary>
        /// <param name="slot">High level PKCS#11 slot</param>
        /// <param name="storeContext">Internal context for Pkcs11X509Store class</param>
        /// <returns>Internal context for Pkcs11Slot class</returns>
        private Pkcs11SlotContext GetSlotContext(ISlot slot, Pkcs11X509StoreContext storeContext)
        {
            var slotInfo = new Pkcs11SlotInfo(slot.GetSlotInfo());
            return new Pkcs11SlotContext(slot, slotInfo, storeContext);
        }

        /// <summary>
        /// Gets PKCS#11 token (cryptographic device) that is typically present in the slot
        /// </summary>
        /// <returns>PKCS#11 token (cryptographic device) that is typically present in the slot</returns>
        private Pkcs11Token GetToken()
        {
            if (!_slotContext.Slot.GetSlotInfo().SlotFlags.TokenPresent)
                return null;
            else
                return new Pkcs11Token(_slotContext);
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

                    if (_token != null)
                    {
                        _token.Dispose();
                        _token = null;
                    }
                }

                // Dispose unmanaged objects

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~Pkcs11Slot()
        {
            Dispose(false);
        }

        #endregion
    }
}

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
    /// Internal context for Pkcs11Slot class
    /// </summary>
    internal class Pkcs11SlotContext
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// High level PKCS#11 slot
        /// </summary>
        private ISlot _slot = null;

        /// <summary>
        /// High level PKCS#11 slot
        /// </summary>
        internal ISlot Slot
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _slot;
            }
        }

        /// <summary>
        /// Detailed information about PKCS#11 slot
        /// </summary>
        private Pkcs11SlotInfo _slotInfo = null;

        /// <summary>
        /// Detailed information about PKCS#11 slot
        /// </summary>
        internal Pkcs11SlotInfo SlotInfo
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _slotInfo;
            }
        }

        /// <summary>
        /// Internal context for Pkcs11X509Store class
        /// </summary>
        private Pkcs11X509StoreContext _storeContext = null;

        /// <summary>
        /// Internal context for Pkcs11X509Store class
        /// </summary>
        internal Pkcs11X509StoreContext StoreContext
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _storeContext;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11SlotContext class
        /// </summary>
        /// <param name="slot">High level PKCS#11 slot</param>
        /// <param name="slotInfo">Detailed information about PKCS#11 slot</param>
        /// <param name="storeContext">Internal context for Pkcs11X509Store class</param>
        internal Pkcs11SlotContext(ISlot slot, Pkcs11SlotInfo slotInfo, Pkcs11X509StoreContext storeContext)
        {
            _slot = slot ?? throw new ArgumentNullException(nameof(slot));
            _slotInfo = slotInfo ?? throw new ArgumentNullException(nameof(slotInfo));
            _storeContext = storeContext ?? throw new ArgumentNullException(nameof(storeContext));
        }
    }
}

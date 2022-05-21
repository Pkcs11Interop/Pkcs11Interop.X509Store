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
    /// PKCS#11 based read-only X.509 store with certificates and corresponding asymmetric keys
    /// </summary>
    public class Pkcs11X509Store : IDisposable
    {
        /// <summary>
        /// Flag indicating whether instance has been disposed
        /// </summary>
        private bool _disposed = false;

        /// <summary>
        /// Internal context for Pkcs11X509Store class
        /// </summary>
        private Pkcs11X509StoreContext _storeContext = null;

        /// <summary>
        /// Detailed information about PKCS#11 based X.509 store
        /// </summary>
        public Pkcs11X509StoreInfo Info
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _storeContext.StoreInfo;
            }
        }

        /// <summary>
        /// List of available PKCS#11 slots representing logical readers
        /// </summary>
        private List<Pkcs11Slot> _slots = null;

        /// <summary>
        /// List of available PKCS#11 slots representing logical readers
        /// </summary>
        public List<Pkcs11Slot> Slots
        {
            get
            {
                if (_disposed)
                    throw new ObjectDisposedException(this.GetType().FullName);

                return _slots;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11X509Store class.
        /// Also loads and initializes unmanaged PCKS#11 library.
        /// </summary>
        /// <param name="libraryPath">Name of or path to PKCS#11 library</param>
        /// <param name="pinProvider">Provider of PIN codes for PKCS#11 tokens and keys</param>
        public Pkcs11X509Store(string libraryPath, IPinProvider pinProvider)
        {
            if (string.IsNullOrEmpty(libraryPath))
                throw new ArgumentNullException(nameof(libraryPath));

            if (pinProvider == null)
                throw new ArgumentNullException(nameof(pinProvider));

            _storeContext = this.GetStoreContext(libraryPath, pinProvider);
            _slots = this.GetSlots();
        }

        /// <summary>
        /// Constructs internal context for Pkcs11X509Store class
        /// </summary>
        /// <param name="libraryPath">Name of or path to PKCS#11 library</param>
        /// <param name="pinProvider">Provider of PIN codes for PKCS#11 tokens and keys</param>
        /// <returns>Internal context for Pkcs11X509Store class</returns>
        private Pkcs11X509StoreContext GetStoreContext(string libraryPath, IPinProvider pinProvider)
        {
            Pkcs11InteropFactories factories = new Pkcs11InteropFactories();

            IPkcs11Library pkcs11Library = null;

            try
            {
                pkcs11Library = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, libraryPath, AppType.MultiThreaded);
                var storeInfo = new Pkcs11X509StoreInfo(libraryPath, pkcs11Library.GetInfo());
                return new Pkcs11X509StoreContext(pkcs11Library, storeInfo, pinProvider);
            }
            catch
            {
                if (pkcs11Library != null)
                {
                    pkcs11Library.Dispose();
                    pkcs11Library = null;
                }

                throw;
            }
        }

        /// <summary>
        /// Gets list of available PKCS#11 slots representing logical readers
        /// </summary>
        /// <returns>List of available PKCS#11 slots representing logical readers</returns>
        private List<Pkcs11Slot> GetSlots()
        {
            var slots = new List<Pkcs11Slot>();

            foreach (ISlot slot in _storeContext.Pkcs11Library.GetSlotList(SlotsType.WithOrWithoutTokenPresent))
            {
                var pkcs11Slot = new Pkcs11Slot(slot, _storeContext);
                slots.Add(pkcs11Slot);
            }

            return slots;
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

                    if (_slots != null)
                    {
                        for (int i = 0; i < _slots.Count; i++)
                        {
                            if (_slots[i] != null)
                            {
                                _slots[i].Dispose();
                                _slots[i] = null;
                            }
                        }
                    }

                    if (_storeContext != null)
                    {
                        _storeContext.Dispose();
                        _storeContext = null;
                    }
                }

                // Dispose unmanaged objects

                _disposed = true;
            }
        }

        /// <summary>
        /// Class destructor that disposes object if caller forgot to do so
        /// </summary>
        ~Pkcs11X509Store()
        {
            Dispose(false);
        }

        #endregion
    }
}

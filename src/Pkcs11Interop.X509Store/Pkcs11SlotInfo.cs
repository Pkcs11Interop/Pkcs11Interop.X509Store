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
    /// Detailed information about PKCS#11 slot representing a logical reader that potentially contains a token
    /// </summary>
    public class Pkcs11SlotInfo
    {
        /// <summary>
        /// Description of the slot
        /// </summary>
        private string _description = null;

        /// <summary>
        /// Description of the slot
        /// </summary>
        public string Description
        {
            get
            {
                return _description;
            }
        }

        /// <summary>
        /// Manufacturer of the slot
        /// </summary>
        private string _manufacturer = null;

        /// <summary>
        /// Manufacturer of the slot
        /// </summary>
        public string Manufacturer
        {
            get
            {
                return _manufacturer;
            }
        }

        /// <summary>
        /// Creates new instance of Pkcs11SlotInfo class
        /// </summary>
        /// <param name="slotInfo">Information about PKCS#11 slot (CK_SLOT_INFO)</param>
        internal Pkcs11SlotInfo(ISlotInfo slotInfo)
        {
            if (slotInfo == null)
                throw new ArgumentNullException(nameof(slotInfo));

            _description = slotInfo.SlotDescription;
            _manufacturer = slotInfo.ManufacturerId;
        }
    }
}

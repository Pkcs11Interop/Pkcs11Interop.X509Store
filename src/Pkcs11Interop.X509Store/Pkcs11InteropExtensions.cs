/*
 *  Copyright 2017-2018 The Pkcs11Interop Project
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
using System.Reflection;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using HLA41 = Net.Pkcs11Interop.HighLevelAPI41;
using LLA41 = Net.Pkcs11Interop.LowLevelAPI41;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Temporary extensions for Pkcs11Interop classes (will be removed with next release of Pkcs11Interop)
    /// </summary>
    public static class Pkcs11InteropExtensions
    {
        /// <summary>
        /// Signs single-part data, where the signature is an appendix to the data
        /// </summary>
        /// <param name="session">Instance of the extended class</param>
        /// <param name="mechanism">Signature mechanism</param>
        /// <param name="keyHandle">Signature key</param>
        /// <param name="data">Data to be signed</param>
        /// <param name="pin">Pin of user</param>
        /// <returns>Signature</returns>
        public static byte[] Sign(this Session session, Mechanism mechanism, ObjectHandle keyHandle, byte[] data, byte[] pin)
        {
            if (Platform.UnmanagedLongSize == 4)
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    var mechanism41 = (HLA41.Mechanism)typeof(Mechanism).GetField("_mechanism41", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(mechanism);
                    var keyHandle41 = (HLA41.ObjectHandle)typeof(ObjectHandle).GetField("_objectHandle41", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(keyHandle);

                    return session.HLA41Session.Sign(mechanism41, keyHandle41, data, pin);
                }
            }
            else
            {
                if (Platform.StructPackingSize == 0)
                {
                    throw new NotImplementedException();
                }
                else
                {
                    throw new NotImplementedException();
                }
            }
        }

        /// <summary>
        /// Signs single-part data, where the signature is an appendix to the data
        /// </summary>
        /// <param name="session">Instance of the extended class</param>
        /// <param name="mechanism">Signature mechanism</param>
        /// <param name="keyHandle">Signature key</param>
        /// <param name="data">Data to be signed</param>
        /// <param name="pin">Pin of user</param>
        /// <returns>Signature</returns>
        public static byte[] Sign(this HLA41.Session session, HLA41.Mechanism mechanism, HLA41.ObjectHandle keyHandle, byte[] data, byte[] pin)
        {
            if (session.Disposed)
                throw new ObjectDisposedException(session.GetType().FullName);

            if (mechanism == null)
                throw new ArgumentNullException("mechanism");

            if (keyHandle == null)
                throw new ArgumentNullException("keyHandle");

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] pinValue = null;
            uint pinValueLen = 0;
            if (pin != null)
            {
                pinValue = pin;
                pinValueLen = Convert.ToUInt32(pin.Length);
            }

            var ckMechanism40 = (LLA41.CK_MECHANISM)typeof(HLA41.Mechanism).GetField("_ckMechanism", BindingFlags.NonPublic | BindingFlags.Instance).GetValue(mechanism);

            CKR rv = session.LowLevelPkcs11.C_SignInit(session.SessionId, ref ckMechanism40, keyHandle.ObjectId);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_SignInit", rv);

            rv = session.LowLevelPkcs11.C_Login(session.SessionId, CKU.CKU_CONTEXT_SPECIFIC, pinValue, pinValueLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_Login", rv);

            uint signatureLen = 0;
            rv = session.LowLevelPkcs11.C_Sign(session.SessionId, data, Convert.ToUInt32(data.Length), null, ref signatureLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_Sign", rv);

            byte[] signature = new byte[signatureLen];
            rv = session.LowLevelPkcs11.C_Sign(session.SessionId, data, Convert.ToUInt32(data.Length), signature, ref signatureLen);
            if (rv != CKR.CKR_OK)
                throw new Pkcs11Exception("C_Sign", rv);

            if (signature.Length != signatureLen)
                Array.Resize(ref signature, Convert.ToInt32(signatureLen));

            return signature;
        }
    }
}

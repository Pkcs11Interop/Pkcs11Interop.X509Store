﻿/*
 *  Copyright 2017-2025 The Pkcs11Interop Project
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
using System.Runtime.Serialization;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Exception indicating that public key object corresponding to certificate object was found on token
    /// </summary>
    [Serializable]
    public class PublicKeyObjectNotFoundException : Exception
    {
        /// <summary>
        /// Initializes new instance of PublicKeyObjectNotFoundException class
        /// </summary>
        /// <param name="message">Message that describes the error</param>
        public PublicKeyObjectNotFoundException(string message = "The public key object corresponding to the certificate object was not found on the token")
            : base(message)
        {

        }

        /// <summary>
        /// Initializes new instance of PublicKeyObjectNotFoundException class
        /// </summary>
        /// <param name="info">SerializationInfo that holds the serialized object data about the exception being thrown</param>
        /// <param name="context">StreamingContext that contains contextual information about the source or destination</param>
        protected PublicKeyObjectNotFoundException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {

        }
    }
}

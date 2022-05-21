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
using System.Runtime.Serialization;

namespace Net.Pkcs11Interop.X509Store
{
    /// <summary>
    /// Exception indicating that login operation was cancelled
    /// </summary>
    [Serializable]
    public class LoginCancelledException : Exception
    {
        /// <summary>
        /// Initializes new instance of LoginCancelledException class
        /// </summary>
        /// <param name="message">Message that describes the error</param>
        public LoginCancelledException(string message)
            : base(message)
        {

        }

        /// <summary>
        /// Initializes new instance of LoginCancelledException class
        /// </summary>
        /// <param name="info">SerializationInfo that holds the serialized object data about the exception being thrown</param>
        /// <param name="context">StreamingContext that contains contextual information about the source or destination</param>
        protected LoginCancelledException(SerializationInfo info, StreamingContext context)
            : base(info, context)
        {

        }
    }
}

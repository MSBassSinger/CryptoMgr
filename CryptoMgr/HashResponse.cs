using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jeff.Jones.CryptoMgr
{
    /// <summary>
    /// Represents the result of a cryptographic hashing operation, including the computed hash and the salt used.
    /// </summary>
    /// <remarks>This class encapsulates the hash value and the salt used during a hashing operation.  It is
    /// typically used to store or transfer the results of a hashing process, such as password hashing.</remarks>
    public class HashResponse
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="HashResponse"/> class with the specified hash and salt values.
        /// </summary>
        /// <param name="hash">The computed hash value. This value cannot be null or empty.</param>
        /// <param name="salt">The salt value used during the hash computation. This value cannot be null or empty.</param>
        public HashResponse(String hash, String salt)
        {
            Hash = hash;
            Salt = salt;
        }

        /// <summary>
        /// Gets or sets the hash value associated with the current object.
        /// </summary>
        public String Hash { get; set; } = "";

        /// <summary>
        /// Gets or sets the cryptographic salt value used for hashing operations.
        /// </summary>
        public String Salt { get; set; } = "";

        /// <summary>
        /// Gets or sets the execution time of the operation in seconds.
        /// </summary>
        public Double ExecutionTime { get; set; } = 0.0;    
    }
}

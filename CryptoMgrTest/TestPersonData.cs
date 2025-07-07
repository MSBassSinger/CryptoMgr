using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;

namespace Jeff.Jones.CryptoMgrTest
{
    /// <summary>
    /// Represents a collection of <see cref="TestPersonData"/> objects.
    ///   
    ///   Be sure to escape these characters in text values in the JSON file.",
    ///   \b  Backspace (ascii code 08)",
    ///   \f  Form feed (ascii code 0C)",
    ///   \n  New line",
    ///   \r  Carriage return",
    ///   \t  Tab",
    ///   \"  Double quote",
    ///   \\  Backslash character"
    /// </summary>
    /// <remarks>This class provides a strongly-typed list for managing <see cref="TestPersonData"/> instances. It
    /// inherits all functionality from <see cref="List{T}"/> and can be used in scenarios where a specialized list of
    /// <see cref="TestPersonData"/> is required.</remarks>
    public class TestPersonDataList : List<TestPersonData>
    {

    }


    public class TestPersonData : IComparable<TestPersonData>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TestDataList"/> class.
        /// </summary>
        /// <remarks>This constructor creates an empty instance of the <see cref="TestDataList"/> class.
        /// It invokes the base class constructor to ensure proper initialization.</remarks>
        public TestPersonData() : base()
        {
            
        }

        /// <summary>
        /// Finalizes an instance of the <see cref="TestPersonData"/> class.
        /// </summary>
        /// <remarks>This destructor is called during garbage collection to release unmanaged resources 
        /// or perform cleanup operations specific to the <see cref="TestPersonData"/> class.</remarks>
        ~TestPersonData()
        {
            
        }

        /// <summary>
        /// Gets or sets the key associated with the current object.
        /// </summary>
        [JsonPropertyName("Key")]
        public String Key { get; set; } = "";

        /// <summary>
        /// Gets or sets the initialization vector (IV) used in cryptographic operations.
        /// </summary>
        /// <remarks>The initialization vector is a critical component in certain encryption algorithms to
        /// ensure data security. Ensure that the IV is unique and properly managed to prevent vulnerabilities such as
        /// replay attacks.</remarks>
        [JsonPropertyName("IV")]
        public String IV { get; set; } = "";

        /// <summary>
        /// Gets or sets the expected value for the operation.
        /// </summary>
        [JsonPropertyName("ExpectedValue")]
        public String ExpectedValue { get; set; } = "";

        /// <summary>
        /// Gets or sets the initialization vector (IV) used for cryptographic operations.
        /// </summary>
        /// <remarks>The IV should be unique for each encryption operation to ensure security. It is
        /// recommended to use a cryptographically secure random value.</remarks>
        [JsonPropertyName("GeneratedIV")]
        public String GeneratedIV { get; set; } = "";

        /// <summary>
        /// Gets or sets the cipher mode used in the cryptographic operation.
        /// </summary>
        /// <remarks>The cipher mode defines the method of chaining blocks during encryption or
        /// decryption. Ensure that the selected mode is compatible with the encryption algorithm and meets  the
        /// security requirements of your application.</remarks>
        [JsonPropertyName("CipherMode")]
        public System.Security.Cryptography.CipherMode CipherMode { get; set; } = System.Security.Cryptography.CipherMode.CBC;

        /// <summary>
        /// Gets or sets the first name of the individual.
        /// </summary>
        [JsonPropertyName("FirstName")]
        public String FirstName { get; set; } = "";

        /// <summary>
        /// Gets or sets the last name of the individual.
        /// </summary>
        [JsonPropertyName("LastName")]
        public String LastName { get; set; } = "";

        /// <summary>
        /// Gets or sets the birthdate of the individual.
        /// </summary>
        [JsonPropertyName("Birthdate")]
        public DateTime Birthdate { get; set; } = default!;

        /// <summary>
        /// Gets or sets the date of death.
        /// </summary>
        [JsonPropertyName("DeathDate")]
        public DateTime? DeathDate { get; set; } = default!;

        /// <summary>
        /// Gets or sets the current iteration count.
        /// </summary>
        [JsonPropertyName("Iteration")]
        public Int32 Iteration { get; set; } = 0;

        /// <summary>
        /// Gets or sets the description of the test.
        /// </summary>
        [JsonPropertyName("TestDescription")]
        public String TestDescription { get; set; } = "";


        /// <summary>
        /// Compares the current instance with another <see cref="TestPersonData"/> object and returns an integer  that
        /// indicates whether the current instance precedes, follows, or occurs in the same position  in the sort order
        /// as the other object.
        /// </summary>
        /// <param name="other">The <see cref="TestPersonData"/> object to compare with the current instance.  Can be <see
        /// langword="null"/>.</param>
        /// <returns>A value that indicates the relative order of the objects being compared: <list type="bullet">
        /// <item><description>A positive value if the current instance follows <paramref name="other"/> or if <paramref
        /// name="other"/> is <see langword="null"/>.</description></item> <item><description>Zero if the current
        /// instance occurs in the same position as <paramref name="other"/>.</description></item> <item><description>A
        /// negative value if the current instance precedes <paramref name="other"/>.</description></item> </list></returns>
        public Int32 CompareTo(TestPersonData? other)
        {
            Int32 retVal = 1;

            if (other == null)
            {
                retVal = 1;
            }
            else
            {
                retVal = Iteration.CompareTo(other.Iteration);
            }
            
            return retVal;
        }




    }
}
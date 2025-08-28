using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json.Serialization;

namespace Jeff.Jones.CryptoMgrTest
{

    /// <summary>
    /// Represents a collection of <see cref="TestData"/> objects.
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
    /// <remarks>This class provides a strongly-typed list for managing <see cref="TestData"/> instances. It
    /// inherits all functionality from <see cref="List{T}"/> and can be used in scenarios where a specialized list of
    /// <see cref="TestData"/> is required.</remarks>
    public class TestDataList : List<TestData>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="TestDataList"/> class.
        /// </summary>
        /// <remarks>This constructor creates an empty instance of the <see cref="TestDataList"/> class.
        /// It invokes the base class constructor to ensure proper initialization.</remarks>
        public TestDataList() : base()
        {
                       
        }


    }

    /// <summary>
    /// Represents a collection of <see cref="TestData" /> objects.
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
    /// <remarks>This class provides a strongly-typed list for managing <see cref="TestData" /> instances. It
    /// inherits all functionality from <see cref="List{T}" /> and can be used in scenarios where a specialized list of
    /// <see cref="TestData" /> is required.</remarks>
    public class CopyOfTestDataList : List<TestData>
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="CopyOfTestDataList"/> class.
        /// </summary>
        /// <remarks>This constructor creates an empty instance of the <see cref="CopyOfTestDataList"/> class.
        /// It invokes the base class constructor to ensure proper initialization.</remarks>
        public CopyOfTestDataList() : base()
        {

        }


    }

    /// <summary>
    /// Represents a set of test data used for cryptographic operations, including encryption and decryption.
    /// </summary>
    /// <remarks>This class provides properties to configure and store values related to cryptographic tests,
    /// such as initialization vectors (IVs), keys, cipher modes, and expected results. It is intended to be used in
    /// scenarios where cryptographic functionality needs to be validated or tested.</remarks>
    public class TestData : IComparable<TestData>
    {

        /// <summary>
        /// Initializes a new instance of the <see cref="TestData"/> class.
        /// </summary>
        public TestData()
        {
            
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="TestData"/> class.
        /// </summary>
        public TestData(Int32 iteration)
        {
            Iteration = iteration;
        }

        /// <summary>
        /// Gets or sets the current iteration count.
        /// </summary>
        [JsonPropertyName("Iteration")]
        public Int32 Iteration { get; set; } = 0;

        /// <summary>
        /// Gets or sets the name associated with the current object.
        /// </summary>
        [JsonPropertyName("Name")]
        public String Name { get; set; } = "";


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
        /// Gets or sets the value to be encrypted.
        /// </summary>
        [JsonPropertyName("ValueToEncrypt")]
        public String ValueToEncrypt { get; set; } = "";

        /// <summary>
        /// Gets or sets the description of the test.
        /// </summary>
        [JsonPropertyName("TestDescription")]
        public String TestDescription { get; set; } = "";

        /// <summary>
        /// Compares the current instance with another <see cref="TestData"/> object and returns an integer  that
        /// indicates whether the current instance precedes, follows, or occurs in the same position  in the sort order
        /// as the other object.
        /// </summary>
        /// <remarks>The comparison is based on the <see cref="Iteration"/> property of the <see
        /// cref="TestData"/> objects. If <paramref name="other"/> is <see langword="null"/>, this instance is
        /// considered greater.</remarks>
        /// <param name="other">The <see cref="TestData"/> object to compare to the current instance. Can be null.</param>
        /// <returns>A value that indicates the relative order of the objects being compared: <list type="bullet"> <item>
        /// <description>Less than zero if this instance precedes <paramref name="other"/> in the sort
        /// order.</description> </item> <item> <description>Zero if this instance occurs in the same position in the
        /// sort order as <paramref name="other"/>.</description> </item> <item> <description>Greater than zero if this
        /// instance follows <paramref name="other"/> in the sort order,  or if <paramref name="other"/> is <see
        /// langword="null"/>.</description> </item> </list></returns>
        public Int32 CompareTo(TestData? other)
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

    /// <summary>
    /// Represents a set of test data used for cryptographic operations, including encryption and decryption.
    /// </summary>
    /// <remarks>This class provides properties to configure and store values related to cryptographic tests,
    /// such as initialization vectors (IVs), keys, cipher modes, and expected results. It is intended to be used in
    /// scenarios where cryptographic functionality needs to be validated or tested.</remarks>
    public class CopyOfTestData : IComparable<CopyOfTestData>
    {

        /// <summary>
        /// Initializes a new instance of the <see cref="CopyOfTestData"/> class.
        /// </summary>
        public CopyOfTestData()
        {

        }

        /// <summary>
        /// Initializes a new instance of the <see cref="CopyOfTestData"/> class.
        /// </summary>
        public CopyOfTestData(Int32 iteration)
        {
            Iteration = iteration;
        }

        /// <summary>
        /// Gets or sets the current iteration count.
        /// </summary>
        [JsonPropertyName("Iteration")]
        public Int32 Iteration { get; set; } = 0;


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
        /// Gets or sets the value to be encrypted.
        /// </summary>
        [JsonPropertyName("ValueToEncrypt")]
        public String ValueToEncrypt { get; set; } = "";

        /// <summary>
        /// Gets or sets the description of the test.
        /// </summary>
        [JsonPropertyName("TestDescription")]
        public String TestDescription { get; set; } = "";

        /// <summary>
        /// Compares the current instance with another <see cref="CopyOfTestData"/> object and returns an integer  that
        /// indicates whether the current instance precedes, follows, or occurs in the same position  in the sort order
        /// as the other object.
        /// </summary>
        /// <remarks>The comparison is based on the <see cref="Iteration"/> property of the <see
        /// cref="CopyOfTestData"/> objects. If <paramref name="other"/> is <see langword="null"/>, this instance is
        /// considered greater.</remarks>
        /// <param name="other">The <see cref="CopyOfTestData"/> object to compare to the current instance. Can be null.</param>
        /// <returns>A value that indicates the relative order of the objects being compared: <list type="bullet"> <item>
        /// <description>Less than zero if this instance precedes <paramref name="other"/> in the sort
        /// order.</description> </item> <item> <description>Zero if this instance occurs in the same position in the
        /// sort order as <paramref name="other"/>.</description> </item> <item> <description>Greater than zero if this
        /// instance follows <paramref name="other"/> in the sort order,  or if <paramref name="other"/> is <see
        /// langword="null"/>.</description> </item> </list></returns>
        public Int32 CompareTo(CopyOfTestData? other)
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
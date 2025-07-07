using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

namespace Jeff.Jones.CryptoMgrTest
{
    public static class Helpers
    {



        /// <summary>
        /// Retrieves a list of test data from a JSON file and deserializes it into a <see cref="TestDataList"/> object.
        /// </summary>
        /// <remarks>The method reads the contents of a file named "TestData.json" and deserializes it
        /// into a <see cref="TestDataList"/>  using specific <see cref="JsonSerializerOptions"/>. The returned list is
        /// sorted in ascending order by the  <c>Iteration</c> property of its elements.</remarks>
        /// <returns>A <see cref="TestDataList"/> containing the deserialized test data. The list is sorted by the
        /// <c>Iteration</c> property.</returns>
        public static TestDataList GetTestData()
        {
            TestDataList retVal = null;

            JsonSerializerOptions options = new JsonSerializerOptions
            {
                WriteIndented = true,
                AllowTrailingCommas = true,
                Converters = { new JsonStringEnumConverter() }
            };

            // This section shows how to create a populate JSON string,
            // so it can be saved as the contents of TestData.json
            #region JSON Data Generation
            //retVal = new TestDataList();

            //retVal.Add(new TestData()
            //{
            //    Iteration = 1,
            //    Key = "$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ",
            //    IV = "1234567887654321",
            //    ExpectedValue = "0FRux8wphlqpLxKgz9AJjw==",
            //    GeneratedIV = "",
            //    CipherMode = System.Security.Cryptography.CipherMode.CBC,
            //    ValueToEncrypt = "ThisIs@Pas$wurd",
            //    TestDescription = "Using Key, IV, CBC Cipher, Moderate length value"
            //});

            //retVal.Add(new TestData()
            //{
            //    Iteration = 2,
            //    Key = "$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ",
            //    IV = "1234567887654322",
            //    ExpectedValue = "53KWg6bqEqRtyglZZRBn4g==\" \")",
            //    GeneratedIV = "",
            //    CipherMode = System.Security.Cryptography.CipherMode.CBC,
            //    ValueToEncrypt = "ShortText",
            //    TestDescription = "Using Key, IV, CBC Cipher, Short length value"
            //});

            //retVal.Add(new TestData()
            //{
            //    Iteration = 3,
            //    Key = "$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ",
            //    IV = "1234567887654323",
            //    ExpectedValue = "BfSlG+bBUC2xP3Elp6H2lpK/gJHQUQW0DRm/DRSpZiHdBpmjIn/rlXv2bvHBjUIzpRaVC/Canty2Q/aXQ0k5Idl87+r5Q1OhaUqbvL7ZCfDo2A2rEbppHdfKU3eMGVGb",
            //    GeneratedIV = "",
            //    CipherMode = System.Security.Cryptography.CipherMode.CBC,
            //    ValueToEncrypt = "This is a long string to be encrypted to see how it goes. Did you know 2 + 2 = 4?",
            //    TestDescription = "Using Key, IV, CBC Cipher, Long length value"
            //});

            //retVal.Add(new TestData()
            //{
            //    Iteration = 4,
            //    Key = "$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ",
            //    IV = "1234567887654324",
            //    ExpectedValue = "h7SGZP46xxliwyZBBJEscQ==\" \")",
            //    GeneratedIV = "",
            //    CipherMode = System.Security.Cryptography.CipherMode.CBC,
            //    ValueToEncrypt = "000-00-0000",
            //    TestDescription = "Using Key, IV, CBC Cipher, Moderate length value that is formatted numeric"
            //});

            //retVal.Add(new TestData()
            //{
            //    Iteration = 5,
            //    Key = "$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ",
            //    IV = "",
            //    ExpectedValue = "T6B/53LFnUlNGXhTlP4ZVw==\" \")",
            //    GeneratedIV = "",
            //    CipherMode = System.Security.Cryptography.CipherMode.CBC,
            //    ValueToEncrypt = "000-00-0000",
            //    TestDescription = "Using Key, no IV, CBC Cipher, Moderate length value that is formatted numeric"
            //});
            //
            //String testDataStringIn = JsonSerializer.Serialize<TestDataList>(retVal, options);
            #endregion JSON Data Generation
            String testDataString = File.ReadAllText("TestData.json");

            retVal = JsonSerializer.Deserialize<TestDataList>(testDataString, options);

            /// Sorts ascending by Iteration
            retVal.Sort();

            return retVal;
        }

        /// <summary>
        /// Retrieves a list of test person data from a JSON file.
        /// </summary>
        /// <remarks>This method deserializes the contents of a JSON file named "TestPersonData.json" into
        /// a  <see cref="TestPersonDataList"/> object. The returned list is sorted in ascending order  by the
        /// <c>Iteration</c> property. If the JSON file contains invalid or missing data,  the behavior of the method
        /// may vary depending on the deserialization process.</remarks>
        /// <returns>A <see cref="TestPersonDataList"/> containing test person data, sorted by the <c>Iteration</c> property.</returns>
        public static TestPersonDataList GetTestPersonData()
        {
            TestPersonDataList retVal = null;

            JsonSerializerOptions options = new JsonSerializerOptions
            {
                WriteIndented = true,
                AllowTrailingCommas = true,
                Converters = { new JsonStringEnumConverter() }
            };

            // This section shows how to create a populate JSON string,
            // so it can be saved as the contents of TestData.json
            #region JSON Data Generation
            //retVal = new TestPersonDataList();

            //retVal.Add(new TestPersonData()
            //{
            //    Iteration = 1,
            //    FirstName = "George",
            //    LastName = "Washington",
            //    Birthdate = new DateTime(1732, 2, 22, 8, 0, 0),
            //    DeathDate = new DateTime(1799, 12, 4, 18, 10, 0),
            //    TestDescription = "Using Key, IV, CBC Cipher, Serialized class", 
            //    Key = "$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ",
            //    IV = "1234567887654321",
            //    ExpectedValue = "WCBvUzMEHkaj9bA5R7eVh9NJQN3HogW4bsRJXzM2Wkxz+neET0MSWVQpTBNca0WCETPWdZGRmbCg+xpVHOQ8mj4v4vqJkpuDDi6QUBrPKVSjwugSSxORrnVVolgdYl+zfcbonHUKz6cLlQ37FcQO1Ig5bZ82zQLFheg4Uh+Qfd1juOyjpraHrNtUazy3mO3plwJni46VoCJWFKdg22fwi6k+c/khjBd7K1UjeioVsHRSpquaMwsVIdEXZwpIzlop",
            //    GeneratedIV = "",
            //    CipherMode = System.Security.Cryptography.CipherMode.CBC            
            //});

            //retVal.Add(new TestPersonData()
            //{
            //    Iteration = 2,
            //    FirstName = "Thomas",
            //    LastName = "Jefferson",
            //    Birthdate = new DateTime(1743, 4, 13, 8, 0, 0),
            //    DeathDate = new DateTime(1826, 7, 4, 19, 20, 0),
            //    TestDescription = "Using Key, IV, CBC Cipher, Serialized class",
            //    Key = "$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ",
            //    IV = "1234567887654321",
            //    ExpectedValue = "WCBvUzMEHkaj9bA5R7eVh73olNW29Gg4n8+nHItUIYD6dEj+FWoAWEj+PsoXV9d7vraWepYEfrd3IiV7t0l35NEX/SgbIqM7ZChBXYfl8tN0JFlikvkWqiGQcauvWUHdtktLgWu8Tp4cjsbDgy9gbhm+/Ngk9rE9+Yj6UN7Kr/g9v9Lt5IHI5zaSr1SVUb5pyTgnzSl9Cp/lt+IamFsVJQsMz/gvphk+I99Iy88MziWGLClBF6Umvc2pNzk15rTs",
            //    GeneratedIV = "",
            //    CipherMode = System.Security.Cryptography.CipherMode.CBC
            //});

            //retVal.Add(new TestPersonData()
            //{
            //    Iteration = 3,
            //    FirstName = "William",
            //    LastName = "Clinton",
            //    Birthdate = new DateTime(1946, 8, 19, 20, 30, 0),
            //    DeathDate = null,
            //    TestDescription = "Using Key, IV, CBC Cipher, Serialized class",
            //    Key = "$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ",
            //    IV = "1234567887654321",
            //    ExpectedValue = "WCBvUzMEHkaj9bA5R7eVh2UcEKeWkHpjD8FfBXO7mPi4hb16GIRVojkKq3TU9Ghs0hS6CGzX+ls2BVTjrSRJR+ft4TXHukq0Z0hKOdsN6h6hs/sSc2WQA8SAlabzt7/M3JS7x99xPpnQYpJv9ymXyLFeruK0Hci9SJD9uZ6UGf0YlI6bSzkDxrf0nxkEfm2OkAxqH6edLhnyTUzRaAGJO3CVn773D/7kLGmWfdOvKhU=",
            //    GeneratedIV = "",
            //    CipherMode = System.Security.Cryptography.CipherMode.CBC
            //});

            //String testDataStringIn = JsonSerializer.Serialize<TestPersonDataList>(retVal, options);

            #endregion JSON Data Generation
            String testDataString = File.ReadAllText("TestPersonData.json");

            retVal = JsonSerializer.Deserialize<TestPersonDataList>(testDataString, options);

            /// Sorts ascending by Iteration
            retVal.Sort();

            return retVal;
        }


    }
}

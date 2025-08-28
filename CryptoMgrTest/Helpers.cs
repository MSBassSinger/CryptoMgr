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
            String testDataString = File.ReadAllText("TestPersonData.json");

            retVal = JsonSerializer.Deserialize<TestPersonDataList>(testDataString, options);

            /// Sorts ascending by Iteration
            retVal.Sort();

            return retVal;
        }


    }
}

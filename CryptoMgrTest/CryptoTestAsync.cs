using Jeff.Jones.CryptoMgr;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace Jeff.Jones.CryptoMgrTest
{
    [TestClass]
    public sealed class CryptoTestAsync
    {

        private static IConfigurationRoot m_Config = default!;

        private static LogLevelsBitset m_LogLevels = default!;

        // NOTE: [AssemblyInitialize] and [AssemblyCleanup] can only exist in one test class.
        //       If you have multiple test classes, only one of them can contain these methods.
        [ClassInitialize]
        public static void ClassInit(TestContext context)
        {
            // Fix for CS1061: Ensure the required package is referenced in the project.
            // AddJsonFile is an extension method provided by Microsoft.Extensions.Configuration.Json.
            // Ensure the NuGet package "Microsoft.Extensions.Configuration.Json" and
            // "Microsoft.Extensions.Configuration.XML" are installed in the project.
            // Build a configuration object from JSON file
            m_Config = new ConfigurationBuilder()
                .SetBasePath(AppContext.BaseDirectory)
                .AddXmlFile("app.config", optional: false, reloadOnChange: true)
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();

            String logLevelString = m_Config["Logging:LogBitsetLevel"];

            m_LogLevels = Enum.Parse<LogLevelsBitset>(logLevelString);

        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            // This method is called once for the test class, after all tests of the class are run.
        }

        [TestInitialize]
        public void TestInit()
        {
            // This method is called before each test method.
        }

        [TestCleanup]
        public void TestCleanup()
        {
            // This method is called after each test method.
        }

        /// <summary>
        /// Retrieves a collection of test data.
        /// A single method is coded to return the test data, so that it can be used in multiple test methods.
        /// It is possible to add a parameter to the call to have the method dynamically change the test data 
        /// based on the parameter.
        /// </summary>
        /// <returns>A <see cref="TestDataList"/> containing the test data. The collection will be empty if no test data is
        /// available.</returns>
        public static TestDataList GetTestData()
        {
            return Helpers.GetTestData();
        }


        public static TestPersonDataList GetTestPersonData()
        {
            return Helpers.GetTestPersonData();
        }

        /// <summary>
        /// Tests encryption, decryption, and hashing of a string using the AES algorithm in CBC mode.
        /// </summary>
        /// <param name="testData">TestData instance with the data to test for 1 iteration.</param>
        [DataTestMethod]
        [DynamicData(nameof(GetTestData))]
        public async Task EncryptionTestAsync(TestData testData)
        {

            TestLogger logger = new TestLogger();

            logger.LogTrace($"Starting CryptoTestAsync.EncryptionTestAsync, iteration # [{testData.Iteration}].");

            CryptoAsync crypto = new CryptoAsync(testData.Key, testData.IV, logger, m_Config, testData.CipherMode);

            String encrypted = await crypto.EncryptStringAESAsync(testData.ValueToEncrypt);

            if (testData.IV.Length == 0)
            {
                // Use this to stop and capture a new encrypted string value to use above.
                logger.LogDebug($"[{testData.Iteration}]-[{testData.ValueToEncrypt}] [{encrypted}] Generated IV [{crypto.IV}]");
            }
            else
            {
                // Use this to stop and capture a new encrypted string value to use above.
                logger.LogDebug($"[{testData.Iteration}]-[{testData.ValueToEncrypt}] [{encrypted}]");
            }

            if (testData.IV.Length == 0)
            {
                // Use this to stop and capture a new encrypted string value to use above.
                logger.LogDebug($"[{testData.Iteration}]-[{testData.ValueToEncrypt}] [{encrypted}] Generated IV [{crypto.IV}]");
            }
            else
            {
                // Use this to stop and capture a new encrypted string value to use above.
                logger.LogDebug($"[{testData.Iteration}]-[{testData.ValueToEncrypt}] [{encrypted}]");
            }

            logger.LogInformation($"Encryption of [{testData.ValueToEncrypt}] to [{encrypted}], expecting [{testData.ExpectedValue}], iteration # [{testData.Iteration}].");

            if (testData.IV.Length > 0)
            {
                Assert.AreEqual(testData.ExpectedValue, encrypted);
            }
            else
            {
                Assert.IsNotNull(encrypted, "Used generated IV.");
            }

            String hash = await crypto.GetSHA512HashAsync(testData.ValueToEncrypt);

            logger.LogInformation($"Hash of [{testData.ValueToEncrypt}] to [{hash}] iteration # [{testData.Iteration}].");

            Assert.IsTrue(hash.Length > 0);

            String decrypted = await crypto.DecryptStringAESAsync(encrypted);

            logger.LogInformation($"Decryption of [{testData.ValueToEncrypt}] to [{decrypted}], iteration # [{testData.Iteration}].");

            Assert.AreEqual(testData.ValueToEncrypt, decrypted);

            crypto.Dispose();

            crypto = null!;

            logger.LogTrace($"Exiting CryptoTestAsync.EncryptionTestAsync, iteration # [{testData.Iteration}].");

            logger = null!;
        }

        /// <summary>
        /// Tests encryption, decryption, and hashing of an object using the AES algorithm in CBC mode.
        /// </summary>
        /// <param name="testData">TestPersonData instance with the data to test for 1 iteration.</param>
        [DataTestMethod]
        [DynamicData(nameof(GetTestPersonData))]
        public async Task EncryptionObjectTestAsync(TestPersonData testData)
        {
            TestLogger logger = new TestLogger();

            logger.LogTrace($"Starting CryptoTestAsync.EncryptionTestAsync, iteration # [{testData.Iteration}].");

            CryptoAsync crypto = new CryptoAsync(testData.Key, testData.IV, logger, m_Config, testData.CipherMode);

            TestPersonClass testBefore = new TestPersonClass()
            {
                FirstName = testData.FirstName,
                LastName = testData.LastName,
                BirthDate = testData.Birthdate,
                DeathDate = testData.DeathDate
            };

            testBefore.MyList.Add("Test1");
            testBefore.MyList.Add("Test2");

            String encrypted = await crypto.EncryptObjectAESAsync<TestPersonClass>(testBefore);

            // Use this to stop and capture a new encrypted string value to use above.
            logger.LogDebug($"[testBefore] [{encrypted}]");

            Assert.AreEqual(testData.ExpectedValue, encrypted);

            // Sample JSON before encryption:
            //{
            //    "FirstName": "George",
            //    "LastName": "Washington",
            //    "BirthDate": "1732-02-22T08:00:00",
            //    "DeathDate": "1799-12-04T08:00:00",
            //    "MyList": [
            //      "Test1",
            //      "Test2"
            //    ]
            //}
            String hashBefore = await crypto.GetObjectSHA512HashAsync<TestPersonClass>(testBefore);

            Assert.IsTrue(hashBefore.Length > 0);

            TestPersonClass testAfter = await crypto.DecryptObjectAESAsync<TestPersonClass>(encrypted);

            // Sample JSON after encryption:
            //{
            //    "FirstName": "George",
            //    "LastName": "Washington",
            //    "BirthDate": "1732-02-22T08:00:00",
            //    "DeathDate": "1799-12-04T08:00:00",
            //    "MyList": [
            //        "Test1",
            //        "Test2"
            //    ]
            //}

            String hashAfter = await crypto.GetObjectSHA512HashAsync<TestPersonClass>(testAfter);

            Assert.IsTrue(hashAfter.Length > 0);

            Assert.AreEqual(hashBefore, hashAfter);

            crypto.Dispose();

            crypto = null!;

            testBefore = null!;

            testAfter = null!;

            logger.LogTrace($"Exiting CryptoTestAsync.EncryptionTestAsync, iteration # [{testData.Iteration}].");

            logger = null!;
        }

    }
}

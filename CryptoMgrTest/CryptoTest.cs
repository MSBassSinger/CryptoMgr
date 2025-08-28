using Jeff.Jones.CryptoMgr;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.Json;
using Microsoft.Extensions.Configuration.Xml;
using Microsoft.Extensions.Logging;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Jeff.Jones.CryptoMgrTest
{
    /// <summary>
    /// Provides unit tests for cryptographic operations, including encryption, decryption, and hashing.
    /// </summary>
    /// <remarks>This class contains test methods for verifying the behavior of cryptographic operations using
    /// the <see cref="Crypto"/> class. It includes tests for string encryption and decryption, as well as object
    /// encryption and decryption. Additionally, lifecycle methods are implemented to manage setup and cleanup at the
    /// assembly, class, and test levels.</remarks>
    [TestClass]
    public sealed class CryptoTest
    {
        private static IConfigurationRoot m_Config = default!;

        private static LogLevelsBitset m_LogLevels = default!;


        [AssemblyInitialize]
        public static void AssemblyInit(TestContext context)
        {
            // This method is called once for the test class, before any tests of the class are run.
        }

        [AssemblyCleanup]
        public static void AssemblyCleanup()
        {
            // This method is called once for the test assembly, after all tests are run.
        }

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
        public void EncryptionTest(TestData testData)
        {
            TestLogger logger = new TestLogger();

            logger.LogTrace($"Starting CryptoTest.EncryptionTest, iteration # [{testData.Iteration}].");

            Crypto crypto = new Crypto(testData.Key, testData.IV, logger, m_LogLevels, testData.CipherMode);

            String encrypted = crypto.EncryptStringAES(testData.ValueToEncrypt);

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


            HashResponse hashReponse = crypto.GetSHA512Hash(testData.ValueToEncrypt, true);

            logger.LogInformation($"Hash of [{testData.ValueToEncrypt}] to [{hashReponse.Hash}] with random salt [{hashReponse.Salt}], iteration # [{testData.Iteration}].");

            Assert.IsTrue(hashReponse.Hash.Length > 0, $"Hash [{hashReponse.Hash}] created.");

            Boolean hashMatch = crypto.VerifySHA512Hash(testData.ValueToEncrypt, hashReponse.Hash, hashReponse.Salt);

            Assert.IsTrue(hashMatch, "Hash was verified with salt");


            hashReponse = crypto.GetSHA512Hash(testData.ValueToEncrypt, false);

            Assert.IsTrue(hashReponse.Salt.Length == 0, "Salt was not generated, as specified.");

            logger.LogInformation($"Hash of [{testData.ValueToEncrypt}] to [{hashReponse.Hash}] with no random salt, iteration # [{testData.Iteration}].");

            Assert.IsTrue(hashReponse.Hash.Length > 0, $"Hash [{hashReponse.Hash}] created.");

            hashMatch = crypto.VerifySHA512Hash(testData.ValueToEncrypt, hashReponse.Hash, "");

            Assert.IsTrue(hashMatch, "Hash was verified with no salt.");



            String decrypted = crypto.DecryptStringAES(encrypted);

            logger.LogInformation($"Decryption of [{testData.ValueToEncrypt}] to [{decrypted}], iteration # [{testData.Iteration}].");

            Assert.AreEqual(testData.ValueToEncrypt, decrypted);

            crypto.Dispose();

            crypto = null!;

            logger.LogTrace($"Exiting CryptoTest.EncryptionTest, iteration # [{testData.Iteration}].");

            logger = null!;
        }


        [DataTestMethod]
        [DynamicData(nameof(GetTestData))]
        public void EncryptionServiceTest(TestData testData)
        {
            TestLogger logger = new TestLogger();

            logger.LogTrace($"Starting CryptoTest.EncryptionTest, iteration # [{testData.Iteration}].");

            CryptoMgrService.Instance.Initialize(logger, m_LogLevels);

            logger.LogInformation($"Crypto instance named [{testData.Name}] has been added to the cache.");

            CryptoMgrService.Instance.AddCrypto(testData.Name, testData.Key, testData.IV, testData.CipherMode);

            Crypto crypto = CryptoMgrService.Instance.GetCrypto(testData.Name);

            logger.LogInformation($"Crypto instance named [{testData.Name}] in the cache has been accessed.");

            String encrypted = crypto.EncryptStringAES(testData.ValueToEncrypt);

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


            HashResponse hashReponse = crypto.GetSHA512Hash(testData.ValueToEncrypt, true);

            logger.LogInformation($"Hash of [{testData.ValueToEncrypt}] to [{hashReponse.Hash}] with random salt [{hashReponse.Salt}], iteration # [{testData.Iteration}].");

            Assert.IsTrue(hashReponse.Hash.Length > 0, $"Hash [{hashReponse.Hash}] created.");

            Boolean hashMatch = crypto.VerifySHA512Hash(testData.ValueToEncrypt, hashReponse.Hash, hashReponse.Salt);

            Assert.IsTrue(hashMatch, "Hash was verified with salt");


            hashReponse = crypto.GetSHA512Hash(testData.ValueToEncrypt, false);

            Assert.IsTrue(hashReponse.Salt.Length == 0, "Salt was not generated, as specified.");

            logger.LogInformation($"Hash of [{testData.ValueToEncrypt}] to [{hashReponse.Hash}] with no random salt, iteration # [{testData.Iteration}].");

            Assert.IsTrue(hashReponse.Hash.Length > 0, $"Hash [{hashReponse.Hash}] created.");

            hashMatch = crypto.VerifySHA512Hash(testData.ValueToEncrypt, hashReponse.Hash, "");

            Assert.IsTrue(hashMatch, "Hash was verified with no salt.");



            String decrypted = crypto.DecryptStringAES(encrypted);

            logger.LogInformation($"Decryption of [{testData.ValueToEncrypt}] to [{decrypted}], iteration # [{testData.Iteration}].");

            Assert.AreEqual(testData.ValueToEncrypt, decrypted);

            CryptoMgrService.Instance.RemoveCrypto(testData.Name);

            logger.LogInformation($"Crypto instance named [{testData.Name}] has been removed from the cache.");

            crypto = null!;

            logger.LogTrace($"Exiting CryptoTest.EncryptionTest, iteration # [{testData.Iteration}].");

            logger = null!;
        }

        /// <summary>
        /// Tests encryption, decryption, and hashing of an object using the AES algorithm in CBC mode.
        /// </summary>
        /// <param name="testData">TestPersonData instance with the data to test for 1 iteration.</param>
        [DataTestMethod]
        [DynamicData(nameof(GetTestPersonData))]
        public void EncryptionObjectTest(TestPersonData testData)
        {

            TestLogger logger = new TestLogger();

            logger.LogTrace($"Starting CryptoTest.EncryptionObjectTest, iteration # [{testData.Iteration}].");

            Crypto crypto = new Crypto(testData.Key, testData.IV, logger, m_LogLevels, testData.CipherMode);

            TestPerson testBefore = new TestPerson()
            {
                FirstName = testData.FirstName,
                LastName = testData.LastName,
                BirthDate = testData.Birthdate,
                DeathDate = testData.DeathDate
            };

            testBefore.MyList.Add("Test1");
            testBefore.MyList.Add("Test2");

            String encrypted = crypto.EncryptObjectAES<TestPerson>(testBefore);

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

            HashResponse hashReponseBefore = crypto.GetObjectSHA512Hash<TestPerson>(testBefore, true);

            logger.LogInformation($"Hash of TestBefore object to [{hashReponseBefore.Hash}] with random salt [{hashReponseBefore.Salt}], iteration # [{testData.Iteration}].");

            Assert.IsTrue(hashReponseBefore.Hash.Length > 0, $"Hash [{hashReponseBefore.Hash}] created.");

            Boolean hashMatch = crypto.VerifyObjectSHA512Hash(testBefore, hashReponseBefore.Hash, hashReponseBefore.Salt);

            Assert.IsTrue(hashMatch, $"Hash [{hashReponseBefore.Hash}] was verified for the TestPerson object with salt");


            hashReponseBefore = crypto.GetObjectSHA512Hash<TestPerson>(testBefore, false);

            Assert.IsTrue(hashReponseBefore.Salt.Length == 0, "Salt was not generated, as specified.");

            logger.LogInformation($"Hash of TestPerson object to [{hashReponseBefore.Hash}] with no random salt, iteration # [{testData.Iteration}].");

            Assert.IsTrue(hashReponseBefore.Hash.Length > 0, $"Hash [{hashReponseBefore.Hash}] created.");

            hashMatch = crypto.VerifyObjectSHA512Hash(testBefore, hashReponseBefore.Hash, hashReponseBefore.Salt);

            Assert.IsTrue(hashMatch, $"Hash [{hashReponseBefore.Hash}] was verified with no salt.");

            TestPerson testAfter = crypto.DecryptObjectAES<TestPerson>(encrypted);

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

            HashResponse hashResponseAfter = crypto.GetObjectSHA512Hash<TestPerson>(testAfter, true);

            logger.LogInformation($"Hash of TestAfter object to [{hashResponseAfter.Hash}] with random salt [{hashResponseAfter.Salt}], iteration # [{testData.Iteration}].");

            Assert.IsTrue(hashResponseAfter.Hash.Length > 0, $"Hash [{hashResponseAfter.Hash}] created.");

            hashMatch = crypto.VerifyObjectSHA512Hash(testAfter, hashResponseAfter.Hash, hashResponseAfter.Salt);

            Assert.IsTrue(hashMatch, $"Hash [{hashResponseAfter.Hash}] was verified for the after-TestPerson object with salt");


            hashResponseAfter = crypto.GetObjectSHA512Hash<TestPerson>(testAfter, false);

            Assert.IsTrue(hashResponseAfter.Salt.Length == 0, "Salt was not generated for the after TestPerson, as specified.");

            logger.LogInformation($"Hash of the after TestPerson object to [{hashResponseAfter.Hash}] with no random salt, iteration # [{testData.Iteration}].");

            Assert.IsTrue(hashResponseAfter.Hash.Length > 0, $"Hash [{hashResponseAfter.Hash}] created.");

            hashMatch = crypto.VerifyObjectSHA512Hash(testAfter, hashResponseAfter.Hash, hashResponseAfter.Salt);

            Assert.IsTrue(hashMatch, $"Hash [{hashResponseAfter.Hash}] was verified for the after-testPerson with no salt.");

            crypto.Dispose();

            crypto = null!;

            testBefore = null!;

            testAfter = null!;

            logger.LogTrace($"Exiting CryptoTestAsync.EncryptionObjectTestAsync, iteration # [{testData.Iteration}].");

            logger = null!;
        }



    }
}

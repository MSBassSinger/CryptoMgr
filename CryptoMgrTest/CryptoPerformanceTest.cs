using Jeff.Jones.CryptoMgr;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jeff.Jones.CryptoMgrTest
{

    [TestClass]
    public sealed class CryptoPerformanceTest
    {


        private static IConfigurationRoot m_Config = default!;

        private static LogLevelsBitset m_LogLevels = default!;

        private static TestLogger m_Logger = null;

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

            String logLevelString = m_Config["Logging:LogLevel:Test"];

            m_LogLevels = Enum.Parse<LogLevelsBitset>(logLevelString);

            m_Logger = new TestLogger();

            TestDataList retVal = Helpers.GetTestData();

            CryptoMgrService.Instance.Initialize(m_Logger, m_LogLevels);

            foreach (TestData? item in retVal)
            {
                CryptoMgrService.Instance.AddCrypto(item.Name, item.Key, item.IV, item.CipherMode);
            }


        }

        [ClassCleanup]
        public static void ClassCleanup()
        {
            // This method is called once for the test class, after all tests of the class are run.
            CryptoMgrService.Instance.Dispose();
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
            TestDataList retVal = Helpers.GetTestData();

            return retVal;
        }


        public static TestPersonDataList GetTestPersonData()
        {
            return Helpers.GetTestPersonData();
        }


        [DataTestMethod]
        [DynamicData(nameof(GetTestData))]
        public void EncryptionPerformanceTest(TestData testData)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            TestLogger logger = new TestLogger();

            Crypto crypto = CryptoMgrService.Instance.GetCrypto(testData.Name);

            stopWatch.Stop();

            // This provides the log with method execution time.
            TimeSpan elapsedTime = stopWatch.Elapsed;

            String logMsg = $"Crypto Singleton GetCrypto Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

            logger.LogTrace(logMsg);


            stopWatch.Start();

            String encrypted = crypto.EncryptStringAES(testData.ValueToEncrypt);

            stopWatch.Stop();

            // This provides the log with method execution time.
            elapsedTime = stopWatch.Elapsed;

            logMsg = $"Crypto EncryptStringAES Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

            logger.LogTrace(logMsg);

            stopWatch.Start();

            HashResponse hashReponse = crypto.GetSHA512Hash(testData.ValueToEncrypt, true);

            stopWatch.Stop();

            // Get hash execution time.
            elapsedTime = stopWatch.Elapsed;

            logMsg = $"Crypto GetSHA512Hash Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

            logger.LogTrace(logMsg);

            stopWatch.Start();

            Boolean hashMatch = crypto.VerifySHA512Hash(testData.ValueToEncrypt, hashReponse.Hash, hashReponse.Salt);

            stopWatch.Stop();

            // Get hash execution time.
            elapsedTime = stopWatch.Elapsed;

            logMsg = $"Crypto VerifySHA512Hash Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

            logger.LogTrace(logMsg);

            stopWatch.Start();

            String decrypted = crypto.DecryptStringAES(encrypted);

            stopWatch.Stop();

            // Get hash execution time.
            elapsedTime = stopWatch.Elapsed;

            logMsg = $"Crypto DecryptStringAES Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

            logger.LogTrace(logMsg);

            crypto = null!;

            logger.LogTrace($"Exiting CryptoTest.EncryptionTest, iteration # [{testData.Iteration}].");

            logger = null!;
        }

    }   // END public sealed class CryptoPerformanceTest

}   // END namespace Jeff.Jones.CryptoMgrTest

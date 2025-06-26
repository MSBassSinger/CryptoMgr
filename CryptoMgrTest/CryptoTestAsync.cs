using Jeff.Jones.CryptoMgr;

namespace Jeff.Jones.CryptoMgrTest
{
    [TestClass]
    public sealed class CryptoTestAsync
    {
        // NOTE: [AssemblyInitialize] and [AssemblyCleanup] can only exist in one test class.
        //       If you have multiple test classes, only one of them can contain these methods.
        [ClassInitialize]
        public static void ClassInit(TestContext context)
        {
            // This method is called once for the test class, before any tests of the class are run.
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
        /// Tests encryption, decryption, and hashing of a string using the AES algorithm in CBC mode.
        /// </summary>
        /// <param name="key">Encryption key (a secret)</param>
        /// <param name="iv">Public string used usually one time or once per operation.</param>
        /// <param name="txt2Encrypt">The string to encrypt</param>
        /// <param name="encryptedValue">The expected encrypted string.</param>
        [TestMethod]
        [DataRow("$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ", "1234567887654321", "ThisIs@Pas$wurd", "0FRux8wphlqpLxKgz9AJjw==")]
        [DataRow("$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ", "1234567887654321", "ShortText", "fz1sHNfZi2HaotBkQYthUQ==")]
        [DataRow("$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ", "1234567887654321", "This is a long string to be encrypted to see how it goes. Did you know 2 + 2 = 4?", "12cRnivee9+1GZaWSGpaqqXB+AP/P9T2S8vJhAjcj0RhWBsom/Oqn7Jxs011MHsE2bg5aHzpJi7EhRyNQBD9EmH79Fo5SCh9NHbiVGK3HaLGqqA/vL4tkdn7nr6r0iv3")]
        [DataRow("$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ", "1234567887654321", "000-00-0000", "aa1pZYaF35+rDa7q1fvLrQ==")]
        public async Task EncryptionTestAsync(String key, String iv, String txt2Encrypt, String encryptedValue)
        {

            CryptoAsync crypto = new CryptoAsync(key, iv, System.Security.Cryptography.CipherMode.CBC);

            String encrypted = await crypto.EncryptStringAESAsync(txt2Encrypt);

            // Use this to stop and capture a new encrypted string value to use above.
            //Debug.WriteLine($"[{txt2Encrypt}] [{encrypted}]");

            Assert.AreEqual(encryptedValue, encrypted);

            String hash = await crypto.GetSHA512HashAsync(txt2Encrypt);

            Assert.IsTrue(hash.Length > 0);

            String decrypted = await crypto.DecryptStringAESAsync(encrypted);

            Assert.AreEqual(txt2Encrypt, decrypted);

            crypto.Dispose();

            crypto = null;

        }

        /// <summary>
        /// Tests encryption, decryption, and hashing of an object using the AES algorithm in CBC mode.
        /// </summary>
        /// <param name="key">Encryption key (a secret)</param>
        /// <param name="iv">Public string used usually one time or once per operation.</param>
        /// <param name="firstName">Data for the TestClass instance.</param>
        /// <param name="lastName">Data for the TestClass instance.</param>
        /// <param name="birthDate">Data for the TestClass instance.</param>
        /// <param name="deathDate">Data for the TestClass instance.</param>
        /// <param name="encryptedValue">The expected encryption value.</param>
        [TestMethod]
        [DataRow("$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ", "1234567887654321", "George", "Washington", "1732-02-22T08:00:00", "1799-12-04T18:10:00", "WCBvUzMEHkaj9bA5R7eVh9NJQN3HogW4bsRJXzM2Wkxz+neET0MSWVQpTBNca0WCETPWdZGRmbCg+xpVHOQ8mj4v4vqJkpuDDi6QUBrPKVSjwugSSxORrnVVolgdYl+zfcbonHUKz6cLlQ37FcQO1Ig5bZ82zQLFheg4Uh+Qfd1juOyjpraHrNtUazy3mO3plwJni46VoCJWFKdg22fwi6k+c/khjBd7K1UjeioVsHRSpquaMwsVIdEXZwpIzlop")]
        [DataRow("$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ", "1234567887654321", "Thomas", "Jefferson", "1743-04-13T08:00:00", "1826-07-04T19:20:00", "WCBvUzMEHkaj9bA5R7eVh73olNW29Gg4n8+nHItUIYD6dEj+FWoAWEj+PsoXV9d7vraWepYEfrd3IiV7t0l35NEX/SgbIqM7ZChBXYfl8tN0JFlikvkWqiGQcauvWUHdtktLgWu8Tp4cjsbDgy9gbhm+/Ngk9rE9+Yj6UN7Kr/g9v9Lt5IHI5zaSr1SVUb5pyTgnzSl9Cp/lt+IamFsVJQsMz/gvphk+I99Iy88MziWGLClBF6Umvc2pNzk15rTs")]
        [DataRow("$#%&(kjh565&*IKJ$#%&(kjh565&*IKJ", "1234567887654321", "William", "Clinton", "1946-08-19T20:30:00", null, "WCBvUzMEHkaj9bA5R7eVh2UcEKeWkHpjD8FfBXO7mPi4hb16GIRVojkKq3TU9Ghs0hS6CGzX+ls2BVTjrSRJR+ft4TXHukq0Z0hKOdsN6h6hs/sSc2WQA8SAlabzt7/M3JS7x99xPpnQYpJv9ymXyLFeruK0Hci9SJD9uZ6UGf0YlI6bSzkDxrf0nxkEfm2OkAxqH6edLhnyTUzRaAGJO3CVn773D/7kLGmWfdOvKhU=")]
        public async Task EncryptionObjectTestAsync(String key, String iv, String firstName, String lastName,
                                               String birthDate, String deathDate, String encryptedValue)
        {
            DateTime birthDateTime;

            DateTime deathDateTime;

            CryptoAsync crypto = new CryptoAsync(key, iv, System.Security.Cryptography.CipherMode.CBC);

            TestClass testBefore = new TestClass()
            {
                FirstName = firstName,
                LastName = lastName,
                BirthDate = null,
                DeathDate = null
            };


            if (!String.IsNullOrEmpty(birthDate))
            {
                if (DateTime.TryParse(birthDate, out birthDateTime))
                {
                    testBefore.BirthDate = birthDateTime;
                }
            }

            if (!String.IsNullOrEmpty(deathDate))
            {
                if (DateTime.TryParse(deathDate, out deathDateTime))
                {
                    testBefore.DeathDate = deathDateTime;
                }
            }

            testBefore.MyList.Add("Test1");
            testBefore.MyList.Add("Test2");

            String encrypted = await crypto.EncryptObjectAESAsync<TestClass>(testBefore);

            // Use this to stop and capture a new encrypted string value to use above.
            //Debug.WriteLine($"[{txt2Encrypt}] [{encrypted}]");

            Assert.AreEqual(encryptedValue, encrypted);


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
            String hashBefore = await crypto.GetObjectSHA512HashAsync<TestClass>(testBefore);

            Assert.IsTrue(hashBefore.Length > 0);

            TestClass testAfter = await crypto.DecryptObjectAESAsync<TestClass>(encrypted);

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

            String hashAfter = await crypto.GetObjectSHA512HashAsync<TestClass>(testAfter);

            Assert.IsTrue(hashAfter.Length > 0);

            Assert.AreEqual(hashBefore, hashAfter);

            crypto.Dispose();

            crypto = null;

            testBefore = null;

            testAfter = null;

        }

    }
}

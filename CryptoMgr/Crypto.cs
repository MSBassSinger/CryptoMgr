using Jeff.Jones.CryptoMgr.Properties;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Aes = System.Security.Cryptography.Aes;

// Note to developers:
//
// You may notice that I do not use some commonly used coding patterns in my code.
// I am not saying those patterns are bad, but I have found that they are advantages to other ways.
//
// using (SomeIDisposable x = new SomeIDisposable())
// {
//     x.DoSomething();
// }
//
//   This is a good shorthand for objects with an IDisposable or IAsyncDisposable interface.
//   However, for production code, the using statement does not capture or allow direct handling of 
//   exceptions in the constructor, nor in the IDispose or IAsyncDisposable execution.  You can wrap
//   the using statement in a try-catch.  However, when comparing the MSIL between that approach, and 
//   the try-catch-finally approach, the try-catch-finally approach is a little more efficient and 
//   provides more flexibility in handling exceptions than is possible with the using statement.
//   Since most of the difference in coding is copy-and-paste, it really doesn't add much time
//   to the development process.  It does add more value to the code in reducing errors and providing 
//   details to the log or the caller of this object.
//
// public String SomeProperty { get; set; }
//
//   I use backing variables for properties.  This makes step-through debugging easier, provides versatility 
//   in handling how the property is get or set, and allows for better validation when it is needed.
//
// IDispose/IDisposable Implementation
//   See the comments in the IDispose/IDisposable region in the code for more information.
// 
// Logging
//
//   Since Microsoft.Extensions.Logging.ILogger is ubiquitous in .NET development, I have included it in this object
//   as a means to provide logging.  If an ILogger instance is not provided, then logging code is not executed.
//   The bitset used, when ILogger is present, allows for runtime control of what is logged and what is not.  This bitset
//   uses the same types of logging that ILogger provides (Critical, Error, Warning, Information, Debug, Trace), but instead
//   of only one level being logged, multiple levels can be logged.  This is especially useful for troubleshooting.
//   
// Variable naming
//   Naming mostly depends on the scope of the variable.
//   A constant is named in all caps with underscores separating words.
//   A private variable scoped to the class is prefixed with "m_", followed by the name of the variable that is properly capitalized for a name.
//   A variable scoped to a method, including parameter names, is is camel-cased.
//   There are no public variables.  Instead, properties are used to expose a variable publicly.
//
// Static versus non-static
//   I use static sparingly.  Static variables are loaded into memory on first use, and destroyed when the parent owner is destroyed.
//   This adds up, little by little, in terms of memory use and can be an issue when using threads and tasks.
//   My preference is to create an object when I need it, use it, then destroy it when done.
//   One exception to this is with extension methods, which can only be static.


namespace Jeff.Jones.CryptoMgr
{
    /// <summary>
    /// Provides synchronous cryptographic operations, including AES encryption/decryption,  SHA-512 hashing, and
    /// object serialization/deserialization.
    /// </summary>
    /// <remarks>This class supports a synchronous disposal pattern to ensure proper 
    /// cleanup of resources. It is designed to handle cryptographic operations securely, using  AES encryption with a
    /// specified private key and initialization vector (IV). 
    /// 
    /// The IV is a critical component of AES encryption in modes like CBC (Cipher Block Chaining) because it ensures 
    /// that the same plaintext encrypted multiple times will produce different ciphertexts, enhancing security.
    /// 
    /// The class also provides methods for hashing and
    /// serialization/deserialization of objects. <para> Typical usage involves creating an instance of <see
    /// cref="Crypto"/> with a private  key and IV, then calling methods such as <see
    /// cref="EncryptObjectAES{T}"/> or  <see cref="DecryptObjectAES{T}"/> for encryption and decryption
    /// operations. </para></remarks>
    public class Crypto
    {
        /// <summary>
        /// Represents the initialization vector (IV) used in encryption and decryption operations.Initialization vector (IV); 
        /// this can differ between encryption/decryption calls using the same private key.
        /// </summary>
        /// <remarks>The initialization vector (IV) is a random or unique value that ensures the same
        /// plaintext encrypted with the same key produces different ciphertexts.  This value can vary between 
        /// encryption and decryption calls using the same private key. When an IV is used only once, it is referred to
        /// as a "nonce" (number used once).
        /// When an IV is used only once, it is also called a "nonce" (number used once).</remarks>
        private String m_IV = "";

        /// <summary>
        /// Represents the private key used for decrypting encrypted strings.They key is kept private, and is necessary to decrypt the encrypted string.
        /// </summary>
        /// <remarks>This field is intended for internal use only and should not be exposed or modified
        /// directly. The private key is required for decryption operations and must remain secure.</remarks>
        private String m_PrivateKey = "";

        /// <summary>
        /// Represents the initialization vector (IV) used in cryptographic operations.This holds the byte array of m_IV.
        /// </summary>
        /// <remarks>The initialization vector is a byte array that ensures the uniqueness of encryption
        /// results for identical plaintext inputs. It is typically required for certain encryption modes, such as
        /// CBC.</remarks>
        private Byte[] m_aryIV = default!;

        /// <summary>
        /// Represents the private key as a byte array.This holds the byte array of m_PrivateKey.
        /// </summary>
        /// <remarks>This field is read-only and intended for internal use to store the private key data.
        /// It should not be exposed or modified directly.</remarks>
        private Byte[] m_aryPrivateKey = default!;

        /// <summary>
        /// Represents the cipher mode used for cryptographic operations.
        /// </summary>
        /// <remarks>The cipher mode determines how encryption and decryption are performed on blocks of
        /// data. This field is set to <see cref="CipherMode.CBC"/>, which stands for Cipher Block Chaining. CBC mode
        /// requires an initialization vector (IV) and ensures that identical plaintext blocks produce different
        /// ciphertext blocks, enhancing security.</remarks>
        private CipherMode m_CipherMode = CipherMode.CBC;

        /// <summary>
        /// Indicates whether the object's <see cref="Crypto.Dispose()"/> method has been called.
        /// </summary>
        /// <remarks>This field is used internally to track whether the object has been disposed. It is
        /// not intended for direct use by external callers.</remarks>
        private Boolean m_blnDisposeHasBeenCalled = false;


        /// <summary>
        /// Represents the bitset of log levels used to filter logging output.
        /// </summary>
        /// <remarks>This field stores the active log levels as a bitset, allowing efficient filtering of
        /// log messages. It is initialized to the default log levels defined in <see
        /// cref="Extensions.DEFAULT_LOG_LEVELS"/>.</remarks>
        private LogLevelsBitset m_LogLevels = Extensions.DEFAULT_LOG_LEVELS;

        /// <summary>
        /// Represents the logger used for logging messages and events within the application.
        /// </summary>
        /// <remarks>This field is intended for internal use and should be initialized before it is injected.</remarks>
        private ILogger m_Log = null!;


        /// <summary>
        /// Represents the size of the AES encryption key.
        /// </summary>
        /// <remarks>The default key size is set to <see cref="AESKeySizeEnum.AES256"/>.</remarks>
        private AESKeySizeEnum m_KeySize = AESKeySizeEnum.AES256;

        /// <summary>
        /// Provides configuration options for JSON serialization.
        /// </summary>
        /// <remarks>This instance of <see cref="JsonSerializerOptions"/> is configured to allow trailing
        /// commas, handle numbers represented as strings, and format the output with indentation for
        /// readability.</remarks>
        private JsonSerializerOptions m_JsonSerializeOptions = new JsonSerializerOptions
        {
            AllowTrailingCommas = true,
            NumberHandling = JsonNumberHandling.AllowReadingFromString,
            WriteIndented = true
        };

        /// <summary>
        /// Provides configuration options for JSON deserialization.
        /// </summary>
        /// <remarks>This configuration allows for case-insensitive property name matching and uses camel
        /// case naming policy. It ignores null values during serialization and allows trailing commas in JSON input.
        /// Additionally, it permits numbers to be read from strings.</remarks>
        private JsonSerializerOptions m_JsonDeserializeOptions = new JsonSerializerOptions
        {
            PropertyNameCaseInsensitive = true,
            PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
            DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
            AllowTrailingCommas = true,
            NumberHandling = JsonNumberHandling.AllowReadingFromString
        };

        /// <summary>
        /// Initializes a new instance of the synchronous <see cref="Crypto"/> class with the specified private key and initialization vector (IV).
        /// </summary>
        /// <param name="privateKey">Typically 32 characters long (32 characters x 8 bits/character = 256 bits). 16 characters is 128 bit encryption, 24 characters is 192 bit encryption.</param>
        /// <param name="iv">Typically 16 characters for 128 bit block size.  If using other block sizes, adjust the iv length to match.</param>
        /// <param name="logger">A instance of the ILogger instance being used, or null if not used.</param>
        /// <param name="logLevels">Logging levels to use.  If not passed in, it defaults to "Error" and "Fatal".</param>
        /// <param name="cipherMode">CBC is the default, and the most commonly used.</param>
        public Crypto(String privateKey, String iv, ILogger logger = null!, LogLevelsBitset logLevels = Extensions.DEFAULT_LOG_LEVELS, CipherMode cipherMode = CipherMode.CBC)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            m_Log = logger;

            // What gets logged and what is skipped over is determined by this bitset variable.
            // It should be injected into this object.
            // If it is not injected, then the default value is used.
            m_LogLevels = logLevels;

            try
            {
                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    m_Log.LogTrace($"Begin Crypto constructor.");
                }

                if (String.IsNullOrWhiteSpace(privateKey))
                {
                    String msg = String.Format(CryptoResources.CTOR_UNHANDLED_MSG, "privateKey is null or empty or just whitespace.  The value is needed for encryption.");
                    ArgumentNullException exArgKey = new ArgumentNullException(msg);

                    throw exArgKey;
                }

                if (String.IsNullOrWhiteSpace(iv))
                {
                    iv = "";
                }
                else
                {
                    if (iv.Length < 16)
                    {
                        iv = "";
                    }
                }

                // Anchor the private key internally.
                m_PrivateKey = privateKey;

                // Make that value into a byte array.
                m_aryPrivateKey = Encoding.ASCII.GetBytes(privateKey);

                // Anchor the iv internally.
                m_IV = iv;

                // Make that value into a byte array.
                if (m_IV.Length > 0)
                {
                    m_aryIV = Encoding.ASCII.GetBytes(m_IV);
                }


                // Anchor the cipher mode internally.
                m_CipherMode = cipherMode;

            }  // END try
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key or iv
                exUnhandled.Data.AddCheck("cipherMode", cipherMode.ToString());
                exUnhandled.Data.AddCheck("privateKey.Length", privateKey.Length.ToString());
                exUnhandled.Data.AddCheck("iv.Length", iv.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto constructor error. [{strError}].");
                }

                throw;

            } // END catch
            finally
            {
                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto constructor Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                    m_Log.LogTrace(logMsg);
                }

            }  // END finally
        }

        /// <summary>
        /// Gets or sets the bitset representing the enabled log levels.
        /// This is useful for changing the logging levels during runtime.
        /// </summary>
        public LogLevelsBitset LogLevelsBitset
        {
            get
            {
                return m_LogLevels;
            }
            set
            {
                m_LogLevels = value;
            }
        }

        /// <summary>
        /// Gets or sets the initialization vector (IV) used for cryptographic operations.
        /// The value is dynamically generated if the IV passed in the constructor is not a valid IV string.
        /// </summary>
        public String IV
        {
            get
            {
                return m_IV;
            }
            set
            {
                m_IV = value;

                if (String.IsNullOrWhiteSpace(m_IV))
                {
                    m_IV = "";
                }
                else
                {
                    if (m_IV.Length < 16)
                    {
                        m_IV = "";
                    }
                }

                // Make that value into a byte array.
                if (m_IV.Length > 0)
                {
                    m_aryIV = Encoding.ASCII.GetBytes(m_IV);
                }
                else
                {
                    m_aryIV = default!;
                }

            }
        }

        /// <summary>
        /// Gets or sets the private key used for cryptographic operations.
        /// </summary>
        public String PrivateKey
        {
            get
            {
                return m_PrivateKey;
            }
            set
            {
                m_PrivateKey = value;

                if (String.IsNullOrWhiteSpace(m_PrivateKey))
                {
                    String msg = String.Format(CryptoResources.PRIVATE_KEY_INVALID_MSG, "PrivateKey is null or empty or just whitespace.  The value is needed for encryption, and should be the length specified in KeySize.");
                    ArgumentNullException exArgKey = new ArgumentNullException(msg);

                    throw exArgKey;
                }
                else
                {
                    // Make that value into a byte array.
                    m_aryPrivateKey = Encoding.ASCII.GetBytes(m_PrivateKey);
                }
            }
        }


        /// <summary>
        /// Gets the size of the private key in bytes.
        /// </summary>
        public AESKeySizeEnum KeySize
        {
            get
            {
                return m_KeySize;
            }
            set
            {
                m_KeySize = value;
            }
        }

        /// <summary>
        /// Gets or sets the mode of operation for the cipher algorithm.
        /// </summary>
        /// <remarks>The cipher mode determines how the algorithm processes blocks of data. Common modes
        /// include CBC (Cipher Block Chaining) and ECB (Electronic Codebook).</remarks>
        public CipherMode CipherMode
        {
            get
            {
                return m_CipherMode;
            }
            set
            {
                m_CipherMode = value;
            }
        }   

        /// <summary>
        /// Generates a random initialization vector (IV) for use in cryptographic operations.
        /// 
        /// Normally, the key and iv are stored as secrets, and used to encrypt and decrypt data.  
        /// However, if the key and iv are not intended to persist or be stored outside the application
        /// (e.g. just used during runtime then forgotten), then they can be generated and used
        /// with the GenerateRandomIV() and GenerateRandomPrivateKey() methods.
        /// </summary>
        /// <remarks>The method creates a new instance of the <see
        /// cref="System.Security.Cryptography.Aes"/> class, generates a random IV, and returns it as a Base64-encoded
        /// string. This IV can be used to ensure the security of encryption processes by introducing
        /// randomness.</remarks>
        /// <returns>A Base64-encoded string representing the generated random initialization vector (IV).</returns>
        public String GenerateRandomIV(Boolean changeInternal = false)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin Crypto GenerateRandomIV().");
            }

            String retVal = "";

            Aes objAES = null!;

            try
            {
                objAES = Aes.Create();

                objAES.KeySize = (Int32)m_KeySize;

                objAES.Mode = m_CipherMode;

                objAES.GenerateIV();

                retVal = Convert.ToBase64String(objAES.IV);

                if (changeInternal)
                {
                    m_IV = retVal;
                }
            }
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [GenerateRandomIV()] error. [{strError}].");
                }

                throw;
            }
            finally
            {
                if (objAES != null!)
                {
                    objAES.Clear();
                    objAES.Dispose();
                    objAES = null!;
                }

                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto [GenerateRandomIV()] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                    m_Log.LogTrace(logMsg);
                }

            }

            return retVal;
        }

        /// <summary>
        /// Generates a random private key using AES encryption.
        /// 
        /// Normally, the key and iv are stored as secrets, and used to encrypt and decrypt data.  
        /// However, if the key and iv are not intended to persist or be stored outside the application
        /// (e.g. just used during runtime then forgotten), then they can be generated and used
        /// with the GenerateRandomIV() and GenerateRandomPrivateKey() methods.
        /// 
        /// They default KeySize is 256 bytes (32 characters x 8 bits/character).
        /// </summary>
        /// <remarks>The method creates a new instance of the AES encryption algorithm, generates a random
        /// key,  and returns the key as a Base64-encoded string. This key can be used for cryptographic operations 
        /// requiring a symmetric key.</remarks>
        /// <returns>A Base64-encoded string representing the randomly generated private key.</returns>
        public String GenerateRandomPrivateKey(Boolean changeInternal = false)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin Crypto GenerateRandomPrivateKey().");
            }

            String retVal = "";

            Aes objAES = null!;

            try
            {
                objAES = Aes.Create();

                objAES.KeySize = (Int32)m_KeySize;

                objAES.Mode = m_CipherMode;

                objAES.GenerateKey();

                retVal = Convert.ToBase64String(objAES.Key);

                if (changeInternal)
                {
                    m_PrivateKey = retVal;
                }

            }
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [GenerateRandomPrivateKey()] error. [{strError}].");
                }

                throw;
            }
            finally
            {
                if (objAES != null!)
                {
                    objAES.Clear();
                    objAES.Dispose();
                    objAES = null!;
                }

                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto [GenerateRandomPrivateKey()] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                    m_Log.LogTrace(logMsg);
                }
            }

            return retVal;
        }

        /// <summary>
        /// Encrypts an object using AES encryption and returns the encrypted string.
        /// </summary>
        /// <remarks>The object is first serialized to JSON using <see
        /// cref="System.Text.Json.JsonSerializer"/>  with specific options, including support for trailing commas and
        /// indented formatting.  The resulting JSON string is then encrypted using AES.</remarks>
        /// <typeparam name="T">The type of the object to encrypt.</typeparam>
        /// <param name="objectToEncrypt">The object to encrypt. Cannot be <see langword="null"/>.</param>
        /// <returns>A string containing the AES-encrypted representation of the object.</returns>
        public String EncryptObjectAES<T>(T objectToEncrypt)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin Crypto [EncryptObjectAES<T>] method.");
            }

            if (objectToEncrypt == null)
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.ENCRYPT_EMPTY_MSG);
                throw exArg;
            }

            String retVal = "";                 // Encrypted string to return 

            try
            {

                String serializedObject = System.Text.Json.JsonSerializer.Serialize<T>(objectToEncrypt, m_JsonSerializeOptions);

                retVal = EncryptStringAES(serializedObject);

            }  // END try
            catch (NotSupportedException exNotSupported)
            {
                ArgumentException exArg = new ArgumentException(CryptoResources.ENCRYPT_NONSERIALIZABLE_OBJECT, exNotSupported);

                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exArg.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());
                exArg.Data.AddCheck("m_PrivateKey.Length", m_PrivateKey.Length.ToString());
                exArg.Data.AddCheck("m_IV.Length", m_IV.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exArg.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [EncryptObjectAES<T>] error. [{strError}].");
                }

                throw;
            }
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());
                exUnhandled.Data.AddCheck("m_PrivateKey.Length", m_PrivateKey.Length.ToString());
                exUnhandled.Data.AddCheck("m_IV.Length", m_IV.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [EncryptObjectAES<T>] error. [{strError}].");
                }

                throw;
            }
            finally
            {
                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto [EncryptObjectAES<T>] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                    m_Log.LogTrace(logMsg);
                }

            }

            return retVal;

        }

        /// <summary>
        /// Decrypts an AES-encrypted string and deserializes it into an object of the specified type.
        /// </summary>
        /// <remarks>The method uses <see cref="System.Text.Json.JsonSerializer"/> for deserialization,
        /// with options configured to: - Ignore case sensitivity in property names. - Use camel case naming for
        /// properties. - Ignore null values during serialization. - Allow trailing commas and handle numbers
        /// represented as strings. Ensure that the encrypted text was serialized using compatible settings before
        /// encryption.</remarks>
        /// <typeparam name="T">The type of the object to deserialize the decrypted string into.</typeparam>
        /// <param name="encryptedText">The AES-encrypted string to decrypt. Cannot be null, empty, or whitespace.</param>
        /// <returns>An object of type <typeparamref name="T"/> deserialized from the decrypted string.</returns>
        public T? DecryptObjectAES<T>(String encryptedText)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin Crypto [DecryptObjectAES<T>] method.");
            }

            if (String.IsNullOrWhiteSpace(encryptedText))
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.DECRYPT_EMPTY_MSG);
                throw exArg;
            }

            T? retVal = default!;

            try
            {

                String serializedObject = DecryptStringAES(encryptedText);

                retVal = JsonSerializer.Deserialize<T>(serializedObject, m_JsonDeserializeOptions);

            }  // END try
            catch (NotSupportedException exNotSupported)
            {
                ArgumentException exArg = new ArgumentException(CryptoResources.DECRYPT_NONSERIALIZABLE_OBJECT, exNotSupported);

                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exArg.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());
                exArg.Data.AddCheck("encryptedText", encryptedText ?? "");
                exArg.Data.AddCheck("m_PrivateKey.Length", m_PrivateKey.Length.ToString());
                exArg.Data.AddCheck("m_IV.Length", m_IV.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exArg.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [EncryptObjectAES<T>] error. [{strError}].");
                }

                throw exArg;
            }
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("encryptedText", encryptedText ?? "");
                exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());
                exUnhandled.Data.AddCheck("m_PrivateKey.Length", m_PrivateKey.Length.ToString());
                exUnhandled.Data.AddCheck("m_IV.Length", m_IV.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [DecryptObjectAES<T>] error. [{strError}].");
                }

                throw;
            }
            finally
            {
                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto [DecryptObjectAES<T>] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                    m_Log.LogTrace(logMsg);
                }

            }

            return retVal;
        }

        /// <summary> 
        /// Encrypt the given string using AES.  The string can be decrypted using  
        /// DecryptStringAES(). Block size is 128 (bits) for the IV value, which is 16 characters.
        /// </summary> 
        /// <param name="stringToEncrypt">The text to encrypt.</param> 
        public String EncryptStringAES(String stringToEncrypt)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace("Begin CryptoAsync [EncryptStringAESAsync] method.");
            }

            if (String.IsNullOrWhiteSpace(stringToEncrypt))
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.ENCRYPT_EMPTY_MSG);

                throw exArg;
            }

            String strReturn = "";                   // Encrypted string to return 
            Aes objAES = null!;                       // Aes object used to encrypt the data.
            MemoryStream memorySteam = null!;         // Memory stream used to hold the encrypted data.
            CryptoStream cryptoStream = null!;        // Crypto stream used to encrypt the data.

            try
            {
                objAES = Aes.Create();

                objAES.KeySize = (Int32)m_KeySize;

                objAES.Key = m_aryPrivateKey;

                if (m_IV.Length == 0)
                {
                    objAES.GenerateIV();
                    m_aryIV = objAES.IV;
                    m_IV = Convert.ToBase64String(m_aryIV);
                }
                else
                {
                    objAES.IV = m_aryIV;
                }

                objAES.Mode = m_CipherMode;

                ICryptoTransform objEncryption = objAES.CreateEncryptor(objAES.Key, objAES.IV);

                memorySteam = new MemoryStream();

                cryptoStream = new CryptoStream(memorySteam, objEncryption, CryptoStreamMode.Write);

                Byte[] bytesToEncrypt = Encoding.UTF8.GetBytes(stringToEncrypt);

                cryptoStream.Write(bytesToEncrypt, 0, bytesToEncrypt.Length);

                cryptoStream.FlushFinalBlock();

                Byte[] results = memorySteam.ToArray();

                memorySteam.Close();

                cryptoStream.Close();

                strReturn = Convert.ToBase64String(results);

            }  // END try
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());
                exUnhandled.Data.AddCheck("m_PrivateKey.Length", m_PrivateKey.Length.ToString());
                exUnhandled.Data.AddCheck("m_IV.Length", m_IV.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [EncryptStringAES] error. [{strError}].");
                }

                throw;
            }
            finally
            {

                // Dispose the IDisposable objects. 
                if (cryptoStream != null)
                {
                    cryptoStream.Close();
                    cryptoStream.Dispose();
                    cryptoStream = null!;
                }


                if (memorySteam != null)
                {
                    memorySteam.Close();
                    memorySteam.Dispose();
                    memorySteam = null!;
                }


                if (objAES != null)
                {
                    objAES.Clear();
                    objAES.Dispose();
                    objAES = null!;
                }

            }

            stopWatch.Stop();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                // This provides the log with method execution time.  Usually only needed for troubleshooting.
                TimeSpan elapsedTime = stopWatch.Elapsed;
                String logMsg = $"Crypto [EncryptStringAES" +
                    $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                m_Log.LogTrace(logMsg);
            }

            // Return the encrypted string. 
            return strReturn;
        }

        /// <summary> 
        /// Decrypt the given string.  Assumes the string was encrypted using  
        /// EncryptStringAES(). 
        /// </summary> 
        /// <param name="strEncryptedText">The text to decrypt.</param> 
        public String DecryptStringAES(String strEncryptedText)
        {

            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin Crypto [DecryptStringAES] method.");
            }

            if (String.IsNullOrWhiteSpace(strEncryptedText))
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.DECRYPT_EMPTY_MSG);

                throw exArg;
            }

            String strReturn = null!;                 // Encrypted string to return 
            Aes objAES = null!;                       // Aes object used to encrypt the data.
            MemoryStream memorySteam = null!;         // Memory stream used to hold the encrypted data.
            CryptoStream cryptoStream = null!;        // Crypto stream used to encrypt the data.
            StreamReader streamReader = null!;        // Stream reader used to read the encrypted data.

            try
            {
                objAES = Aes.Create();

                objAES.KeySize = (Int32)m_KeySize;

                objAES.Key = m_aryPrivateKey;

                if (m_IV.Length == 0)
                {
                    objAES.GenerateIV();
                    m_aryIV = objAES.IV;
                    m_IV = Convert.ToBase64String(m_aryIV);
                }
                else
                {
                    objAES.IV = m_aryIV;
                }

                objAES.Mode = m_CipherMode;

                ICryptoTransform objDecryption = objAES.CreateDecryptor(objAES.Key, objAES.IV);

                Byte[] bytesToDecrypt = Convert.FromBase64String(strEncryptedText);

                memorySteam = new MemoryStream(bytesToDecrypt);
                cryptoStream = new CryptoStream(memorySteam, objDecryption, CryptoStreamMode.Read);

                streamReader = new StreamReader(cryptoStream);
                strReturn = streamReader.ReadToEnd();

            }  // END try
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());
                exUnhandled.Data.AddCheck("strEncryptedText", strEncryptedText ?? "");
                exUnhandled.Data.AddCheck("m_PrivateKey.Length", m_PrivateKey.Length.ToString());
                exUnhandled.Data.AddCheck("m_IV.Length", m_IV.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [DecryptStringAES] error. [{strError}].");
                }

                throw;

            } // END catch
            finally
            {

                // Dispose the IDisposable objects. 
                if (streamReader != null)
                {
                    streamReader.Close();
                    streamReader.Dispose();
                    streamReader = null!;
                }

                if (cryptoStream != null)
                {
                    cryptoStream.Close();
                    cryptoStream.Dispose();
                    cryptoStream = null!;
                }


                if (memorySteam != null)
                {
                    memorySteam.Close();
                    memorySteam.Dispose();
                    memorySteam = null!;
                }


                if (objAES != null)
                {
                    objAES.Clear();
                    objAES.Dispose();
                    objAES = null!;
                }

                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto [DecryptStringAES" +
                        $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

                    m_Log.LogTrace(logMsg);
                }
            }

            return strReturn;

        }  // END public String DecryptStringAES(String encryptedText)

        /// <summary>
        /// Computes the SHA-512 hash of the specified object.
        /// </summary>
        /// <remarks>The method serializes the provided object using JSON serialization before computing
        /// the hash. Ensure that the object is serializable and does not contain circular references.</remarks>
        /// <typeparam name="T">The type of the object to hash.</typeparam>
        /// <param name="objectToHash">The object to compute the hash for. Cannot be <see langword="null"/>.</param>
        /// <param name="useRandomSalt">Salt (a random string) added to unencrypted serialized object to improve security.</param>
        /// <returns>A string representation of the SHA-512 hash of the serialized object, and a string for the salt..</returns>
        public HashResponse GetObjectSHA512Hash<T>(T objectToHash, Boolean useRandomSalt = true)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin CryptoAsync [GetObjectSHA512HashAsync<T>] method.");
            }

            if (objectToHash == null)
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.HASH_UNHANDLED_MSG);
                throw exArg;
            }

            HashResponse retVal = null!; 

            try
            {
                String serializedObject = System.Text.Json.JsonSerializer.Serialize<T>(objectToHash, m_JsonSerializeOptions);

                retVal = GetSHA512Hash(serializedObject, useRandomSalt);

            }  // END try
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());
                exUnhandled.Data.AddCheck("m_PrivateKey.Length", m_PrivateKey.Length.ToString());
                exUnhandled.Data.AddCheck("m_IV.Length", m_IV.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [GetObjectSHA512Hash<T>] error. [{strError}].");
                }

                throw;
            }
            finally
            {
                stopWatch.Stop();

                retVal.ExecutionTime = stopWatch.Elapsed.TotalMicroseconds;

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto [GetObjectSHA512Hash<T>" +
                        $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

                    m_Log.LogTrace(logMsg);
                }

            }

            return retVal;

        }  // END public HashResponse GetObjectSHA512Hash<T>(T objectToHash, Boolean useRandomSalt = true)

        /// <summary>
        /// This function takes a value you want hashed and hashes it uses SHA-512 for strength.  
        /// </summary>
        /// <param name="stringToHash">This is the value, such as a password.  It will usually be the same over a number of instances on multiple machines.</param>
        /// <param name="useRandomSalt">True gives better security with a random salt before hashing (non-deterministic). False hashes without using a salt are deterministic and less secure.</param>
        /// <returns>The value returned is the hash string in Base 64</returns>
        public HashResponse GetSHA512Hash(String stringToHash, Boolean useRandomSalt = true)
        {

            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin CryptoAsync [GetSHA512Hash] method.");
            }

            HashResponse retVal = null!;

            SHA512 hasher = null!;

            Byte[] saltBytes = default!;

            String hash = "";
            String salt = "";

            try
            {

                if (String.IsNullOrWhiteSpace(stringToHash))
                {
                    ArgumentNullException exArg = new ArgumentNullException(CryptoResources.HASH_EMPTY_MSG);
                    throw exArg;
                }

                if (useRandomSalt)
                {
                    saltBytes = RandomNumberGenerator.GetBytes(16);
                    salt = Convert.ToBase64String(saltBytes);
                    stringToHash = stringToHash + salt;
                }

                Byte[] aryStringToHash = Encoding.UTF8.GetBytes(stringToHash);

                hasher = SHA512.Create();

                Byte[] aryHash = hasher.ComputeHash(aryStringToHash);

                hash = Convert.ToBase64String(aryHash);

                retVal = new HashResponse(hash, salt);

            }
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());
                exUnhandled.Data.AddCheck("m_PrivateKey.Length", m_PrivateKey.Length.ToString());
                exUnhandled.Data.AddCheck("m_IV.Length", m_IV.Length.ToString());
                exUnhandled.Data.AddCheck("useRandomSalt", useRandomSalt.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [GetSHA512Hash] error. [{strError}].");
                }
                throw;

            } // END catch
            finally
            {
                if (hasher != null)
                {
                    hasher.Clear();

                    hasher.Initialize();

                    hasher.Dispose();

                    hasher = null!;
                }

                stopWatch.Stop();

                retVal.ExecutionTime = stopWatch.Elapsed.TotalMicroseconds;

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto [GetSHA512Hash" +
                        $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

                    m_Log.LogTrace(logMsg);
                }

            }

            return retVal;

        }  // END public HashResponse GetSHA512Hash(String stringToHash, Boolean useRandomSalt = true)

        /// <summary>
        /// Verifies whether the specified text, when hashed with the provided salt, matches the given SHA-512 hash
        /// value.
        /// </summary>
        /// <remarks>This method uses the SHA-512 hashing algorithm to compute the hash of the
        /// concatenated plain text and salt.  Ensure that the provided hash value and salt are consistent with the
        /// original hashing process to achieve accurate verification.</remarks>
        /// <param name="textToCheck">The plain text input to verify against the hash.</param>
        /// <param name="hashValue">The expected SHA-512 hash value, encoded as a Base64 string.</param>
        /// <param name="salt">The salt to append to the plain text before hashing.</param>
        /// <returns><see langword="true"/> if the computed hash of the salted text matches the provided hash value; otherwise,
        /// <see langword="false"/>.</returns>
        public Boolean VerifySHA512Hash(String textToCheck, String hashValue, String salt)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin CryptoAsync [VerifySHA512Hash] method.");
            }

            Boolean retVal = false;

            SHA512 hasher = null!;


            try
            {
                String saltedInput = textToCheck + salt;

                hasher = SHA512.Create();

                Byte[] aryStringToHash = Encoding.UTF8.GetBytes(saltedInput);

                Byte[] aryHash = hasher.ComputeHash(aryStringToHash);

                String thisHash = Convert.ToBase64String(aryHash);

                if (thisHash.Equals(hashValue, StringComparison.Ordinal))
                {
                    retVal = true;
                }

            }
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("textToCheck.Length", textToCheck.Length.ToString());
                exUnhandled.Data.AddCheck("hashValue.Length", hashValue.Length.ToString());
                exUnhandled.Data.AddCheck("salt.Length", salt.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [VerifySHA512Hash] error. [{strError}].");
                }
                throw;

            } // END catch
            finally
            {
                if (hasher != null)
                {
                    hasher.Clear();

                    hasher.Initialize();

                    hasher.Dispose();

                    hasher = null!;
                }

                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto [VerifySHA512Hash" +
                        $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

                    m_Log.LogTrace(logMsg);
                }

            }

            return retVal;
        }  // END public Boolean VerifySHA512Hash(String textToCheck, String hashValue, String salt)

        /// <summary>
        /// Verifies whether the SHA-512 hash of a serialized object, combined with a specified salt, matches a given
        /// hash value.
        /// </summary>
        /// <remarks>This method serializes the provided object to JSON, appends the specified salt, and
        /// computes the SHA-512 hash of the resulting string. The computed hash is then compared to the provided
        /// <paramref name="hashValue"/> using an ordinal string comparison.</remarks>
        /// <typeparam name="T">The type of the object to be hashed.</typeparam>
        /// <param name="objectToCheck">The object to serialize and hash.</param>
        /// <param name="hashValue">The expected SHA-512 hash value, encoded as a Base64 string.</param>
        /// <param name="salt">The salt to append to the serialized object before hashing.</param>
        /// <returns><see langword="true"/> if the computed hash matches the provided <paramref name="hashValue"/>; otherwise,
        /// <see langword="false"/>.</returns>
        public Boolean VerifyObjectSHA512Hash<T>(T objectToCheck, String hashValue, String salt)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin CryptoAsync [VerifyObjectSHA512Hash<T>] method.");
            }

            Boolean retVal = false;

            try
            {
                String serializedObject = JsonSerializer.Serialize<T>(objectToCheck, m_JsonSerializeOptions);

                retVal = VerifySHA512Hash(serializedObject, hashValue, salt);
            }
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.AddCheck("hashValue.Length", hashValue.Length.ToString());
                exUnhandled.Data.AddCheck("salt.Length", salt.Length.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"Crypto [VerifyObjectSHA512Hash<T>] error. [{strError}].");
                }
                throw;

            } // END catch
            finally
            {

                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"Crypto [VerifyObjectSHA512Hash<T>" +
                        $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

                    m_Log.LogTrace(logMsg);
                }

            }

            return retVal;
        }

        #region IDisposable Implementation

        /// <summary>
        /// Implement the IDisposable.Dispose() method
        /// Developers are supposed to call this method when done with this Object.
        /// There is no guarantee when or if the GC will call it, so 
        /// the developer is responsible to.  GC does NOT clean up unmanaged 
        /// resources, such as COM objects, so we have to clean those up, too.
        /// The GC does not dispose your objects, as it has no knowledge of IDisposable.Dispose() or 
        /// IAsyncDisposable.DisposeAsync(). The GC only knows whether an object is finalizable (that is, 
        /// it defines an Object.Finalize() method), and when the object's finalizer needs to be called. 
        /// For more information, see How finalization works.
        /// 
        /// If you don't call Dispose(), the GC sends it to the Finalization queue, and ultimately again 
        /// to the f-reachable queue. Finalization makes an object survive 2 collections, which means it 
        /// will be promoted to Gen1 if it was in Gen0, and to Gen2 if it was in Gen1.
        /// 
        /// </summary>
        public void Dispose()
        {
            try
            {
                // Check if Dispose has already been called 
                // Only allow the consumer to call it once with effect.
                if (!m_blnDisposeHasBeenCalled)
                {
                    // Call the overridden Dispose method that contains common cleanup code
                    // Pass true to indicate that it is called from Dispose
                    Dispose(true);

                    // Prevent subsequent finalization of this Object. This is not needed 
                    // because managed and unmanaged resources have been explicitly released
                    GC.SuppressFinalize(this);
                }
            }

            catch (Exception exUnhandled)
            {
                exUnhandled.Data.Add("m_blnDisposeHasBeenCalled", m_blnDisposeHasBeenCalled.ToString());

                throw;
            }
        }

        /// <summary>
        /// Explicit Finalize method.  The GC calls Finalize, if it is called.
        /// There are times when the GC will fail to call Finalize, which is why it is up to 
        /// the developer to call Dispose() from the consumer Object.
        /// </summary>
        ~Crypto()
        {
            // Call Dispose indicating that this is not coming from the public
            // dispose method.
            Dispose(false);
        }

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">the disposing parameter is a Boolean that indicates whether the method call comes from a Dispose method (its value is true) or from a finalizer (its value is false)</param>
        protected virtual void Dispose(bool disposing)
        {

            try
            {

                if (!m_blnDisposeHasBeenCalled)
                {

                    if (disposing)
                    {
                        // Need to unregister/detach yourself from the events your code in this class created. 
                        // Always make sure the object is not null first before trying to unregister/detach them!
                        // Failure to unregister can be a BIG source of memory leaks
                        //if (someDisposableObjectWithAnEventHandler != null)
                        //{                 
                        //	m_objWithAnEventHandler.SomeEvent -= someDelegate;
                        //	m_objWithAnEventHandler.Dispose();
                        //	m_objWithAnEventHandler = null;
                        //}


                        // Here we dispose and clean up the unmanaged objects and managed Object we created in code
                        // that are not in the IContainer child Object of this object.
                        // Unmanaged objects do not have a Dispose() method, so we just set them to null
                        // to release the reference.  For managed objects, we call their respective Dispose()
                        // methods and then release the reference.
                        // DEVELOPER NOTE:
                        //if (m_obj != null)
                        //    {
                        //    // This explicitly tells the GC that you are done with it and there are no more rooted references to it.
                        //    m_obj.Dispose();
                        //    m_obj = null;
                        //    }
                    }

                    //m_obj2 = null;  // Object does not implement IDispose or have a .Clear() method

                    // Objects passed in to the instance (e.g. Dependency Injection) should be set to null
                    // as this removes the reference, but leaves the original object outside this instance 
                    // untouched.
                    //m_Log = null;
                }

            }

            catch (Exception exUnhandled)
            {
                exUnhandled.Data.Add("m_blnDisposeHasBeenCalled", m_blnDisposeHasBeenCalled.ToString());
                exUnhandled.Data.Add("disposing", disposing.ToString());

                throw;

            }
            finally
            {
                // Set the flag that Dispose has been called and executed.
                m_blnDisposeHasBeenCalled = true;
            }

        }

        #endregion IDisposable Implementation

    }
}

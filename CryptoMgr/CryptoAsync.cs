using Jeff.Jones.CryptoMgr.Properties;
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
    /// Provides asynchronous cryptographic operations, including AES encryption/decryption,  SHA-512 hashing, and
    /// object serialization/deserialization.
    /// </summary>
    /// <remarks>This class supports both synchronous and asynchronous disposal patterns to ensure proper 
    /// cleanup of resources. It is designed to handle cryptographic operations securely, using  AES encryption with a
    /// specified private key and initialization vector (IV). 
    /// 
    /// The IV is a critical component of AES encryption in modes like CBC (Cipher Block Chaining) because it ensures 
    /// that the same plaintext encrypted multiple times will produce different ciphertexts, enhancing security.
    /// 
    /// The class also provides methods for hashing and
    /// serialization/deserialization of objects. <para> Typical usage involves creating an instance of <see
    /// cref="CryptoAsync"/> with a private  key and IV, then calling methods such as <see
    /// cref="EncryptObjectAESAsync{T}"/> or  <see cref="DecryptObjectAESAsync{T}"/> for encryption and decryption
    /// operations. </para></remarks>
    public class CryptoAsync : IDisposable, IAsyncDisposable
    {
        /// <summary>
        /// Represents the initialization vector (IV) used in encryption and decryption operations.Initialization vector (IV); 
        /// this can differ between encryption/decryption calls using the same private key.
        /// </summary>
        /// <remarks>The initialization vector (IV) is a random or unique value that ensures the same
        /// plaintext encrypted with the same key produces different ciphertexts.  This value can vary between 
        /// encryption and decryption calls using the same private key. When an IV is used only once, it is referred to
        /// as a "nonce" (number used once).</remarks>
        // When an IV is used only once, it is also called a "nonce" (number used once).
        private String m_IV = "";

        /// <summary>
        /// Represents the private key used for decrypting encrypted strings.They key is kept private, and is necessary to decrypt the encrypted string.
        /// </summary>
        /// <remarks>This field is intended for internal use only and should not be exposed or modified
        /// directly. The private key is required for decryption operations and must remain secure.</remarks>
        private readonly String m_PrivateKey = "";

        /// <summary>
        /// Represents the initialization vector (IV) used in cryptographic operations.This holds the byte array of m_IV.
        /// </summary>
        /// <remarks>The initialization vector is a byte array that ensures the uniqueness of encryption
        /// results for identical plaintext inputs. It is typically required for certain encryption modes, such as
        /// CBC.</remarks>
        private Byte[] m_aryIV;

        /// <summary>
        /// Represents the private key as a byte array.This holds the byte array of m_PrivateKey.
        /// </summary>
        /// <remarks>This field is read-only and intended for internal use to store the private key data.
        /// It should not be exposed or modified directly.</remarks>
        private readonly Byte[] m_aryPrivateKey;

        /// <summary>
        /// Represents the cipher mode used for cryptographic operations.
        /// </summary>
        /// <remarks>The cipher mode determines how encryption and decryption are performed on blocks of
        /// data. This field is set to <see cref="CipherMode.CBC"/>, which stands for Cipher Block Chaining. CBC mode
        /// requires an initialization vector (IV) and ensures that identical plaintext blocks produce different
        /// ciphertext blocks, enhancing security.</remarks>
        private readonly CipherMode m_CipherMode = CipherMode.CBC;

        /// <summary>
        /// Indicates whether the object's <see cref="CryptoAsync.Dispose()"/> method has been called.
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
        /// Represents the configuration settings for the application.
        /// </summary>
        /// <remarks>This field is initialized during application startup and provides access to
        /// configuration values. It should not be null during normal operation.</remarks>
        private IConfiguration m_Config = null!;

        /// <summary>
        /// Initializes a new instance of the asynchronous <see cref="CryptoAsync"/> class with the specified private key and initialization vector (IV).
        /// </summary>
        /// <param name="privateKey">Typically 32 characters long (32 characters x 8 bits/character = 256 bits). 16 characters is 128 bit encryption, 24 characters is 192 bit encryption.</param>
        /// <param name="iv">Typically 16 characters for 128 bit block size.  If using other block sizes, adjust the iv length to match.</param>
        /// <param name="logger">A instance of the ILogger instance being used, or null if not used.</param>
        /// <param name="config">An instance of the calling code's IConfiguration, or null if not used.</param>
        /// <param name="cipherMode">CBC is the default, and the most commonly used.</param>
        public CryptoAsync(String privateKey, String iv, ILogger logger = null!, IConfiguration config = null!, CipherMode cipherMode = CipherMode.CBC)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            m_Log = logger;

            m_Config = config;

            if (m_Config != null)
            {
                // What gets logged and what is skipped over is determined by this bitset variable.
                // It should exist in the IConfiguration object injected into this object.
                // If it does not exist in the IConfiguration object, or that object does not exist, then the default value is used.
                String logLevels = m_Config["Logging:LogLevels"] ?? Extensions.DEFAULT_LOG_LEVELS_STRING;
                m_LogLevels = Enum.Parse<LogLevelsBitset>(logLevels);
            }

            try
            {
                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    m_Log.LogTrace($"Begin CryptoAsync constructor.");
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
                m_aryIV = Encoding.ASCII.GetBytes(iv);

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

                    m_Log.LogError($"CryptoAsync constructor error. [{strError}].");
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
                    String logMsg = $"CryptoAsync constructor Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                    m_Log.LogTrace(logMsg);
                }

            }  // END finally
        }

        /// <summary>
        /// Gets the initialization vector (IV) used for cryptographic operations.
        /// The value is dynamically generated if the IV passed in is not a valid IV string.
        /// </summary>
        public String IV
        {
            get
            {
                return m_IV;
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
        public async Task<String> GenerateRandomIVAsync()
        {
            String retVal = await Task.Run(() =>
            {
                Stopwatch stopWatch = Stopwatch.StartNew();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    m_Log.LogTrace($"Begin CryptoAsync GenerateRandomIVAsync().");
                }

                Aes objAES = null!;

                try
                {
                    objAES = Aes.Create();
                    objAES.Mode = m_CipherMode;
                    objAES.GenerateIV();
                    return Convert.ToBase64String(objAES.IV);

                }
                catch (Exception exUnhandled)
                {
                    // Add some additional information to the exception's Data dictionary.
                    // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                    exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());

                    if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                    {
                        String strError = exUnhandled.GetFullExceptionMessage(true, true);

                        m_Log.LogError($"CryptoAsync [GenerateRandomIVAsync()] error. [{strError}].");
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
                        String logMsg = $"CryptoAsync [GenerateRandomIVAsync()] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                        m_Log.LogTrace(logMsg);
                    }

                }
            });

            return retVal;
        }

        /// <summary>
        /// Generates a random private key using AES encryption.
        /// 
        /// Normally, the key and iv are stored as secrets, and used to encrypt and decrypt data.  
        /// However, if the key and iv are not intended to persist or be stored outside the application
        /// (e.g. just used during runtime then forgotten), then they can be generated and used
        /// with the GenerateRandomIV() and GenerateRandomPrivateKey() methods.
        /// </summary>
        /// <remarks>The method creates a new instance of the AES encryption algorithm, generates a random
        /// key,  and returns the key as a Base64-encoded string. This key can be used for cryptographic operations 
        /// requiring a symmetric key.</remarks>
        /// <returns>A Base64-encoded string representing the randomly generated private key.</returns>
        public async Task<String> GenerateRandomPrivateKeyAsync()
        {
            String retVal = await Task.Run(() =>
            {

                Stopwatch stopWatch = Stopwatch.StartNew();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    m_Log.LogTrace($"Begin CryptoAsync GenerateRandomPrivateKeyAsync().");
                }

                Aes objAES = null!;

                try
                {
                    objAES = Aes.Create();
                    objAES.Mode = m_CipherMode;
                    objAES.GenerateKey();
                    return Convert.ToBase64String(objAES.Key);
                }
                catch (Exception exUnhandled)
                {
                    // Add some additional information to the exception's Data dictionary.
                    // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                    exUnhandled.Data.AddCheck("m_CipherMode", m_CipherMode.ToString());

                    if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                    {
                        String strError = exUnhandled.GetFullExceptionMessage(true, true);

                        m_Log.LogError($"CryptoAsync [GenerateRandomIVAsync()] error. [{strError}].");
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
                        String logMsg = $"CryptoAsync [GenerateRandomIVAsync()] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                        m_Log.LogTrace(logMsg);
                    }
                }

            });

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
        public async Task<String> EncryptObjectAESAsync<T>(T objectToEncrypt)
        {

            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin CryptoAsync [EncryptObjectAESAsync<T>] method.");
            }

            if (objectToEncrypt == null)
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.ENCRYPT_EMPTY_MSG);
                throw exArg;
            }

            MemoryStream stream = default!;
            StreamReader reader = default!;

            String retVal = "";                 // Encrypted string to return 

            try
            {
                JsonSerializerOptions jsonOptions = new JsonSerializerOptions
                {
                    AllowTrailingCommas = true,
                    NumberHandling = JsonNumberHandling.AllowReadingFromString,
                    WriteIndented = true
                };

                stream = new MemoryStream();

                await JsonSerializer.SerializeAsync<T>(stream, objectToEncrypt, jsonOptions);

                stream.Position = 0;

                reader = new StreamReader(stream);

                String serializedObject = await reader.ReadToEndAsync();

                retVal = await EncryptStringAESAsync(serializedObject);

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

                    m_Log.LogError($"CryptoAsync [EncryptObjectAESAsync<T>] error. [{strError}].");
                }

                throw;


                throw exArg;
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

                    m_Log.LogError($"CryptoAsync [EncryptObjectAESAsync<T>] error. [{strError}].");
                }

                throw;
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                    reader.Dispose();
                    reader = null!;
                }

                if (stream != null)
                {
                    stream.Close();
                    stream.Dispose();
                    stream = null!;
                }

                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"CryptoAsync [EncryptObjectAESAsync<T>] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
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
        /// <typeparam name="T?">The type of the object to deserialize the decrypted string into.</typeparam>
        /// <param name="encryptedText">The AES-encrypted string to decrypt. Cannot be null, empty, or whitespace.</param>
        /// <returns>An object of type <typeparamref name="T"/> deserialized from the decrypted string.</returns>
        public async Task<T?> DecryptObjectAESAsync<T>(String encryptedText)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin CryptoAsync [DecryptObjectAESAsync<T>] method.");
            }

            if (String.IsNullOrWhiteSpace(encryptedText))
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.DECRYPT_EMPTY_MSG);
                throw exArg;
            }

            T? retVal = default!;

            MemoryStream stream = default!;

            try
            {

                JsonSerializerOptions jsonOptions = new JsonSerializerOptions
                {
                    PropertyNameCaseInsensitive = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                    DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
                    AllowTrailingCommas = true,
                    NumberHandling = JsonNumberHandling.AllowReadingFromString
                };

                String decryptedString = await DecryptStringAESAsync(encryptedText);

                stream = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(decryptedString));

                retVal = await JsonSerializer.DeserializeAsync<T>(stream, jsonOptions);

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

                    m_Log.LogError($"CryptoAsync [EncryptObjectAESAsync<T>] error. [{strError}].");
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

                    m_Log.LogError($"CryptoAsync [DecryptObjectAESAsync<T>] error. [{strError}].");
                }

                throw;
            }
            finally
            {

                if (stream != null)
                {
                    stream.Close();
                    stream.Dispose();
                    stream = null!;
                }

                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"CryptoAsync [DecryptObjectAESAsync<T>] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                    m_Log.LogTrace(logMsg);
                }

            }

            return retVal;
        }  // END public async Task<T?> DecryptObjectAESAsync<T>(String encryptedText)

        /// <summary> 
        /// Encrypt the given string using AES.  The string can be decrypted using  
        /// DecryptStringAESAsync(). Block size is 128 (bits) for the IV value, which is 16 characters.
        /// </summary> 
        /// <param name="stringToEncrypt">The text to encrypt.</param> 
        public async Task<String> EncryptStringAESAsync(String stringToEncrypt)
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

            String retVal = "";                       // Encrypted string to return 
            Aes objAES = null!;                       // Aes object used to encrypt the data.
            MemoryStream memorySteam = null!;         // Memory stream used to hold the encrypted data.
            CryptoStream cryptoStream = null!;        // Crypto stream used to encrypt the data.

            try
            {
                objAES = Aes.Create();
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

                await cryptoStream.WriteAsync(bytesToEncrypt, 0, bytesToEncrypt.Length);

                await cryptoStream.FlushFinalBlockAsync();

                Byte[] results = memorySteam.ToArray();

                memorySteam.Close();

                cryptoStream.Close();

                retVal = Convert.ToBase64String(results);

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

                    m_Log.LogError($"CryptoAsync [EncryptStringAESAsync] error. [{strError}].");
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

                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"CryptoAsync [EncryptStringAESAsync" +
                        $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                    m_Log.LogTrace(logMsg);
                }

            }

            // Return the encrypted string. 
            return retVal;
        }  // END  public async Task<String> EncryptStringAESAsync(String strStringToEncrypt)

        /// <summary> 
        /// Decrypt the given string.  Assumes the string was encrypted using  
        /// EncryptStringAES(). 
        /// </summary> 
        /// <param name="strEncryptedText">The text to decrypt.</param> 
        public async Task<String> DecryptStringAESAsync(String strEncryptedText)
        {

            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin CryptoAsync [DecryptStringAESAsync] method.");
            }

            if (String.IsNullOrWhiteSpace(strEncryptedText))
            {

                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.DECRYPT_EMPTY_MSG);

                throw exArg;
            }

            String retVal = null!;                    // Encrypted string to return 
            Aes objAES = null!;                       // Aes object used to encrypt the data.
            MemoryStream memorySteam = null!;         // Memory stream used to hold the encrypted data.
            CryptoStream cryptoStream = null!;        // Crypto stream used to encrypt the data.
            StreamReader streamReader = null!;        // Stream reader used to read the encrypted data.

            try
            {
                objAES = Aes.Create();
                objAES.Key = m_aryPrivateKey;
                objAES.IV = m_aryIV;
                objAES.Mode = m_CipherMode;

                ICryptoTransform objDecryption = objAES.CreateDecryptor(objAES.Key, objAES.IV);

                Byte[] bytesToDecrypt = Convert.FromBase64String(strEncryptedText);

                memorySteam = new MemoryStream(bytesToDecrypt);
                cryptoStream = new CryptoStream(memorySteam, objDecryption, CryptoStreamMode.Read);

                streamReader = new StreamReader(cryptoStream);
                retVal = await streamReader.ReadToEndAsync();

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

                    m_Log.LogError($"CryptoAsync [DecryptStringAESAsync] error. [{strError}].");
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
                    String logMsg = $"CryptoAsync [DecryptStringAESAsync" +
                        $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

                    m_Log.LogTrace(logMsg);
                }
            }

            return retVal;

        }  // END public async Task<String> DecryptStringAESAsync(String strEncryptedText)

        /// <summary>
        /// Computes the SHA-512 hash of the specified object after serializing it to JSON.
        /// </summary>
        /// <remarks>The method serializes the provided object to a JSON string using <see
        /// cref="System.Text.Json.JsonSerializer"/>,  then computes the SHA-512 hash of the serialized string. The JSON
        /// serialization options include support for  trailing commas, number handling, and indented
        /// formatting.</remarks>
        /// <typeparam name="T">The type of the object to hash.</typeparam>
        /// <param name="objectToHash">The object to compute the hash for. Cannot be <see langword="null"/>.</param>
        /// <returns>A string representing the SHA-512 hash of the serialized JSON representation of the object.</returns>
        public async Task<String> GetObjectSHA512HashAsync<T>(T objectToHash)
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

            String retVal = "";                 // Hashed string to return 

            MemoryStream stream = default!;
            StreamReader reader = default!;

            try
            {
                JsonSerializerOptions jsonOptions = new JsonSerializerOptions
                {
                    AllowTrailingCommas = true,
                    NumberHandling = JsonNumberHandling.AllowReadingFromString,
                    WriteIndented = true
                };

                stream = new MemoryStream();

                await System.Text.Json.JsonSerializer.SerializeAsync<T>(stream, objectToHash, jsonOptions);

                stream.Position = 0;

                reader = new StreamReader(stream);

                String serializedObject = await reader.ReadToEndAsync();

                retVal = await GetSHA512HashAsync(serializedObject);

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

                    m_Log.LogError($"CryptoAsync [GetObjectSHA512HashAsync<T>] error. [{strError}].");
                }

                throw;
            }
            finally
            {
                if (reader != null)
                {
                    reader.Close();
                    reader.Dispose();
                    reader = null!;
                }

                if (stream != null)
                {
                    stream.Close();
                    stream.Dispose();
                    stream = null!;
                }

                stopWatch.Stop();

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    // This provides the log with method execution time.  Usually only needed for troubleshooting.
                    TimeSpan elapsedTime = stopWatch.Elapsed;
                    String logMsg = $"CryptoAsync [GetObjectSHA512HashAsync<T>" +
                        $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

                    m_Log.LogTrace(logMsg);
                }
            }

            return retVal;

        }  // END  public async Task<String> GetObjectSHA512HashAsync<T>(T objectToHash)

        /// <summary>
        /// This function takes a value you want hashed and hashes it using SHA-512 for strength.  
        /// </summary>
        /// <param name="stringToHash">This is the value, such as a password.  It will usually be the same over a number of instances on multiple machines.</param>
        /// <returns>The value returned is the hash string in Base 64</returns>
        public async Task<String> GetSHA512HashAsync(String stringToHash)
        {

            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin CryptoAsync [GetSHA512HashAsync] method.");
            }

            String retVal = "";

            SHA512 hasher = null!;

            MemoryStream stream = default!;

            try
            {
                Byte[] aryStringToHash = Encoding.UTF8.GetBytes(stringToHash);

                hasher = SHA512.Create();

                stream = new MemoryStream(aryStringToHash);

                Byte[] aryHash = await hasher.ComputeHashAsync(stream);

                retVal = BitConverter.ToString(aryHash).Replace("-", "").ToLowerInvariant();

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

                    m_Log.LogError($"CryptoAsync [GetSHA512HashAsync] error. [{strError}].");
                }

                throw;

            } // END catch
            finally
            {
                if (stream != null)
                {
                    stream.Close();
                    stream.Dispose();
                    stream = null!;
                }

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
                    String logMsg = $"CryptoAsync [GetSHA512HashAsync" +
                        $"] Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

                    m_Log.LogTrace(logMsg);
                }
            }

            return retVal;

        }


        #region IDisposable, IDisposableAsync Implementation

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
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
                exUnhandled.Data.Add("m_blnDisposeHasBeenCalled", m_blnDisposeHasBeenCalled.ToString());

                throw;
            }
        }

        /// <summary>
        /// Explicit Finalize method.  The GC calls Finalize, if it is called.
        /// There are times when the GC will fail to call Finalize, which is why it is up to 
        /// the developer to call Dispose() from the consumer Object.
        /// </summary>
        ~CryptoAsync()
        {
            // Call Dispose indicating that this is not coming from the public
            // dispose method.
            Dispose(false);
        }

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">the disposing parameter is a Boolean that indicates whether the method call comes from a Dispose method (its value is true) or from a finalizer (its value is false)</param>
        protected virtual void Dispose(Boolean disposing)
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
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing the private key, iv, or unencrypted sensitive data.
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

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        public async ValueTask DisposeAsync()
        {
            await DisposeAsyncCore().ConfigureAwait(false);

            Dispose(false);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// 
        /// </summary>
        /// <returns></returns>
        protected virtual async ValueTask DisposeAsyncCore()
        {
            // Make async cleanup call here e.g. await Database.CleanupAsync();
        }

        #endregion IDisposable, IDisposableAsync Implementation

    }
}

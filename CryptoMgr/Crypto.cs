﻿using Jeff.Jones.CryptoMgr.Properties;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Jeff.Jones.CryptoMgr
{
    /// <summary>
    /// Provides methods for encrypting and decrypting data using AES encryption, as well as hashing data using SHA-512.
    /// </summary>
    /// <remarks>The <see cref="Crypto"/> class is designed to facilitate secure data handling by providing
    /// AES encryption and decryption methods,  along with SHA-512 hashing functionality. It supports customizable
    /// initialization vectors (IVs) and private keys for encryption. The class also implements <see
    /// cref="IDisposable"/> to ensure proper cleanup of resources.</remarks>
    public class Crypto
    {
        // Initialization vector (IV); this can differ between encryption/decryption calls using the same private key.
        // When an IV is used only once, it is also called a "nonce" (number used once).
        private readonly String m_IV = "";

        private readonly String m_PrivateKey = "";

        private readonly Byte[] m_aryIV;

        private readonly Byte[] m_aryPrivateKey;

        private readonly CipherMode m_CipherMode = CipherMode.CBC;

        private Boolean m_blnDisposeHasBeenCalled = false;

        /// <summary>
        /// 
        /// </summary>
        /// <param name="privateKey">Typically 32 characters long (32 characters x 8 bits/character = 256 bits)</param>
        /// <param name="iv">Typically 16 characters</param>
        /// <param name="cipherMode">CBC is the default, and the most commonly used.</param>
        public Crypto(String privateKey, String iv, CipherMode cipherMode = CipherMode.CBC)
        {


            try
            {
                m_PrivateKey = privateKey;

                m_aryPrivateKey = Encoding.ASCII.GetBytes(privateKey);

                m_IV = iv;

                m_aryIV = Encoding.ASCII.GetBytes(iv);

                m_CipherMode = cipherMode;

            }  // END try
            catch
            {
                throw;
            } // END catch
            finally
            {

            }  // END finally


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
            if (objectToEncrypt == null)
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.ENCRYPT_EMPTY_MSG);
                throw exArg;
            }

            String strReturn = "";                 // Encrypted string to return 

            try
            {
                JsonSerializerOptions jsonOptions = new JsonSerializerOptions
                {
                    AllowTrailingCommas = true,
                    NumberHandling = JsonNumberHandling.AllowReadingFromString,
                    WriteIndented = true
                };

                String serializedObject = System.Text.Json.JsonSerializer.Serialize<T>(objectToEncrypt, jsonOptions);

                strReturn = EncryptStringAES(serializedObject);

            }  // END try
            catch (NotSupportedException exNotSupported)
            {
                ArgumentException exArg = new ArgumentException(CryptoResources.ENCRYPT_NONSERIALIZABLE_OBJECT, exNotSupported);

                exArg.Data.Add("m_CipherMode", m_CipherMode.ToString());

                throw exArg;
            }
            catch (Exception exUnhandled)
            {
                exUnhandled.Data.Add("m_CipherMode", m_CipherMode.ToString());
                throw;
            }
            finally
            {
            }

            return strReturn;

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
        /// <param name="strEncryptedText">The AES-encrypted string to decrypt. Cannot be null, empty, or whitespace.</param>
        /// <returns>An object of type <typeparamref name="T"/> deserialized from the decrypted string.</returns>
        public T DecryptObjectAES<T>(String strEncryptedText)
        {
            if (String.IsNullOrWhiteSpace(strEncryptedText))
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.DECRYPT_EMPTY_MSG);
                throw exArg;
            }

            T objReturn = default;

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

                String serializedObject = DecryptStringAES(strEncryptedText);

                objReturn = JsonSerializer.Deserialize<T>(serializedObject, jsonOptions);

            }  // END try
            catch (NotSupportedException exNotSupported)
            {
                ArgumentException exArg = new ArgumentException(CryptoResources.DECRYPT_NONSERIALIZABLE_OBJECT, exNotSupported);

                exArg.Data.Add("m_CipherMode", m_CipherMode.ToString());

                throw exArg;
            }
            catch (Exception exUnhandled)
            {
                exUnhandled.Data.Add("strEncryptedText", strEncryptedText ?? "");
                exUnhandled.Data.Add("m_CipherMode", m_CipherMode.ToString());
                throw;
            }
            finally
            {

            }

            return objReturn;
        }

        /// <summary> 
        /// Encrypt the given string using AES.  The string can be decrypted using  
        /// DecryptStringAES(). Block size is 128 (bits) for the IV value, which is 16 characters.
        /// </summary> 
        /// <param name="strStringToEncrypt">The text to encrypt.</param> 
        public String EncryptStringAES(String strStringToEncrypt)
        {
            if (String.IsNullOrWhiteSpace(strStringToEncrypt))
            {

                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.ENCRYPT_EMPTY_MSG);

                throw exArg;
            }

            String strReturn = "";                   // Encrypted string to return 
            Aes objAES = null;                       // Aes object used to encrypt the data.
            MemoryStream memorySteam = null;         // Memory stream used to hold the encrypted data.
            CryptoStream cryptoStream = null;        // Crypto stream used to encrypt the data.

            try
            {
                objAES = Aes.Create();
                objAES.Key = m_aryPrivateKey;
                objAES.IV = m_aryIV;
                objAES.Mode = m_CipherMode;

                ICryptoTransform objEncryption = objAES.CreateEncryptor(objAES.Key, objAES.IV);

                memorySteam = new MemoryStream();
                cryptoStream = new CryptoStream(memorySteam, objEncryption, CryptoStreamMode.Write);

                Byte[] bytesToEncrypt = Encoding.UTF8.GetBytes(strStringToEncrypt);

                cryptoStream.Write(bytesToEncrypt, 0, bytesToEncrypt.Length);

                cryptoStream.FlushFinalBlock();

                Byte[] results = memorySteam.ToArray();

                memorySteam.Close();

                cryptoStream.Close();

                strReturn = Convert.ToBase64String(results);

            }  // END try
            catch (Exception exUnhandled)
            {
                exUnhandled.Data.Add("strStringToEncrypt", strStringToEncrypt ?? "");
                exUnhandled.Data.Add("m_CipherMode", m_CipherMode.ToString());

                throw;
            }
            finally
            {

                // Dispose the IDisposable objects. 
                if (cryptoStream != null)
                {
                    cryptoStream.Close();
                    cryptoStream.Dispose();
                    cryptoStream = null;
                }


                if (memorySteam != null)
                {
                    memorySteam.Close();
                    memorySteam.Dispose();
                    memorySteam = null;
                }


                if (objAES != null)
                {
                    objAES.Clear();
                    objAES.Dispose();
                    objAES = null;
                }

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

            if (String.IsNullOrWhiteSpace(strEncryptedText))
            {

                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.DECRYPT_EMPTY_MSG);

                throw exArg;
            }

            String strReturn = null;                 // Encrypted string to return 
            Aes objAES = null;                       // Aes object used to encrypt the data.
            MemoryStream memorySteam = null;         // Memory stream used to hold the encrypted data.
            CryptoStream cryptoStream = null;        // Crypto stream used to encrypt the data.
            StreamReader streamReader = null;

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
                strReturn = streamReader.ReadToEnd();

            }  // END try
            catch (Exception exUnhandled)
            {
                exUnhandled.Data.Add("strEncryptedText", strEncryptedText ?? "");
                exUnhandled.Data.Add("m_CipherMode", m_CipherMode.ToString());

                throw;

            } // END catch
            finally
            {

                // Dispose the IDisposable objects. 
                if (streamReader != null)
                {
                    streamReader.Close();
                    streamReader.Dispose();
                    streamReader = null;
                }

                if (cryptoStream != null)
                {
                    cryptoStream.Close();
                    cryptoStream.Dispose();
                    cryptoStream = null;
                }


                if (memorySteam != null)
                {
                    memorySteam.Close();
                    memorySteam.Dispose();
                    memorySteam = null;
                }


                if (objAES != null)
                {
                    objAES.Clear();
                    objAES.Dispose();
                    objAES = null;
                }
            }

            return strReturn;

        }  // END public String DecryptStringAES(String strEncryptedText)

        /// <summary>
        /// Computes the SHA-512 hash of the specified object.
        /// </summary>
        /// <remarks>The method serializes the provided object using JSON serialization before computing
        /// the hash. Ensure that the object is serializable and does not contain circular references.</remarks>
        /// <typeparam name="T">The type of the object to hash.</typeparam>
        /// <param name="objectToHash">The object to compute the hash for. Cannot be <see langword="null"/>.</param>
        /// <returns>A string representation of the SHA-512 hash of the serialized object.</returns>
        public String GetObjectSHA512Hash<T>(T objectToHash)
        {
            if (objectToHash == null)
            {
                ArgumentNullException exArg = new ArgumentNullException(CryptoResources.HASH_UNHANDLED_MSG);
                throw exArg;
            }

            String strReturn = "";                 // Encrypted string to return 

            try
            {
                JsonSerializerOptions jsonOptions = new JsonSerializerOptions
                {
                    AllowTrailingCommas = true,
                    NumberHandling = JsonNumberHandling.AllowReadingFromString,
                    WriteIndented = true
                };

                String serializedObject = System.Text.Json.JsonSerializer.Serialize<T>(objectToHash, jsonOptions);

                strReturn = GetSHA512Hash(serializedObject);

            }  // END try
            catch (Exception exUnhandled)
            {
                exUnhandled.Data.Add("m_CipherMode", m_CipherMode.ToString());
                throw;
            }
            finally
            {

            }
            return strReturn;
        }  // END public String GetObjectSHA512Hash<T>(T objectToHash)

        /// <summary>
        /// This function takes a value you want hashed and hashes it uses SHA-512 for strength.  
        /// </summary>
        /// <param name="stringToHash">This is the value, such as a password.  It will usually be the same over a number of instances on multiple machines.</param>
        /// <returns>The value returned is the hash string in Base 64</returns>
        public String GetSHA512Hash(String stringToHash)
        {

            String retVal = "";

            SHA512 hasher = null;

            try
            {
                Byte[] aryStringToHash = Encoding.UTF8.GetBytes(stringToHash);

                hasher = SHA512.Create();

                Byte[] aryHash = hasher.ComputeHash(aryStringToHash);

                retVal = BitConverter.ToString(aryHash).Replace("-", "").ToLowerInvariant();

            }
            catch (Exception exUnhandled)
            {
                exUnhandled.Data.Add("stringToHash", stringToHash ?? "");

                throw;

            } // END catch
            finally
            {
                if (hasher != null)
                {
                    hasher.Clear();

                    hasher.Initialize();

                    hasher.Dispose();

                    hasher = null;
                }
            }

            return retVal;

        }  // END public String GetSHA512Hash(String stringToHash)


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
                        //	m_objtWithAnEventHandler.Dispose();
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

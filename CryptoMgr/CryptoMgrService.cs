using Jeff.Jones.CryptoMgr;
using Jeff.Jones.CryptoMgr.Properties;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Jeff.Jones.CryptoMgr
{

    /// <summary>
    /// Provides a thread-safe service for managing Crypto instances and operations, implemented as thread-safe singleton.
    /// The benefit of using a singleton is that keeps 1 or more instances of Crypto object(s) in memory for reuse, eliminating the creation and disposal time
    /// while still be accessible through the application.  Each Crypto instance is uniquely identified by a name, and the service supports adding, retrieving, and
    /// removing Crypto instances.  The service is thread-safe and ensures proper disposal of resources. Users must call <see cref="Dispose"/> when the service is no
    /// </summary>
    /// <remarks>This class is a singleton, accessible via the <see cref="Instance"/> property, and is
    /// designed to manage Crypto instances identified by unique names. It supports adding, retrieving, and
    /// removing Crypto instances, as well as thread-safe access to the collection of Crypto instances.  The
    /// service is thread-safe and ensures proper disposal of resources. Users must call <see cref="Dispose"/> when the
    /// service is no longer needed to release resources explicitly.</remarks>
    public sealed class CryptoMgrService : IDisposable
    {

        /// <summary>
        /// The single, thread-safe instance of the CryptoMgrService.
        /// </summary>
        public static readonly CryptoMgrService Instance = new CryptoMgrService();

        /// <summary>
        /// True if dispose was called.
        /// </summary>
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
        /// The thread-safe dictionary containing the name-Crypto pairs.
        /// The C# keyword "volatile" tells the compiler that the object must not be cached, and enables multithread
        /// access to the object.  When the object is read or a method is called, it is the current object
        /// instance in memory, and not a cached version.
        /// </summary>
        private volatile ConcurrentDictionary<String, Crypto> m_CryptoDictionary = new ConcurrentDictionary<String, Crypto>();

        /// <summary>
        /// Indicates whether this singleton has been initialized.  Initialization provides the common logging object and levels
        /// used by this object and all the child Crypto objects.
        /// </summary>
        /// <remarks>This field is used to track the initialization state of the object.  It is marked as
        /// <see langword="volatile"/> to ensure that updates to its value  are immediately visible across
        /// threads.</remarks>
        private volatile Boolean m_IsInitialized = false;

        /// <summary>
        /// Initializes a new instance of the <see cref="CryptoMgrService"/> class.
        /// This is called on first reference to the object.
        /// </summary>
        /// <remarks>This constructor ensures that the internal dictionary used to manage Crypto instances
        /// is properly initialized. The dictionary is thread-safe, allowing concurrent access.</remarks>
        private CryptoMgrService()
        {
            if (m_CryptoDictionary == null)
            {
                m_CryptoDictionary = new ConcurrentDictionary<String, Crypto>();
            }
        }

        /// <summary>
        /// Initializes the instance with the specified logger and log levels.
        /// 
        /// If the instance is already initialized, this method will not reinitialize it.
        /// </summary>
        /// <param name="log">An optional logger to be used for logging operations. If null, no logging will occur.</param>
        /// <param name="logLevels">A bitset representing the log levels to be used. Defaults to <see cref="Extensions.DEFAULT_LOG_LEVELS"/> if
        /// not specified.</param>
        public void Initialize(ILogger log = null, LogLevelsBitset logLevels = Extensions.DEFAULT_LOG_LEVELS)
        {
            Stopwatch stopWatch = Stopwatch.StartNew();

            try
            {
                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    m_Log.LogTrace($"Begin CryptoMgrService initialization.");
                }

                if (!m_IsInitialized)
                {

                    if (m_CryptoDictionary == null)
                    {
                        m_CryptoDictionary = new ConcurrentDictionary<String, Crypto>();
                    }

                    m_Log = log;

                    m_LogLevels = logLevels;

                    m_IsInitialized = true;
                }

            }  // END try
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing secure information
                exUnhandled.Data.AddCheck("IsLogNull", log != null ? log.GetType().FullName : "NULL");
                exUnhandled.Data.AddCheck("logLevels", logLevels.ToString());
                exUnhandled.Data.AddCheck("IsInitialized", m_IsInitialized.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"CryptoMgrService initialization error. [{strError}].");
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

                    String logMsg = $"CryptoMgrService initialization Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";

                    m_Log.LogTrace(logMsg);
                }

            }  // END finally

        }


        /// <summary>
        /// Adds a cryptographic configuration for use in encryption and decryption operations.
        /// </summary>
        /// <remarks>This method configures a cryptographic setup that can be referenced by the specified
        /// <paramref name="name"/>. Ensure that the <paramref name="privateKey"/> and <paramref name="iv"/> are
        /// securely managed and comply with the requirements of the selected <paramref name="cipherMode"/>.</remarks>
        /// <param name="name">The unique name identifying the cryptographic configuration. Must not be null or empty.  Case insensitive.</param>
        /// <param name="privateKey">The private key used for encryption and decryption. Must not be null or empty.</param>
        /// <param name="iv">The initialization vector (IV) used for encryption. Must not be null or empty.</param>
        /// cref="Extensions.DEFAULT_LOG_LEVELS"/>.</param>
        /// <param name="cipherMode">The cipher mode to be used for encryption and decryption. Defaults to <see cref="CipherMode.CBC"/>.</param>
        public Boolean AddCrypto(String name, String privateKey, String iv,
                                 CipherMode cipherMode = CipherMode.CBC)
        {
            Boolean retVal = false;

            Stopwatch stopWatch = Stopwatch.StartNew();

            try
            {
                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
                {
                    m_Log.LogTrace($"Begin AddCrypto.");
                }

                if (m_CryptoDictionary.ContainsKey(name.ToUpper()))
                {
                    String msg = String.Format(CryptoResources.CRYPTO_INSTANCE_EXISTS, name.ToUpper());

                    throw new ArgumentException(msg, nameof(name));
                }
                else
                {
                    retVal = m_CryptoDictionary.TryAdd(name.ToUpper(), new Crypto(privateKey, iv, m_Log, m_LogLevels, cipherMode));
                }
            }  // END try
            catch (Exception exUnhandled)
            {
                // Add some additional information to the exception's Data dictionary.
                // Be sure to NOT add anything that would lead to exposing secure information
                exUnhandled.Data.AddCheck("name", name.ToUpper() ?? "NULL");
                exUnhandled.Data.AddCheck("cipherMode", cipherMode.ToString());

                if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Error) == LogLevelsBitset.Error))
                {
                    String strError = exUnhandled.GetFullExceptionMessage(true, true);

                    m_Log.LogError($"AddCrypto error. [{strError}].");
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
                    String logMsg = $"AddCrypto Elapsed time = [{elapsedTime.GetElapsedTimeDisplayString()}].";
                    m_Log.LogTrace(logMsg);
                }

            }  // END finally

            return retVal;
        }

        /// <summary>
        /// Retrieves a Crypto instance by its name.
        /// </summary>
        /// <remarks>Use this method to look up a Crypto instance by its name from the internal dictionary.
        /// Ensure that the name provided matches the key exactly, as the lookup is case-sensitive.
        /// Note that what is returned is a reference to the object in the ConcurrentDictionary, not a new instance.
        /// The object in the caller should not be Disposed, but can be set to null since it is the reference 
        /// being set to null, not the actual object still remaining in the ConcurrentDictionary instance.</remarks>
        /// <param name="name">The name of the Crypto instance to retrieve. This value is case-sensitive and cannot be null.</param>
        /// <returns>The <see cref="Crypto"/> object associated with the specified name,  or <see langword="null"/> if the name
        /// does not exist in the dictionary.</returns>
        public Crypto GetCrypto(String name)
        {
            Crypto retVal = null!;

            if (m_CryptoDictionary.ContainsKey(name.ToUpper()))
            {
                retVal = m_CryptoDictionary[name.ToUpper()];
            }

            return retVal;
        }

        /// <summary>
        /// Removes the specified Crypto instance from the internal collection.
        /// </summary>
        /// <remarks>If the specified Crypto instance exists in the collection, it will be removed and any
        /// associated resources will be disposed. If the Crypto instance does not exist, the method will return <see
        /// langword="true"/> without performing any action.</remarks>
        /// <param name="name">The name of the Crypto instance to remove. This value is case-sensitive and cannot be null.</param>
        /// <returns><see langword="true"/> if the Crypto instance was successfully removed or if it was not found in the
        /// collection; otherwise, <see langword="false"/> if the removal operation failed.</returns>
        public Boolean RemoveCrypto(String name)
        {
            Boolean retVal = false;

            Stopwatch stopWatch = Stopwatch.StartNew();

            if ((m_Log != null) && ((m_LogLevels & LogLevelsBitset.Trace) == LogLevelsBitset.Trace))
            {
                m_Log.LogTrace($"Begin RemoveCrypto method.");
            }

            if (!m_CryptoDictionary.ContainsKey(name.ToUpper()))
            {
                retVal = true;
            }
            else
            {
                if (m_CryptoDictionary.TryRemove(name.ToUpper(), out Crypto? crypto))
                {
                    crypto.Dispose();

                    crypto = null;

                    retVal = true;
                }
            }

            return retVal;
        }

        /// <summary>
        /// Gets a thread-safe collection of Crypto instance items.
        /// </summary>
        /// <remarks>The dictionary is lazily initialized and ensures thread-safe access for concurrent
        /// operations.</remarks>
        public ConcurrentDictionary<String, Crypto> CryptoItems
        {
            get
            {
                if (m_CryptoDictionary == null)
                {
                    m_CryptoDictionary = new ConcurrentDictionary<String, Crypto>();
                }

                return m_CryptoDictionary;
            }
        }


        #region IDisposable Implementation=========================

        /// <summary>
        /// This property is true if Dispose() has been called, false if not.
        ///
        /// The programmer does not have to check this property before calling
        /// the Dispose() method as the check is made internally and Dispose()
        /// is not executed more than once.
        /// </summary>
        public Boolean Disposing
        {
            get
            {
                return m_blnDisposeHasBeenCalled;
            }
        }  // END public Boolean Disposing

        /// <summary>
        /// Implement the IDisposable.Dispose() method
        /// Developers are supposed to call this method when done with this object.
        /// There is no guarantee when or if the GC will call it, so 
        /// the developer is responsible to.  GC does NOT clean up unmanaged 
        /// resources, so we have to clean those up, too.
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

                    // Prevent subsequent finalization of this object. Subsequent finalization 
                    // is not needed because managed and unmanaged resources have been 
                    // explicitly released
                    GC.SuppressFinalize(this);
                }
            }

            catch
            {

            }  // END Catch

        }  // END public new void Dispose()

        /// <summary>
        /// Explicit Finalize method.  The GC calls Finalize, if it is called.
        /// There are times when the GC will fail to call Finalize, which is why it is up to 
        /// the developer to call Dispose() from the consumer object.
        /// </summary>
        ~CryptoMgrService()
        {
            // Call Dispose indicating that this is not coming from the public
            // dispose method.
            Dispose(false);
        }

        /// <summary>
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="pDisposing">true if managed resources should be disposed; otherwise, false.</param>
        public void Dispose(Boolean pDisposing)
        {

            try
            {
                if (!m_blnDisposeHasBeenCalled)
                {
                    if (pDisposing)
                    {
                        // Here we dispose and clean up the unmanaged objects and managed object we created in code
                        // that are not in the IContainer child object of this object.
                        // Unmanaged objects do not have a Dispose() method, so we just set them to null
                        // to release the reference.  For managed objects, we call their respective Dispose()
                        // methods, if they have them, and then release the reference.
                        // if (m_objComputers != null)
                        //     {
                        //     m_objComputers = null;
                        //     }

                        if (m_CryptoDictionary != null)
                        {
                            foreach (KeyValuePair<String, Crypto> kvp in m_CryptoDictionary)
                            {
                                kvp.Value.Dispose();
                            }

                            m_CryptoDictionary.Clear();

                            m_CryptoDictionary = null!;
                        }

                        // If the base object for this instance has a Dispose() method, call it.
                        //base.Dispose();
                    }

                    // Set the flag that Dispose has been called and executed.
                    m_blnDisposeHasBeenCalled = true;
                }

            }

            catch
            {

            }  // END Catch
        }

        #endregion IDisposable Implementation======================
    }
}

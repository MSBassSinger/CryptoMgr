using System.Collections;
using System.Text.Json.Serialization;

namespace Jeff.Jones.CryptoMgr
{
    /// <summary>
    /// Level(s) to use for logging.  Changing this value changes what is logged and what is not.
    /// </summary>
    [JsonConverter(typeof(JsonStringEnumConverter<LogLevelsBitset>))]
    [Flags]
    public enum LogLevelsBitset
    {
        /// <summary>
        /// Represents the absence of a value or state.
        /// </summary>
        [JsonStringEnumMemberName("None")] 
        None = 0,
        /// <summary>
        /// Represents the trace level of logging, used for detailed diagnostic information.
        /// </summary>
        [JsonStringEnumMemberName("Trace")]
        Trace = 1,
        /// <summary>
        /// Represents the debug logging level, typically used for diagnostic information.
        /// </summary>
        /// <remarks>This level is intended for detailed information that is useful during development or
        /// debugging. It may include extensive data about the application's state or behavior.</remarks>
        [JsonStringEnumMemberName("Debug")]
        Debug = 2,
        /// <summary>
        /// Represents an informational log level used to log general application events or messages.
        /// </summary>
        [JsonStringEnumMemberName("Information")]
        Information = 4,
        /// <summary>
        /// Represents a warning-level log severity.
        /// </summary>
        /// <remarks>This value is typically used to indicate potential issues or situations that require
        /// attention but do not prevent the application from functioning.</remarks>
        [JsonStringEnumMemberName("Warning")]
        Warning = 8,
        /// <summary>
        /// Represents an error state or condition.
        /// </summary>
        /// <remarks>This value is typically used to indicate that an operation has failed or encountered
        /// an unexpected issue.</remarks>
        [JsonStringEnumMemberName("Error")]
        Error = 16,
        /// <summary>
        /// Represents a log level indicating a critical failure that causes the application to terminate.
        /// </summary>
        [JsonStringEnumMemberName("Fatal")]
        Fatal = 32,
        /// <summary>
        /// Represents a value that includes all possible flags in the enumeration.
        /// </summary>
        /// <remarks>This value is typically used to indicate that all flags are selected or
        /// enabled.</remarks>
        [JsonStringEnumMemberName("All")]
        All = 63
    }

    /// <summary>
    /// Specifies the key sizes available for AES encryption.
    /// </summary>
    /// <remarks>This enumeration defines the standard key sizes used in AES (Advanced Encryption Standard)
    /// encryption. Each value represents the bit length of the encryption key.</remarks>
    public enum AESKeySizeEnum
    {
        /// <summary>
        /// Represents the AES encryption algorithm with a 128-bit key size (16 characters).
        /// </summary>
        [JsonStringEnumMemberName("AES128")]
        AES128 = 128,
        /// <summary>
        /// Represents the Advanced Encryption Standard (AES) with a 192-bit key size (24 characters).
        /// </summary>
        [JsonStringEnumMemberName("AES192")]
        AES192 = 192,
        /// <summary>
        /// Represents the AES encryption algorithm with a 256-bit key size (32 characters).
        /// </summary>
        /// <remarks>AES256 is a symmetric encryption algorithm that uses a 256-bit key for encrypting and
        /// decrypting data. It is widely used for its strong security and efficiency.</remarks>
        [JsonStringEnumMemberName("AES256")]
        AES256 = 256
    }

    /// <summary>
    /// Provides a set of extension methods and constants for common operations, including exception handling, string
    /// manipulation, and delimiter definitions.
    /// </summary>
    /// <remarks>This class includes utility methods for working with exceptions, converting strings to and
    /// from Base64, formatting <see cref="TimeSpan"/> instances, and more. It also defines constants for default
    /// logging levels and non-printable ASCII delimiters commonly used in data processing.</remarks>
    public static class Extensions
    {
        /// <summary>
        /// Default logging level value to use.  
        /// </summary>
        public const LogLevelsBitset DEFAULT_LOG_LEVELS = LogLevelsBitset.Error | LogLevelsBitset.Fatal;

        /// <summary>
        /// Represents the default log levels as a pipe-separated string.
        /// </summary>
        /// <remarks>The default log levels are "Error" and "Fatal", separated by a pipe ('|') character.
        /// This constant can be used to initialize or configure logging systems with predefined log levels.</remarks>
        public const String DEFAULT_LOG_LEVELS_STRING = "Error,Fatal";

        /// <summary>
        /// Returns error messages from the parent exception and any 
        /// exceptions down the stack, and optionally, the data collection.
        /// 
        /// </summary>
        /// <param name="ex2Examine">The exception to examine.</param>
        /// <param name="getDataCollection">True if the data collection items are to be included; False if not.</param>
        /// <param name="getStackTrace">True if the stack trace is to be included; False if not.</param>
        /// <returns>A string with the error messages</returns>
        public static String GetFullExceptionMessage(this Exception ex2Examine,
                                                     Boolean getDataCollection,
                                                     Boolean getStackTrace)
        {

            String retValue = "";
            String message = "";
            String data = "";
            String stackTrace = "";

            try
            {

                if (((ex2Examine != null)))
                {

                    if ((getStackTrace))
                    {
                        // The stack trace is most complete at the top-level
                        // exception.  If we are to include it, we grab it here.
                        if (((ex2Examine.StackTrace != null)))
                        {
                            stackTrace = "; Stack Trace=[" + ex2Examine.StackTrace + "].";
                        }

                    }

                    Exception nextException = ex2Examine;

                    message = "";

                    // We need to loop through all child exceptions to get all the messages.
                    // For example, an exception caught when using a SqlClient may not
                    // show a message that explains the problem.  There may be 1, 2, or even 3 
                    // inner exceptions stacked up. The deepest will likely have the cause
                    // of the failure in its message.  So it is a good practice to capture
                    // all the messages, pulled from each instance.
                    while (nextException != null)
                    {

                        data = "";

                        message += nextException.Message ?? "NULL";


                        if (nextException.Source != null)
                        {
                            message += "; Source=[" + nextException.Source + "]";

                        }

                        // The Exception provides a Data collection of name-value
                        // pairs.  This provides a means, at each method level from 
                        // initiation up through the stack, to capture the runtime data
                        // which helps diagnose the problem.
                        if (getDataCollection)
                        {
                            if (nextException.Data != null)
                            {
                                if (nextException.Data.Count > 0)
                                {
                                    foreach (DictionaryEntry item in nextException.Data)
                                    {
                                        data += "{" + item.Key.ToString() + "}={" + item.Value?.ToString() + "}|";
                                    }

                                    data = data.Substring(0, data.Length - 1);
                                }

                            }

                        }

                        if (getDataCollection)
                        {
                            if ((data.Length > 0))
                            {
                                message = message + "; Data=[" + data + "]";
                            }
                            else
                            {
                                message += "; Data=[None]";
                            }
                        }

                        if (nextException.InnerException == null)
                        {
                            break;
                        }
                        else
                        {
                            nextException = nextException.InnerException;
                        }

                        message += "::";

                    }

                    if ((stackTrace.Length > 0))
                    {
                        message = message.Trim();

                        if (message.EndsWith(';'))
                        {
                            message += " " + stackTrace;
                        }
                        else
                        {
                            message += "; " + stackTrace;
                        }
                    }

                }

                retValue = message.Trim();

                if (retValue.EndsWith("::"))
                {
                    retValue = retValue.Substring(0, retValue.Length - 2);
                }

            }
            catch (Exception exUnhandled)
            {
                exUnhandled.Data.AddCheck("getDataCollection", getDataCollection.ToString());

                exUnhandled.Data.AddCheck("getStackTrace", getStackTrace.ToString());

                throw;

            }

            return retValue;

        }  // END public static String GetFullExceptionMessage( ... )


        /// <summary>
        /// IDictionary extension method that is an enhanced Add to check to see if a key exists, and if so, 
        /// adds the key with an ordinal appended to the key name to prevent overwrite.
        /// This is useful with the Exception.Data IDictionary collection, among other
        /// IDictionary implementations.
        /// </summary>
        /// <param name="dct">The IDictionary implementation</param>
        /// <param name="dataKey">The string key for the name-value pair.</param>
        /// <param name="dataValue">The value for the name-value pair.  Accepts any data type, which is resolved to the type at runtime.</param>
        public static void AddCheck(this IDictionary dct, String dataKey, dynamic dataValue)
        {

            if (dct != null)
            {
                if (dct.Contains(dataKey))
                {
                    for (int i = 1; i < 101; i++)
                    {
                        String newKey = dataKey + "-" + i.ToString();

                        if (!dct.Contains(newKey))
                        {
                            if (dataValue == null)
                            {
                                dct.Add(newKey, "NULL");
                            }
                            else
                            {
                                dct.Add(newKey, dataValue);
                            }

                            break;
                        }
                    }
                }
                else
                {
                    dct.Add(dataKey, dataValue);
                }
            }
        }

        /// <summary>
        /// Converts a <see cref="TimeSpan"/> instance into a human-readable string representation.
        /// </summary>
        /// <remarks>The method formats the <paramref name="timeSpan"/> by including only the non-zero
        /// components of the time span.  For example, a <see cref="TimeSpan"/> of 1 day, 2 hours, and 30 minutes will
        /// be formatted as "1 d, 02 h, 30 m". Trailing commas are removed from the resulting string.</remarks>
        /// <param name="timeSpan">The <see cref="TimeSpan"/> to format.</param>
        /// <returns>A string that represents the elapsed time in a readable format, including days, hours, minutes, seconds, 
        /// milliseconds, and nanoseconds, as applicable. Each unit is separated by a comma.</returns>
        public static String GetElapsedTimeDisplayString(this TimeSpan timeSpan)
        {
            String retVal = "";

            if (timeSpan.Days > 0)
            {
                retVal += timeSpan.Days.ToString("0") + " d, ";
            }
            if (timeSpan.Hours > 0)
            {
                retVal += timeSpan.Hours.ToString("00") + " h, ";
            }
            if (timeSpan.Minutes > 0)
            {
                retVal += timeSpan.Minutes.ToString("00") + " m, ";
            }
            if (timeSpan.Seconds > 0)
            {
                retVal += timeSpan.Seconds.ToString("00") + " s, ";
            }
            if (timeSpan.Milliseconds > 0)
            {
                retVal += timeSpan.Milliseconds.ToString("000") + " ms, ";
            }
            if (timeSpan.Nanoseconds > 0)
            {
                retVal += timeSpan.Nanoseconds.ToString("000") + " ns";
            }

            if (retVal.EndsWith(", "))
            {
                retVal = retVal.Substring(0, retVal.Length - 2);
            }

            return retVal;
        }

        /// <summary>
        /// Method to get all the exception messages, generally when the outer exception has inner exceptions.
        /// </summary>
        /// <param name="ex2Examine">Outer parameter to examine.</param>
        /// <param name="messageDelimiter">Character(s) used to delimit lines.</param>
        /// <returns>String with the error messages.</returns>
        public static String GetExceptionMessages(this Exception ex2Examine, String messageDelimiter = "::")
        {

            String retValue = "";
            String message = "";

            try
            {

                if (((ex2Examine != null)))
                {

                    Exception nextException = ex2Examine;

                    message = "";

                    // We need to loop through all child exceptions to get all the messages.
                    // For example, an exception caught when using a SqlClient may not
                    // show a message that explains the problem.  There may be 1, 2, or even 3 
                    // inner exceptions stacked up. The deepest will likely have the cause
                    // of the failure in its message.  So it is a good practice to capture
                    // all the messages, pulled from each instance.
                    while (nextException != null)
                    {

                        message += nextException.GetType().Name + " Message=[" + (nextException.Message ?? "NULL") + "]";


                        if (nextException.Source != null)
                        {
                            message += "; Source=[" + nextException.Source + "]";

                        }

                        if (nextException.InnerException == null)
                        {
                            break;
                        }
                        else
                        {
                            nextException = nextException.InnerException;
                        }

                        message += messageDelimiter;

                    }

                }

                retValue = message.Trim();

                if (retValue.EndsWith(messageDelimiter))
                {
                    retValue = retValue.Substring(0, retValue.Length - messageDelimiter.Length);
                }

            }
            catch (Exception exUnhandled)
            {
                exUnhandled.Data.AddCheck("ex2Examine", ex2Examine == null ? "NULL" : ex2Examine.GetType().Name);
                throw;
            }

            return retValue;

        }  // END public static String GetExceptionMessages( ... )


        /// <summary>
        /// Iterates through all the exceptions (outer and inner) for the name-value pairs in each Exception's Data collection.
        /// Example:
        /// {name01}={Value01}|{name02}={Value02}::{name11}={Value11}|{name12}={Value12}
        /// </summary>
        /// <param name="ex2Examine">Outer exception to check.</param>
        /// <param name="columnDelimiter">Delimiter to use between name-value pair strings.</param>
        /// <param name="lineDelimiter">Delimiter between lines of name-value pair(s)</param>
        /// <returns>String formatted with name-value pairs in the exception's Data collection.</returns>
        public static String GetExceptionData(this Exception ex2Examine, String columnDelimiter = "|", String lineDelimiter = "::")
        {

            String retVal = "";
            String data = "";

            try
            {

                if (((ex2Examine != null)))
                {

                    Exception nextException = ex2Examine;

                    // We need to loop through all child exceptions to get all the Data collection 
                    // name-value pairs. For example, an exception caught when using a SqlClient may not
                    // show data that helps explains the problem.  There may be 1, 2, or even 3 
                    // inner exceptions stacked up. The deepest will likely have data (if it has any) related 
                    // to the failure in its data collection.  So it is a good practice to capture
                    // all the data collection, pulled from each exception/inner exception.
                    while (nextException != null)
                    {

                        data = "";

                        // The Exception provides a Data collection of name-value
                        // pairs.  This provides a means, at each method level from 
                        // initiation up through the stack, to capture the runtime data
                        // which helps diagnose the problem.
                        if (nextException.Data.Count > 0)
                        {
                            foreach (DictionaryEntry item in nextException.Data)
                            {
                                data += "{" + item.Key.ToString() + "}={" + item.Value?.ToString() + "}" + columnDelimiter;
                            }

                            data = data.Substring(0, data.Length - 1);
                        }

                        if ((data.Length > 0))
                        {
                            retVal += nextException.GetType().Name + " Data=[" + data + "]";
                        }
                        else
                        {
                            retVal += nextException.GetType().Name + " Data=[None]";
                        }

                        if (nextException.InnerException == null)
                        {
                            break;
                        }
                        else
                        {
                            nextException = nextException.InnerException;
                        }

                        retVal += lineDelimiter;

                    }

                    retVal = retVal.Trim();

                }

                if (retVal.EndsWith(lineDelimiter))
                {
                    retVal = retVal.Substring(0, retVal.Length - lineDelimiter.Length);
                }

            }
            catch (Exception exUnhandled)
            {
                exUnhandled.Data.AddCheck("ex2Examine", ex2Examine == null ? "NULL" : ex2Examine.GetType().Name);

                throw;
            }

            return retVal;

        }  // END public static String GetExceptionData( ... )


        /// <summary>
        /// Convert String to Base64
        /// 
        /// Exceptions:
        ///   System.ArgumentNullException - String2Convert  or byte array created from it is null.
        ///   System.Text.EncoderFallbackException - 
        ///        A fallback occurred (see Understanding Encodings for complete explanation)-and-
        ///        System.Text.Encoding.EncoderFallback is set to System.Text.EncoderExceptionFallback.
        /// 
        /// </summary>
        /// <param name="String2Convert">A string to be converted to Base64</param>
        /// <returns>String with Base64 value.</returns>
        public static String StringToBase64(this String String2Convert)
        {
            Byte[] ByteString = System.Text.Encoding.UTF8.GetBytes(String2Convert);
            String ByteString64 = Convert.ToBase64String(ByteString);
            return ByteString64;
        }

        /// <summary>
        /// Convert Base64String to String
        /// 
        /// Exceptions:
        ///   System.ArgumentNullException - ByteString64, or the byte array made from it, is null.
        ///   System.FormatException - 
        ///        The length of ByteString64, ignoring white-space characters, is not zero or a multiple
        ///        of 4. -or-The format of ByteString64 is invalid. s contains a non-base-64 character,
        ///        more than two padding characters, or a non-white space-character among the
        ///        padding characters.
        ///   System.ArgumentException - The byte array contains invalid Unicode code points.
        ///   System.Text.DecoderFallbackException - 
        ///        A fallback occurred (see Understanding Encodings for complete explanation)-and-
        ///        System.Text.Encoding.DecoderFallback is set to System.Text.DecoderExceptionFallback.
        /// 
        /// </summary>
        /// <param name="ByteString64">A Base64 string to be decoded.</param>
        /// <returns>String with converted value.</returns>
        public static String Base64ToString(this String ByteString64)
        {
            byte[] ByteString = Convert.FromBase64String(ByteString64);
            return (System.Text.Encoding.UTF8.GetString(ByteString));
        }

        /// <summary>
        /// Converts a 32 bit integer to a String hex value.
        /// Default length of the return string is 2 characters.
        /// </summary>
        /// <param name="lngValue">The number to be converted to a hex value.</param>
        /// <param name="outputLength">How many characters in the return value.</param>
        /// <returns>String hex value.</returns>
        public static String ToHex(this Int32 lngValue, Int32 outputLength = 2)
        {
            String retVal = lngValue.ToString($"X{outputLength}");
            return retVal;
        }














        /// <summary>
        /// This value can be applied to the value for a constant.
        /// 
        /// RowDelimiter is the same non-printable ASCII character used
        /// in teletypes and other devices to indicate a new row, 
        /// and not likely to be seen in string data.
        /// </summary>
        public static String RowDelimiter
        {
            get
            {
                return ((Char)29).ToString();
            }
        }

        /// <summary>
        /// This value can be applied to the value for a constant.
        /// 
        /// ColumnDelimiter is the same non-printable ASCII character used
        /// in teletypes and other devices to indicate a new column, 
        /// and not likely to be seen in string data.
        /// </summary>
        public static String ColumnDelimiter
        {
            get
            {
                return ((Char)28).ToString();
            }
        }

        /// <summary>
        /// This value can be applied to the value for a constant.
        /// 
        /// TableDelimiter is the same non-printable ASCII character used
        /// in teletypes and other devices to indicate a new table of data, 
        /// and not likely to be seen in string data.
        /// </summary>
        public static String TableDelimiter
        {
            get
            {
                return ((Char)30).ToString();
            }
        }
    }
}

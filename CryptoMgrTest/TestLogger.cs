using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Jeff.Jones.CryptoMgrTest
{
    public class TestLogger : ILogger
    {
        public IDisposable? BeginScope<TState>(TState state) where TState : notnull
        {
            throw new NotImplementedException();
        }

        public Boolean IsEnabled(LogLevel logLevel)
        {
            return true;
        }

        /// <summary>
        /// 
        /// </summary>
        /// <param name="logLevel">Entry will be written on this level.</param>
        /// <param name="eventId">Id of the event.</param>
        /// <param name="state">The entry to be written. Can be also an object.</param>
        /// <param name="exception">The exception related to this entry.</param>
        /// <param name="formatter">Function to create a <see cref="string"/> message of the <paramref name="state"/> and <paramref name="exception"/>.</param>
        /// <typeparam name="TState">The type of the object to be written.</typeparam>
        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            if (exception == null)
            {
                if (eventId.Id <= 0)
                {
                    Debug.WriteLine($"[{logLevel}] [Test State: {state}]");
                }
                else
                {
                    Debug.WriteLine($"[{logLevel}] [Event ID: {eventId}] [Test State: {state}]");
                }
            }
            else
            {
                if (eventId.Id <= 0)
                {
                    Debug.WriteLine($"[{logLevel}] [Test State: {state}] [{exception.GetType().Name}]");
                }
                else
                {
                    Debug.WriteLine($"[{logLevel}] [Event ID: {eventId}] [Test State: {state}] [{exception.GetType().Name}]");
                }
            }
        }
    }
}

/*
 * Aerospike Backup/Restore Test
 *
 * Copyright (c) 2008-2015 Aerospike, Inc. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy of
 * this software and associated documentation files (the "Software"), to deal in
 * the Software without restriction, including without limitation the rights to
 * use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is furnished to do
 * so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

using System;
using System.IO;
using System.Threading;

namespace Test
{
	public enum LogLevel {
		Debug, Info, Error
	}

	public class Log
	{
		private static string[] LogLevelStrings = { "D", "I", "E" };
		public static LogLevel LogLevel = LogLevel.Debug;
 		private static object Mutex = new object();
 		private string Tag;

		public Log(string tag)
		{
			Tag = tag;
		}

		private void Write(LogLevel logLevel, string message, params object[] args)
		{
			try {
				if (logLevel >= LogLevel) {
					string threadId = (Thread.CurrentThread.ManagedThreadId % 100000).ToString();
					string logLine = String.Format(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") +
							" [" + LogLevelStrings[(int)logLevel] + "]" +
							" [" + "     ".Substring(threadId.Length) + threadId + "]" +
							" [" + "          ".Substring(Tag.Length) + Tag + "] " + message, args);
					lock (Mutex) {
						Console.WriteLine(logLine);
					}
				}
			} catch (Exception) {}
		}

		public void Debug(string message, params object[] args)
		{
			Write(LogLevel.Debug, message, args);
		}

		public void Info(string message, params object[] args)
		{
			Write(LogLevel.Info, message, args);
		}

		public void Error(string message, params object[] args)
		{
			Write(LogLevel.Error, message, args);
		}
	}
}

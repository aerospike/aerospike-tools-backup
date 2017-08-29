/*
 * Aerospike Backup/Restore Test
 *
 * Copyright (c) 2008-2016 Aerospike, Inc. All rights reserved.
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

using Aerospike.Client;

using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;

namespace Test
{
	public class Test
	{
		private delegate Key NextKey();

		private const string WrapperPath = "./asd.sh";
		private const string BackupPath = "../bin/asbackup";
		private const string RestorePath = "../bin/asrestore";
		private const string FillPath = "../bin/fill";
		private const string SpecPath = "../spec.txt";

		private const string BackupFilePath = "test.asb";
		private const string LogFilePathTemplate = "log-{0}.txt";

		private const string Namespace = "test";
		private const int Timeout = 10000;
		private const int RandBinBase = 10000;
		private const int RandBinCount = 250;

		private static Log Log = new Log("Test");
		private static Log WrapperLog = new Log("asd.sh");
		private static Log BackupLog = new Log("asbackup");
		private static Log RestoreLog = new Log("asrestore");
		private static Log FillLog = new Log("fill");

		private static Process asd = null;
		private static AerospikeClient client = null;
		private static WritePolicy writePolicy = null;
		private static Random rand = new Random(0);
		private static int keyBase = 0;
		private static int logCount = 0;
		private static int randBin;

		private static Process StartProcess(string path, string args, Log log)
		{
			Log.Debug("Executing \"{0}\" with arguments \"{1}\"", path, args);
			Process proc = new Process();
			proc.StartInfo.FileName = path;
			proc.StartInfo.Arguments = args;
			proc.StartInfo.CreateNoWindow = true;
			proc.StartInfo.UseShellExecute = false;
			proc.StartInfo.RedirectStandardOutput = true;
			proc.StartInfo.RedirectStandardError = true;
			proc.StartInfo.RedirectStandardInput = true;

			proc.ErrorDataReceived += (object sender, DataReceivedEventArgs line) => {
				if (line.Data != null && line.Data.Length > 0) {
					log.Info("{0}", line.Data);
				}
			};

			proc.OutputDataReceived += (object sender, DataReceivedEventArgs line) => {
				if (line.Data != null && line.Data.Length > 0) {
					log.Info("{0}", line.Data);
				}
			};

			if (!proc.Start()) {
				Log.Error("Error while executing \"{0}\" with arguments \"{1}\"",
						path, args);
				return null;
			}

			proc.BeginOutputReadLine();
			proc.BeginErrorReadLine();
			return proc;
		}

		private static bool WaitForProcess(Process proc)
		{
			Log.Debug("Waiting for process");
			proc.WaitForExit();

			if (proc.ExitCode == 0) {
				Log.Debug("External process indicates success");
				return true;
			}

			Log.Debug("External process indicates failure");
			return false;
		}

		private static bool Execute(string path, string args, Log log)
		{
			Process proc = StartProcess(path, args, log);
			return proc != null && WaitForProcess(proc);
		}

		private static string GetLogPath(int count)
		{
			return String.Format(LogFilePathTemplate, count);
		}

		private static bool StartAsd()
		{
			if (asd != null) {
				Log.Error("Existing asd process");
				return false;
			}

			if (!Execute(WrapperPath, "test", WrapperLog)) {
				return false;
			}

			asd = StartProcess(WrapperPath, "start " + GetLogPath(++logCount), WrapperLog);

			if (asd == null) {
				return false;
			}

			if (!Execute(WrapperPath, "wait", WrapperLog)) {
				asd = null;
				return false;
			}

			Thread.Sleep(2000);
			return true;
		}

		private static bool StopAsd()
		{
			if (asd == null) {
				return true;
			}

			if (!Execute(WrapperPath, "stop", WrapperLog) || !WaitForProcess(asd)) {
				return false;
			}

			asd = null;
			return true;
		}

		private static bool Backup()
		{
			Log.Debug("Backing up");
			return Execute(BackupPath, "-n " + Namespace + " -o " + BackupFilePath, BackupLog);
		}

		private static bool BackupCompact()
		{
			Log.Debug("Backing up (compact)");
			return Execute(BackupPath, "-C -n " + Namespace + " -o " + BackupFilePath, BackupLog);
		}

		private static bool Restore()
		{
			Log.Debug("Restoring");
			return Execute(RestorePath, "-i " + BackupFilePath, RestoreLog);
		}

		private static bool Fill()
		{
			Log.Debug("Filling");
			return Execute(FillPath, "-z -f " + SpecPath + " " + Namespace + " test 10000 test",
					FillLog);
		}

		private static string RandomString(int size, bool allowNul)
		{
			StringBuilder build = new StringBuilder();

			for (int i = 0; i < size; ++i) {
				build.Append(allowNul ? (char)rand.Next() : (char)(rand.Next() % 127 + 1));
			}

			return build.ToString();
		}

		private static byte[] MakeBlob(string input)
		{
			byte[] blob = new byte[input.Length];

			for (int i = 0; i < input.Length; ++i) {
				blob[i] = (byte)input[i];
			}

			return blob;
		}

		private static byte[] RandomBlob(int size)
		{
			byte[] blob = new byte[size];

			for (int i = 0; i < size; ++i) {
				blob[i] = (byte)rand.Next();
			}

			return blob;
		}

		private static Bin[] CreateBins()
		{
			var binList = new List<Bin>();

			binList.Add(new Bin("i-max", 9223372036854775807));
			binList.Add(new Bin("i-min", -9223372036854775808));
			binList.Add(new Bin("i-zero", 0));

			var pos_inf = 1.0 / 0.0;
			var neg_inf = -1.0 / 0.0;
			var nan = pos_inf - pos_inf;

			binList.Add(new Bin("d-pos-inf", pos_inf));
			binList.Add(new Bin("d-neg-inf", neg_inf));
			binList.Add(new Bin("d-nan", nan));
			binList.Add(new Bin("d-basic1", 1.2345));
			binList.Add(new Bin("d-basic2", 1.234567890123456));
			binList.Add(new Bin("d-basic3", -1.2345));
			binList.Add(new Bin("d-basic4", -1.234567890123456));
			binList.Add(new Bin("d-basic5", 1.0));
			binList.Add(new Bin("d-basic6", -1.0));
			binList.Add(new Bin("d-ex1", 0.00000000000000000001));
			binList.Add(new Bin("d-ex2", 100000000000000000000.0));
			binList.Add(new Bin("d-neg-ex1", -0.00000000000000000001));
			binList.Add(new Bin("d-neg-ex2", -100000000000000000000.0));

			while (randBin < RandBinBase + RandBinCount) {
				binList.Add(new Bin(RandomString(14, false), randBin++));
			}

			binList.Add(new Bin("s-10", "ABCDEFGHIJ"));
			binList.Add(new Bin("s-20", "ABCDEFGHIJKLMNOPQRST"));
			binList.Add(new Bin("s-empty", ""));
			binList.Add(new Bin("s-space", "ABCDE: :FGHIJ"));
			binList.Add(new Bin("s-lf", "ABCDE:\n:FGHIJ"));
			binList.Add(new Bin("s-nul", "ABCDE:\x0:FGHIJ"));
			binList.Add(new Bin("s-german", "ABCDE:ÄÖÜäöüß:FGHIJ"));
			binList.Add(new Bin("s-accents", "ABCDE:àáâèéêìíîòóôùúû:FGHIJ"));
			binList.Add(new Bin("s-rand1", RandomString(1000, false)));
			binList.Add(new Bin("s-rand2", RandomString(1000, true)));

			binList.Add(new Bin("b-10", MakeBlob("ABCDEFGHIJ")));
			binList.Add(new Bin("b-20", MakeBlob("ABCDEFGHIJKLMNOPQRST")));
			binList.Add(new Bin("b-empty", new byte[0]));
			binList.Add(new Bin("b-space", MakeBlob("ABCD EFGH")));
			binList.Add(new Bin("b-lf", MakeBlob("ABCD\nEFGH")));
			binList.Add(new Bin("b-nul", MakeBlob("ABCD\x0EFGH")));
			binList.Add(new Bin("b-random", RandomBlob(1000)));

			binList.Add(new Bin("f-0", 0.0));
			binList.Add(new Bin("f-1.23", 1.23));
			binList.Add(new Bin("f--2.34", -2.34));

			var listVal = new List<int>();

			for (int i = 0; i < 10; ++i) {
				listVal.Add(i);
			}

			var mapVal = new Dictionary<int, string>();

			for (int i = 0; i < 10; ++i) {
				mapVal[i] = "ABCDEFGHIJ";
			}

			binList.Add(new Bin("list-10", listVal));
			binList.Add(new Bin("map-10", mapVal));
			return binList.ToArray();
		}

		private static void PutRecords(Dictionary<Key, Bin[]> data, int count, NextKey nextKey,
				bool sendKey)
		{
			writePolicy.sendKey = sendKey;

			for (int i = 0; i < 3; ++i) {
				writePolicy.expiration = i == 0 ? -1 : i * 1000;

				for (int k = 0; k < count; ++k) {
					Key key = nextKey();
					Bin[] bins = CreateBins();
					data[key] = bins;
					client.Put(writePolicy, key, bins);
				}
			}
		}

		private static void PutRecords(Dictionary<Key, Bin[]> data, string set, bool sendKey)
		{
			PutRecords(data, 10, () => {
				return new Key(Namespace, set, keyBase++);
			}, sendKey);

			PutRecords(data, 10, () => {
				return new Key(Namespace, set, "s-" + keyBase++);
			}, sendKey);

			PutRecords(data, 10, () => {
				return new Key(Namespace, set, MakeBlob("b-" + keyBase++));
			}, sendKey);
		}

		private static void PutRecords(Dictionary<Key, Bin[]> data, string set)
		{
			PutRecords(data, set, true);
			PutRecords(data, set, false);

			PutRecords(data, 1, () => {
				return new Key(Namespace, set, 9223372036854775807);
			}, true);

			PutRecords(data, 1, () => {
				return new Key(Namespace, set, -9223372036854775808);
			}, true);
		}

		private static Dictionary<Key, Bin[]> PutRecords()
		{
			Log.Info("Writing records");
			randBin = RandBinBase;
			var data = new Dictionary<Key, Bin[]>();
			PutRecords(data, "test");

			for (int i = 0; i < 100; ++i) {
				PutRecords(data, RandomString(63, false));
			}

			return data;
		}

		private static Dictionary<Key, Record> GetRecords()
		{
			Log.Info("Reading records");
			var recs = new Dictionary<Key, Record>();

			client.ScanAll(null, Namespace, null, (Key key, Record rec) => {
				recs[key] = rec;
			});

			return recs;
		}

		private static bool CheckKeys<K, V1, V2>(Dictionary<K, V1> dict1, Dictionary<K, V2> dict2)
		{
			bool ok = true;

			foreach (K key in dict1.Keys) {
				if (!dict2.ContainsKey(key)) {
					Log.Error("Missing key in 2nd map: {0}", key);
					ok = false;
				}
			}

			foreach (K key in dict2.Keys) {
				if (!dict1.ContainsKey(key)) {
					Log.Error("Missing key in 1st map: {0}", key);
					ok = false;
				}
			}

			return ok;
		}

		private static Value ObjectToValue(object obj)
		{
			if (obj is byte[]) {
				return Value.Get((byte[])obj);
			}

			if (obj is IList) {
				return Value.Get((IList)obj);
			}

			if (obj is IDictionary) {
				return Value.Get((IDictionary)obj);
			}

			if (obj is Double && Double.IsNaN((Double)obj)) {
				obj = Double.NaN;
			}

			return Value.Get(obj);
		}

		private static byte[] ValueToBlob(Value val)
		{
			int len = val.EstimateSize();
			byte[] blob = new byte[len];
			val.Write(blob, 0);
			return blob;
		}

		private static byte[] BinToBlob(Bin bin)
		{
			return ValueToBlob(bin.value);
		}

		private static byte[] ObjectToBlob(object obj)
		{
			return ValueToBlob(ObjectToValue(obj));
		}

		private static bool Compare(Dictionary<Key, Bin[]> data, Dictionary<Key, Record> recs)
		{
			Log.Info("Comparing record data");

			if (!CheckKeys(data, recs)) {
				return false;
			}

			bool ok = true;

			foreach (Key key in data.Keys) {
				foreach (Bin bin in data[key]) {
					string name = bin.name;

					if (!recs[key].bins.ContainsKey(name)) {
						Log.Error("Missing bin for key {0}: {1}", key, name);
						ok = false;
					} else {
						byte[] dataBlob = BinToBlob(bin);
						byte[] recBlob = ObjectToBlob(recs[key].bins[name]);

						if (!dataBlob.SequenceEqual(recBlob)) {
							Log.Error("Data mismatch for key {0}, bin {1}", key, name);
							ok = false;
						}
					}
				}
			}

			return ok;
		}

		private static bool Compare(Dictionary<Key, Record> recs1, Dictionary<Key, Record> recs2)
		{
			Log.Info("Comparing records");

			if (!CheckKeys(recs1, recs2)) {
				return false;
			}

			bool ok = true;
			var lookup = new Dictionary<Key, Key>();

			foreach (Key key in recs1.Keys) {
				lookup[key] = key;
			}

			foreach (Key key2 in recs2.Keys) {
				Key key1 = lookup[key2];

				if ((key1.userKey == null) != (key2.userKey == null)) {
					Log.Error("User key mismatch [1] for key {0}", key1);
					ok = false;
				}

				if (key1.userKey != null) {
					byte[] keyBlob1 = ValueToBlob(key1.userKey);
					byte[] keyBlob2 = ValueToBlob(key2.userKey);

					if (!keyBlob1.SequenceEqual(keyBlob2)) {
						Log.Error("User key mismatch [2] for key {0}", key1);
						ok = false;
					}
				}
			}

			foreach (Key key in recs1.Keys) {
				Record rec1 = recs1[key];
				Record rec2 = recs2[key];

				int expDiff = rec1.expiration - rec2.expiration;

				if (expDiff < -3 || expDiff > 3) {
					Log.Error("Expiration mismatch for key {0}: {1} vs. {2}", key, rec1.expiration,
							rec2.expiration);
					ok = false;
				}

				if (!CheckKeys(rec1.bins, rec2.bins)) {
					ok = false;
					continue;
				}

				foreach (string name in rec1.bins.Keys) {
					byte[] recBlob1 = ObjectToBlob(rec1.bins[name]);
					byte[] recBlob2 = ObjectToBlob(rec2.bins[name]);

					if (!recBlob1.SequenceEqual(recBlob2)) {
						Log.Error("Data mismatch for key {0}, bin {1}", key, name);
						ok = false;
					}
				}
			}

			return ok;
		}

		private static void OpenClient()
		{
			if (client == null) {
				client = new AerospikeClient("127.0.0.1", 3000);
				writePolicy = new WritePolicy();
				writePolicy.timeout = Timeout;
			}
		}

		private static void CloseClient()
		{
			if (client != null) {
				client.Close();
			}

			client = null;
			writePolicy = null;
		}

		private static void RemoveBackup()
		{
			Log.Debug("Removing backup file");
			File.Delete(BackupFilePath);
		}

		private static void RemoveLogs(int logCount)
		{
			Log.Debug("Removing log files");

			for (int i = 1; i <= logCount; ++i) {
				File.Delete(GetLogPath(i));
			}
		}

		private static bool RunTest1()
		{
			Log.Info("*** Running test 1 ***");

			try {
				if (!StartAsd()) {
					return false;
				}

				OpenClient();
				var data = PutRecords();
				var recs1 = GetRecords();

				if (!Compare(data, recs1)) {
					return false;
				}

				var recs2 = GetRecords();

				if (!Compare(recs1, recs2)) {
					return false;
				}

				CloseClient();

				if (!Backup()) {
					return false;
				}

				if (!StopAsd()) {
					return false;
				}

				if (!StartAsd()) {
					return false;
				}

				if (!Restore()) {
					return false;

				}

				OpenClient();
				var recs3 = GetRecords();
				CloseClient();

				if (!Compare(recs2, recs3)) {
					return false;
				}

				RemoveBackup();

				if (!BackupCompact()) {
					return false;
				}

				if (!StopAsd()) {
					return false;
				}

				if (!StartAsd()) {
					return false;
				}

				if (!Restore()) {
					return false;
				}

				OpenClient();
				var recs4 = GetRecords();

				if (!Compare(recs4, recs3)) {
					return false;
				}

				RemoveBackup();
				return true;
			} finally {
				CloseClient();
				StopAsd();
			}
		}

		private static bool RunTest2()
		{
			Log.Info("*** Running test 2 ***");

			try {
				if (!StartAsd()) {
					return false;
				}

				if (!Fill()) {
					return false;
				}

				OpenClient();
				var recs1 = GetRecords();
				CloseClient();

				if (!Backup()) {
					return false;
				}

				if (!StopAsd()) {
					return false;
				}

				if (!StartAsd()) {
					return false;
				}

				if (!Restore()) {
					return false;

				}

				OpenClient();
				var recs2 = GetRecords();
				CloseClient();

				if (!Compare(recs1, recs2)) {
					return false;
				}

				RemoveBackup();

				if (!BackupCompact()) {
					return false;
				}

				if (!StopAsd()) {
					return false;
				}

				if (!StartAsd()) {
					return false;
				}

				if (!Restore()) {
					return false;
				}

				OpenClient();
				var recs3 = GetRecords();

				if (!Compare(recs3, recs2)) {
					return false;
				}

				RemoveBackup();
				return true;
			} finally {
				CloseClient();
				StopAsd();
			}
		}

		public static int Main(string[] args)
		{
			Log.LogLevel = LogLevel.Info;
			RemoveBackup();
			RemoveLogs(10);

			try {
				if (!RunTest1()) {
					Log.Error("*** Test 1 failed ***");
					return 1;
				} else {
					Log.Info("*** Test 1 OK ***");
				}

				if (!RunTest2()) {
					Log.Error("*** Test 2 failed ***");
					return 1;
				} else {
					Log.Info("*** Test 2 OK ***");
				}

				RemoveLogs(logCount);
			} finally {
				CloseClient();
				StopAsd();
			}

			return 0;
		}
	}
}

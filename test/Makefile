#
# Aerospike Backup/Restore Test
#
# Copyright (c) 2008-2015 Aerospike, Inc. All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a copy of
# this software and associated documentation files (the "Software"), to deal in
# the Software without restriction, including without limitation the rights to
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
# of the Software, and to permit persons to whom the Software is furnished to do
# so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#

NEO_LUA_URL :=			http://packages.nuget.org/api/v1/package/NeoLua/0.9.15
CLIENT_DIR :=			../../../aerospike-client-csharp/AerospikeClient

CLIENT_SRCS :=			$(wildcard $(CLIENT_DIR)/*/*.cs)

all:
						@echo "Please run \"make tests\" in the root directory instead."

Test.exe:				Log.cs Test.cs Aerospike.Client.dll
						mcs -out:Test.exe -pkg:dotnet -r:Aerospike.Client -debug Log.cs Test.cs

Aerospike.Client.dll:	$(CLIENT_SRCS) Neo.Lua.dll
						mcs -out:Aerospike.Client.dll -target:library -pkg:dotnet \
								-r:Neo.Lua -r:System.Numerics -debug $(CLIENT_SRCS)

Neo.Lua.zip:
						wget --output-document Neo.Lua.zip $(NEO_LUA_URL)

Neo.Lua.dll:			Neo.Lua.zip
						unzip -j Neo.Lua.zip lib/net4/Neo.Lua.dll lib/net4/Neo.Lua.pdb
						touch Neo.Lua.dll Neo.Lua.pdb

test-cs:				Test.exe
						mono --debug ./Test.exe

clean:
						rm -f Test.exe Test.exe.mdb Aerospike.Client.dll Aerospike.Client.dll.mdb \
								Neo.Lua.zip Neo.Lua.dll Neo.Lua.pdb \
								log-*.txt test.asb

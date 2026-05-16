/*
 * Aerospike Asbackup Logger
 *
 * Copyright (c) 2022 Aerospike, Inc. All rights reserved.
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

#pragma once

//==========================================================
// Includes.
//

#include <aws/core/utils/logging/ConsoleLogSystem.h>


//==========================================================
// Class Declarations.
//

class AsbackupLogger : public Aws::Utils::Logging::LogSystemInterface {
public:

	AsbackupLogger(Aws::Utils::Logging::LogLevel logLevel);

	virtual ~AsbackupLogger();

	/**
	 * Gets the currently configured log level.
	 */
	virtual Aws::Utils::Logging::LogLevel GetLogLevel(void) const override;

	/**
	 * Set a new log level. This has the immediate effect of changing the log output to the new level.
	 */
	void SetLogLevel(Aws::Utils::Logging::LogLevel logLevel);

	void Flush() override;

	/*
	 * Does a printf style output to ProcessFormattedStatement. Don't use this, it's unsafe. See LogStream
	 */
	virtual void Log(Aws::Utils::Logging::LogLevel logLevel,
			const char* tag, const char* formatStr, ...) override;

	/*
	 * Writes the stream to ProcessFormattedStatement.
	 */
	virtual void LogStream(Aws::Utils::Logging::LogLevel logLevel,
			const char* tag, const Aws::OStringStream &messageStream) override;

private:
	std::atomic<Aws::Utils::Logging::LogLevel> m_logLevel;

	static const char* GetLogCategory(Aws::Utils::Logging::LogLevel logLevel);

};

/*
 * Copyright 2022 Aerospike, Inc.
 *
 * Portions may be licensed to Aerospike, Inc. under one or more contributor
 * license agreements.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

 
//==========================================================
// Includes.
//

#include <asbackup_logger.h>

#include <cstdarg>

#include <utils.h>


//==========================================================
// Class Definitions.
//

AsbackupLogger::AsbackupLogger(Aws::Utils::Logging::LogLevel logLevel) :
		m_logLevel(logLevel) {}

AsbackupLogger::~AsbackupLogger() {}

Aws::Utils::Logging::LogLevel
AsbackupLogger::GetLogLevel(void) const
{
	return m_logLevel.load();
}

void
AsbackupLogger::SetLogLevel(Aws::Utils::Logging::LogLevel logLevel)
{
	m_logLevel.store(logLevel);
}

void
AsbackupLogger::Flush()
{
	fflush(stderr);
}

void AsbackupLogger::Log(Aws::Utils::Logging::LogLevel logLevel,
		const char* tag, const char* formatStr, ...)
{
	std::va_list args;
	va_start(args, formatStr);

	Aws::StringStream ss;
	ss << "[" << tag << "] ";
	log_line(GetLogCategory(logLevel), ss.str().c_str(), formatStr, args, false);
	va_end(args);
}

void
AsbackupLogger::LogStream(Aws::Utils::Logging::LogLevel logLevel,
		const char* tag, const Aws::OStringStream &messageStream)
{
	Log(logLevel, tag, "%s", messageStream.str().c_str());
}

const char*
AsbackupLogger::GetLogCategory(Aws::Utils::Logging::LogLevel logLevel)
{
	switch(logLevel) {
		case Aws::Utils::Logging::LogLevel::Error:
			return "AWS ERROR";

		case Aws::Utils::Logging::LogLevel::Fatal:
			return "AWS FATAL";

		case Aws::Utils::Logging::LogLevel::Warn:
			return "AWS WARN ";

		case Aws::Utils::Logging::LogLevel::Info:
			return "AWS INFO ";

		case Aws::Utils::Logging::LogLevel::Debug:
			return "AWS DEBUG";

		case Aws::Utils::Logging::LogLevel::Trace:
			return "AWS TRACE";

		default:
			return "AWS UNKOWN";
	}
}


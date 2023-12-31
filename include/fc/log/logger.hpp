#pragma once
#include <fc/string.hpp>
#include <fc/time.hpp>
#include <fc/log/log_message.hpp>

// define `SPDLOG_ACTIVE_LEVEL` before including spdlog.h as per https://github.com/gabime/spdlog/issues/1268
#define SPDLOG_ACTIVE_LEVEL SPDLOG_LEVEL_TRACE
#define SPDLOG_LEVEL_NAMES { "trace", "debug", "info", "warn", "error", "crit", "off" }

#include <spdlog/spdlog.h>
#include <spdlog/sinks/stdout_sinks.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/daily_file_sink.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/fmt/fmt.h>

#ifndef DEFAULT_LOGGER
#define DEFAULT_LOGGER "default"
#endif

namespace fc
{
   #ifndef DEFAULT_PATTERN
   #define DEFAULT_PATTERN "%^%-5l %Y-%m-%dT%T.%f %-9!k %20!s:%-5# %-20!!] %v%$"
   #endif

   /**
    *
    *
    @code
       void my_class::func()
      {
         fc_dlog( my_class_logger, "Format four: {arg}  five: {five}", ("arg",4)("five",5) );
      }
    @endcode
    */
   class logger 
   {
      public:
         static logger get( const fc::string& name = DEFAULT_LOGGER );
         static void update( const fc::string& name, logger& log );

         logger();
         logger( const string& name, const logger& parent = nullptr );
         logger( std::nullptr_t );
         logger( const logger& c );
         logger( logger&& c );
         ~logger();
         logger& operator=(const logger&);
         logger& operator=(logger&&);
         friend bool operator==( const logger&, nullptr_t );
         friend bool operator!=( const logger&, nullptr_t );

         logger&    set_log_level( log_level e );
         log_level  get_log_level()const;
         std::unique_ptr<spdlog::logger>& get_agent_logger()const;
         void update_agent_logger(std::unique_ptr<spdlog::logger>&& al);

         void  set_name( const fc::string& n );
         const fc::string& name()const;

         bool is_enabled( log_level e )const;
         void log( log_message m );

      private:
         friend struct log_config;
         void add_sink(const std::shared_ptr<spdlog::sinks::sink>& s);
         std::vector<std::shared_ptr<spdlog::sinks::sink>>& get_sinks() const;

      private:
         class impl;
         std::shared_ptr<impl> my;
   };

} // namespace fc

// suppress warning "conditional expression is constant" in the while(0) for visual c++
// http://cnicholson.net/2009/03/stupid-c-tricks-dowhile0-and-c4127/
#define FC_MULTILINE_MACRO_BEGIN do {
#ifdef _MSC_VER
# define FC_MULTILINE_MACRO_END \
    __pragma(warning(push)) \
    __pragma(warning(disable:4127)) \
    } while (0) \
    __pragma(warning(pop))
#else
# define FC_MULTILINE_MACRO_END  } while (0)
#endif

#define FC_LOG_CATCH \
   catch( const std::exception & ex ) { \
      std::cerr<< "<" + std::string(__FILE__) + ":" + std::to_string(__LINE__) + "  " + ex.what() + ">" <<std::endl; \
   } catch( ... ) { \
      std::cerr<< "<" + std::string(__FILE__) + ":" + std::to_string(__LINE__) + "  " + "Failed to log this message" + ">" <<std::endl; \
   }

#define fc_dlog_1( LOGGER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( (LOGGER).is_enabled( fc::log_level::debug ) ) \
      try{ \
         SPDLOG_LOGGER_DEBUG((LOGGER).get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ )); \
      } FC_LOG_CATCH \
  FC_MULTILINE_MACRO_END

#define fc_dlog_0( LOGGER, FORMAT ) fc_dlog_1( LOGGER, FORMAT, )
#define fc_dlog(...) SWITCH_MACRO1(fc_dlog_0, fc_dlog_1, 2, __VA_ARGS__)

#define fc_ilog_1( LOGGER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( (LOGGER).is_enabled( fc::log_level::info ) ) \
      try{ \
         SPDLOG_LOGGER_INFO((LOGGER).get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ )); \
      } FC_LOG_CATCH \
  FC_MULTILINE_MACRO_END

// this is to deal with -Wgnu-zero-variadic-macro-arguments
#define fc_ilog_0( LOGGER, FORMAT ) fc_ilog_1( LOGGER, FORMAT, )
#define fc_ilog(...) SWITCH_MACRO1(fc_ilog_0, fc_ilog_1, 2, __VA_ARGS__)

#define fc_wlog_1( LOGGER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( (LOGGER).is_enabled( fc::log_level::warn ) ) \
      try{ \
         SPDLOG_LOGGER_WARN((LOGGER).get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ )); \
      } FC_LOG_CATCH \
  FC_MULTILINE_MACRO_END

#define fc_wlog_0( LOGGER, FORMAT ) fc_wlog_1( LOGGER, FORMAT, )
#define fc_wlog(...) SWITCH_MACRO1(fc_wlog_0, fc_wlog_1, 2, __VA_ARGS__)

#define fc_elog_1( LOGGER, FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( (LOGGER).is_enabled( fc::log_level::error ) ) \
      try{ \
         SPDLOG_LOGGER_ERROR((LOGGER).get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ )); \
      } FC_LOG_CATCH \
  FC_MULTILINE_MACRO_END

#define fc_elog_0( LOGGER, FORMAT ) fc_elog_1(LOGGER, FORMAT,)
#define fc_elog(...) SWITCH_MACRO1(fc_elog_0, fc_elog_1, 2, __VA_ARGS__)

#define dlog_1( FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( (fc::logger::get(DEFAULT_LOGGER)).is_enabled( fc::log_level::debug ) ) \
      try{ \
         SPDLOG_LOGGER_DEBUG((fc::logger::get(DEFAULT_LOGGER)).get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ )); \
      } FC_LOG_CATCH \
  FC_MULTILINE_MACRO_END

#define dlog_0(FORMAT) dlog_1(FORMAT,)
#define dlog(...) SWITCH_MACRO1(dlog_0, dlog_1, 1, __VA_ARGS__)

#define ilog_1( FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( (fc::logger::get(DEFAULT_LOGGER)).is_enabled( fc::log_level::info ) ) \
      try{ \
         SPDLOG_LOGGER_INFO((fc::logger::get(DEFAULT_LOGGER)).get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ )); \
      } FC_LOG_CATCH \
  FC_MULTILINE_MACRO_END

#define ilog_0(FORMAT) ilog_1(FORMAT,)
#define ilog(...) SWITCH_MACRO1(ilog_0, ilog_1, 1, __VA_ARGS__)

#define wlog_1( FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( (fc::logger::get(DEFAULT_LOGGER)).is_enabled( fc::log_level::warn ) ) \
      try{ \
         SPDLOG_LOGGER_WARN((fc::logger::get(DEFAULT_LOGGER)).get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ )); \
      } FC_LOG_CATCH \
  FC_MULTILINE_MACRO_END

#define wlog_0(FORMAT) wlog_1(FORMAT,)
#define wlog(...) SWITCH_MACRO1(wlog_0, wlog_1, 1, __VA_ARGS__)

#define elog_1( FORMAT, ... ) \
  FC_MULTILINE_MACRO_BEGIN \
   if( (fc::logger::get(DEFAULT_LOGGER)).is_enabled( fc::log_level::error ) ) \
      try{ \
         SPDLOG_LOGGER_ERROR((fc::logger::get(DEFAULT_LOGGER)).get_agent_logger(), FC_FMT( FORMAT, __VA_ARGS__ )); \
      } FC_LOG_CATCH \
  FC_MULTILINE_MACRO_END

// this is to deal with -Wgnu-zero-variadic-macro-arguments
#define elog_0(FORMAT) elog_1(FORMAT,)
#define elog(...) SWITCH_MACRO1(elog_0, elog_1, 1, __VA_ARGS__)

#include <boost/preprocessor/seq/for_each.hpp>
#include <boost/preprocessor/seq/enum.hpp>
#include <boost/preprocessor/seq/size.hpp>
#include <boost/preprocessor/seq/seq.hpp>
#include <boost/preprocessor/stringize.hpp>
#include <boost/preprocessor/punctuation/paren.hpp>


#define FC_FORMAT_ARG(r, unused, base) \
  BOOST_PP_STRINGIZE(base) ": {" BOOST_PP_STRINGIZE( base ) "} "

#define FC_FORMAT_ARGS(r, unused, base) \
  BOOST_PP_LPAREN() BOOST_PP_STRINGIZE(base), base BOOST_PP_RPAREN()

#define FC_FORMAT( SEQ )\
    BOOST_PP_SEQ_FOR_EACH( FC_FORMAT_ARG, v, SEQ ) 

// takes a ... instead of a SEQ arg because it can be called with an empty SEQ 
// from FC_CAPTURE_AND_THROW()
#define FC_FORMAT_ARG_PARAMS( ... )\
    BOOST_PP_SEQ_FOR_EACH( FC_FORMAT_ARGS, v, __VA_ARGS__ ) 

#define idump( SEQ ) \
    ilog( FC_FORMAT(SEQ), FC_FORMAT_ARG_PARAMS(SEQ) )  
#define wdump( SEQ ) \
    wlog( FC_FORMAT(SEQ), FC_FORMAT_ARG_PARAMS(SEQ) )  
#define edump( SEQ ) \
    elog( FC_FORMAT(SEQ), FC_FORMAT_ARG_PARAMS(SEQ) )  

// this disables all normal logging statements -- not something you'd normally want to do,
// but it's useful if you're benchmarking something and suspect logging is causing
// a slowdown.
#ifdef FC_DISABLE_LOGGING
# undef elog
# define elog(...) FC_MULTILINE_MACRO_BEGIN FC_MULTILINE_MACRO_END
# undef wlog
# define wlog(...) FC_MULTILINE_MACRO_BEGIN FC_MULTILINE_MACRO_END
# undef ilog
# define ilog(...) FC_MULTILINE_MACRO_BEGIN FC_MULTILINE_MACRO_END
# undef dlog
# define dlog(...) FC_MULTILINE_MACRO_BEGIN FC_MULTILINE_MACRO_END
#endif
#include <fc/log/log_message.hpp>
#include <fc/exception/exception.hpp>
#include <fc/variant.hpp>
#include <fc/time.hpp>
#include <fc/filesystem.hpp>
#include <fc/io/json.hpp>

namespace fc
{
   const string& get_thread_name();
   namespace detail
   {
      class log_context_impl
      {
         public:
            log_level level;
            string       file;
            uint64_t     line;
            string       method;
            string       thread_name;
            string       task_name;
            string       hostname;
            string       context;
            time_point   timestamp;
      };

      class log_message_impl
      {
         public:
            log_message_impl( log_context&& ctx )
            :context( std::move(ctx) ){}
            log_message_impl(){}

            log_context     context;
            string          msg;
      };
   }



   log_context::log_context()
   :my( std::make_shared<detail::log_context_impl>() ){}

   log_context::log_context( log_level ll, const char* file, uint64_t line, 
                                            const char* method )
   :my( std::make_shared<detail::log_context_impl>() )
   {
      my->level       = ll;
      my->file        = fc::path(file).filename().generic_string(); // TODO truncate filename
      my->line        = line;
      my->method      = method;
      my->timestamp   = time_point::now();
      my->thread_name = fc::get_thread_name();
   }

   log_context::log_context( const variant& v )
   :my( std::make_shared<detail::log_context_impl>() )
   {
       auto obj = v.get_object();
       my->level        = obj["level"].as<log_level>();
       my->file         = obj["file"].as_string();
       my->line         = obj["line"].as_uint64();
       my->method       = obj["method"].as_string();
       my->hostname     = obj["hostname"].as_string();
       my->thread_name  = obj["thread_name"].as_string();
       if (obj.contains("task_name"))
         my->task_name    = obj["task_name"].as_string();
       my->timestamp    = obj["timestamp"].as<time_point>();
       if( obj.contains( "context" ) )
           my->context      = obj["context"].as<string>();
   }

   fc::string log_context::to_string()const
   {
      return my->thread_name + "  " + my->file + ":" + fc::to_string(my->line) + " " + my->method;

   }

   void log_context::append_context( const fc::string& s )
   {
        if (!my->context.empty())
          my->context += " -> ";
        my->context += s;
   }

   log_context::~log_context(){}


   void to_variant( const log_context& l, variant& v )
   { 
      v = l.to_variant();     
   }

   void from_variant( const variant& l, log_context& c )
   { 
        c = log_context(l); 
   }

   void from_variant( const variant& l, log_message& c )
   {
        c = log_message(l);
   }
   void to_variant( const log_message& m, variant& v )
   {
        v = m.to_variant();
   }

   void  to_variant( log_level e, variant& v )
   {
      switch( e )
      {
        case log_level::all: 
           v = "all";
           return;
        case log_level::debug:
           v = "debug";
           return;
        case log_level::info:
           v = "info";
           return;
        case log_level::warn:
           v = "warn";
           return;
        case log_level::error:
           v = "error";
           return;
        case log_level::off:
           v = "off";
           return;
      }
   }
   void from_variant( const variant& v, log_level& e )
   {
      try 
      {
        if( v.as_string() == "all" ) e = log_level::all;
        else if( v.as_string() == "debug" ) e = log_level::debug;
        else if( v.as_string() == "info" ) e = log_level::info;
        else if( v.as_string() == "warn" ) e = log_level::warn;
        else if( v.as_string() == "error" ) e = log_level::error;
        else if( v.as_string() == "off" ) e = log_level::off;
        else FC_THROW_EXCEPTION( bad_cast_exception, "Failed to cast from Variant to log_level" );
      } FC_RETHROW_EXCEPTIONS( error, 
                                   "Expected 'all|debug|info|warn|error|off', but got '{variant}'",
                                   ("variant", fc::json::to_string(v, fc::time_point::now() + fc::exception::format_time_limit)) );
   }

   string log_level::to_string()const {
      switch( value )
      {
         case log_level::all:
            return "all";
         case log_level::debug:
            return "debug";
         case log_level::info:
            return "info";
         case log_level::warn:
            return "warn";
         case log_level::error:
            return "error";
         case log_level::off:
            return "off";
      }
      return "unknown";
   }

   string     log_context::get_file()const       { return my->file; }
   uint64_t   log_context::get_line_number()const { return my->line; }
   string     log_context::get_method()const     { return my->method; }
   string     log_context::get_thread_name()const { return my->thread_name; }
   string     log_context::get_task_name()const { return my->task_name; }
   string     log_context::get_host_name()const   { return my->hostname; }
   time_point  log_context::get_timestamp()const  { return my->timestamp; }
   log_level  log_context::get_log_level()const{ return my->level;   }
   string     log_context::get_context()const   { return my->context; }


   variant log_context::to_variant()const
   {
      mutable_variant_object o;
              o( "level",        variant(my->level)      )
               ( "file",         my->file                )
               ( "line",         my->line                )
               ( "method",       my->method              )
               ( "hostname",     my->hostname            )
               ( "thread_name",  my->thread_name         )
               ( "timestamp",    variant(my->timestamp)  );

      if( my->context.size() ) 
         o( "context",      my->context             );

      return o;
   }

   log_message::~log_message(){}
   log_message::log_message()
   :my( std::make_shared<detail::log_message_impl>() ){}

   log_message::log_message( log_context ctx, std::string msg)
   :my( std::make_shared<detail::log_message_impl>(std::move(ctx)) )
   {
      my->msg = std::move(msg);
   }

   log_message::log_message( const variant& v )
   :my( std::make_shared<detail::log_message_impl>( log_context( v.get_object()["context"] ) ) )
   {
      my->msg    = v.get_object()["msg"].as_string();
   }

   variant log_message::to_variant()const
   {
      return mutable_variant_object( "context", my->context )
                             ("msg", my->msg);
   }

   log_context log_message::get_context()const { return my->context; }

   string log_message::get_message()const
   {
      return my->msg;
   }

   constexpr size_t minimize_max_size = 1024;

   string log_message::get_limited_message()const
   {
      return my->msg.substr(0, minimize_max_size) + "...";
   }

} // fc


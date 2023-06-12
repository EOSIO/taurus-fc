#pragma once

#include <boost/container/flat_set.hpp>
#include <fc/exception/exception.hpp>
#include <fc/io/json.hpp>
#include <spdlog/spdlog.h>
#include <memory>

namespace fmt {
   template<typename T>
   struct formatter<boost::container::flat_set<T>> {
      template<typename ParseContext>
      constexpr auto parse( ParseContext& ctx ) { return ctx.begin(); }

      template<typename FormatContext>
      auto format( const boost::container::flat_set<T>& p, FormatContext& ctx ) {
         for (const auto& i : p) {
            fmt::formatter<T>().format(i, ctx);
         }
         return format_to( ctx.out());
      }
   };

   template<typename T>
   struct formatter<std::shared_ptr<T>> {
      template<typename ParseContext>
      constexpr auto parse( ParseContext& ctx ) { return ctx.begin(); }

      template<typename FormatContext>
      auto format( const std::shared_ptr<T>& p, FormatContext& ctx ) {
         if (p)
            return fmt::formatter<T>().format(*p, ctx);
         else
            return format_to( ctx.out(), "{}", "null");
      }
   };

   template<>
   struct formatter<fc::exception> {
      template<typename ParseContext>
      constexpr auto parse( ParseContext& ctx ) { return ctx.begin(); }

      template<typename FormatContext>
      auto format( const fc::exception& p, FormatContext& ctx ) {
         try {
            return format_to( ctx.out(), "{}", p.to_detail_string());
         } catch (...) {
            int line = __LINE__;
            std::string file = __FILE__;
            return format_to(ctx.out(), "{}", "< error formatting " + fc::path(file).filename().generic_string() + ":" + std::to_string(line) + " >");
         }
      }
   };
}
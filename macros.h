#ifndef SIPP_MACROS_H
#define SIPP_MACROS_H

#if defined _WIN32 || defined __CYGWIN__
  #ifdef BUILDING_DLL
    #ifdef __GNUC__
      #define SIPP_PUBLIC __attribute__((dllexport))
    #else
      #define SIPP_PUBLIC __declspec(dllexport)
    #endif
  #else
    #ifdef __GNUC__
      #define SIPP_PUBLIC __attribute__((dllimport))
    #else
      #define SIPP_PUBLIC __declspec(dllimport)
    #endif
  #endif
  #define SIPP_LOCAL
#else
  #if __GNUC__ >= 4
    #define SIPP_PUBLIC __attribute__((visibility("default")))
    #define SIPP_LOCAL  __attribute__((visibility("hidden")))
  #else
    #define SIPP_PUBLIC
    #define SIPP_LOCAL
  #endif
#endif

#define CR '\r'
#define LF '\n'

#endif

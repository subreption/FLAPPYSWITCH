#ifndef _DEBUG_H
#define _DEBUG_H

#ifdef DEBUG
  #include <stdio.h>
  #include <unistd.h>

  void log_info(void *drawer, const char *fmt, ...);

  #define debug_perror(...)  perror(__VA_ARGS__)
  #define debug_fprintf(fp, fmt, ...) fprintf(fp, "[LOADER][pid:%d] " fmt, getpid(), ##__VA_ARGS__)
#else
  #define log_info(...)      ((void)0)
  #define debug_perror(...)  ((void)0)
  #define debug_fprintf(...) ((void)0)
#endif


#endif

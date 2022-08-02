/*****************************************************************************
*  Copyright 2011 Sergey Shekyan
*
*  Licensed under the Apache License, Version 2.0 (the "License");
*  you may not use this file except in compliance with the License.
*  You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
* *****************************************************************************/

/*****
 * Author: Sergey Shekyan shekyan@gmail.com
 *         Victor Agababov vagababov@gmail.com
 *
 * Slow HTTP attack  vulnerability test tool
 *  https://github.com/shekyan/slowhttptest
 *****/


#include <ctime>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "slowurl.h"
#include "slowlog.h"

using namespace slowhttptest;

extern  int proxy_cnt;
extern Proxy proxy_All[1024];

namespace {
static FILE* log_file = NULL;
int current_log_level;
static FILE* proxy_file = NULL;
}

namespace slowhttptest {




void slowproxy_init(const char* file_name) {

 int nchars,  nlines;

 char c[60]="123456"; char gc;

// char*p;

 proxy_file = file_name == NULL ? stdout : fopen(file_name, "r");
  if(!proxy_file) {
    printf("Unable to open proxy_file file %s for writing: %s", file_name,
           strerror(errno));
  }
  else
  	{	nchars=nlines=0;
		while((gc=getc(proxy_file))!=EOF){
			 if (gc!='\n')
				 {c[nchars++]=gc;}
			 else{c[nchars++]='\0';
				 if (nchars>3) {
					 proxy_All[nlines].prepare(c);
					/*  p=strtok(c,":");
					  strcpy(proxyAll[nlines].ip,p);
					  p=strtok(NULL,",");
					  strcpy(proxyAll[nlines].port,p);*/
					  nchars=0;
					  nlines++;
					 }
			 }
		}

  	proxy_cnt=nlines;
  	printf("get %d\n",proxy_cnt);
  //	for (i=0;i<proxy_cnt;i++)
  //	{printf("getss--- %s- %s\n",proxyAll[i].ip,proxyAll[i].port);}

    fclose(proxy_file);
  	}



}



void slowlog_init(int debug_level, const char* file_name) {
  log_file = file_name == NULL ? stdout : fopen(file_name, "w");
  if(!log_file) {
    printf("Unable to open log file %s for writing: %s", file_name,
           strerror(errno));
  }
  current_log_level = debug_level;
}

void check(bool f, const char* message) {
  if (!f) {
    fprintf(log_file, "%s\n", message);
    fflush(log_file);
    exit(1);
  }   
}

void log_fatal(const char* format, ...) {
  const time_t  now = time(NULL);
  char ctimebuf[32];
  const char* buf = ctime_r(&now, ctimebuf);

  fprintf(log_file, "%-.24s FATAL:", buf);

  va_list va;
  va_start(va, format);
  vfprintf(log_file, format, va);
  va_end(va);
  fflush(log_file);
  exit(1);
}

void slowlog(int lvl, const char* format, ...) {
  if(lvl <= current_log_level || lvl == LOG_FATAL) {
    const time_t now = time(NULL);
    char ctimebuf[32];
    const char* buf = ctime_r(&now, ctimebuf);

    fprintf(log_file, "%-.24s:", buf);

    va_list va;
    va_start(va, format);
    vfprintf(log_file, format, va);
    va_end(va);
  }
}

}  // namespace slowhttptest

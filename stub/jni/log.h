
#ifndef ANDROID_LOG_INFO
    #define ANDROID_LOG_INFO 4
    #define ANDROID_LOG_ERROR 6
#endif

#define LOGTAG "wi-log"

#ifndef _DEBUG
    #define LOGD(fmt, ...) wi_log(ANDROID_LOG_INFO, LOGTAG, fmt, ##__VA_ARGS__)
    #define LOGE(fmt, ...) wi_log(ANDROID_LOG_ERROR, LOGTAG, fmt, ##__VA_ARGS__)
#else
    #define LOGD(fmt, ...) 
    #define LOGE(fmt, ...) 
#endif

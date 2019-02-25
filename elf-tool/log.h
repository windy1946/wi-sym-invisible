#ifndef _POC_LOG_H
#define _POC_LOG_H
#define _NDEBUG

#ifdef _DEBUG
#define LOGD(fmt, ...) fprintf(stderr, "[%s:%d]DEBUG:: " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOGI(fmt, ...) fprintf(stdout, "[+]" fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "[%s:%s:%d]ERROR:: " fmt "\n", __FILE__, __FUNCTION__, __LINE__, ##__VA_ARGS__)
#else
#define LOGD(fmt, ...)
#define LOGI(fmt, ...) fprintf(stdout, "[+]" fmt "\n", ##__VA_ARGS__) //LOGI(fmt, ...)
#define LOGE(fmt, ...)
#endif

#endif
#ifndef EasyTshark_WebServer_hpp
#define EasyTshark_WebServer_hpp

#include <string>

#include "httplib/httplib.h"

#include "AnalysisSession.hpp"

// Web 前端的 HTTP 路由层：把 /api/* 路由、令牌鉴权、Origin 校验、路径白名单集中于此，
// 供生产入口（main_web.cpp）与单元测试复用，不绑定命令行参数。
//
// 线程：httplib 每连接一线程，处理器可能并发进入；内部用 opMutex 串行化写操作，
// 实时抓包回调只推进带锁的 liveBuffer。
// 安全：所有 /api/* 须带 X-Auth-Token；浏览器请求还校验 Origin==Host；
// /api/load 仅允许用户主目录或 data/ 下的文件。静态资源不要求 token。
void registerWebRoutes(httplib::Server& svr, AnalysisSession& session,
                       const std::string& token);

#endif

#ifndef PARAMOP_FUNCTION_TRACER_H
#define PARAMOP_FUNCTION_TRACER_H

// C++98-friendly tracer for CK_PARAMETEROPERATION functions.
//
// Enable:
//  - Build define: PARAMOP_TRACE_ENABLED=1
//  - Optional runtime env var: PARAMOP_TRACE=0 disables output even if compiled enabled.
//
// Output:
//  - Uses OutputDebugStringA (visible in VS Debug Output / DebugView)

#include <stdio.h>
#include <map>

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <Windows.h>

#include "CKAll.h"

#ifndef PARAMOP_TRACE_ENABLED
#if defined(_DEBUG)
#define PARAMOP_TRACE_ENABLED 1
#else
#define PARAMOP_TRACE_ENABLED 0
#endif
#endif

namespace ParamOpTrace
{
    struct OpFuncMeta
    {
        const char *Name;
        CKGUID OpGuid;
        CKGUID ResTypeGuid;
        CKGUID P1TypeGuid;
        CKGUID P2TypeGuid;

        OpFuncMeta() : Name(0), OpGuid(0, 0), ResTypeGuid(0, 0), P1TypeGuid(0, 0), P2TypeGuid(0, 0) {}

        OpFuncMeta(const char *name, const CKGUID &opGuid, const CKGUID &resTypeGuid, const CKGUID &p1TypeGuid, const CKGUID &p2TypeGuid)
            : Name(name), OpGuid(opGuid), ResTypeGuid(resTypeGuid), P1TypeGuid(p1TypeGuid), P2TypeGuid(p2TypeGuid) {}
    };

    inline const char *GuidToString(const CKGUID &g, char *buf, size_t bufSize)
    {
        if (!buf || bufSize < 32)
            return "{?}";
        // {0x12345678,0x9abcdef0}
        sprintf(buf, "{0x%08lX,0x%08lX}", (unsigned long)g.d1, (unsigned long)g.d2);
        return buf;
    }

    inline std::map<CK_PARAMETEROPERATION, OpFuncMeta> &Registry()
    {
        static std::map<CK_PARAMETEROPERATION, OpFuncMeta> reg;
        return reg;
    }

    inline void RegisterMeta(CK_PARAMETEROPERATION thunk, const OpFuncMeta &meta)
    {
        Registry()[thunk] = meta;
    }

    inline const OpFuncMeta *FindMeta(CK_PARAMETEROPERATION thunk)
    {
        std::map<CK_PARAMETEROPERATION, OpFuncMeta>::iterator it = Registry().find(thunk);
        if (it == Registry().end())
            return 0;
        return &it->second;
    }

    inline int IsEnabled()
    {
#if PARAMOP_TRACE_ENABLED
        static int s_inited = 0;
        static int s_enabled = 1;
        if (!s_inited)
        {
            s_inited = 1;
            char buf[32];
            DWORD n = GetEnvironmentVariableA("PARAMOP_TRACE", buf, (DWORD)sizeof(buf));
            if (n > 0)
            {
                // Any of: 0 / false / off -> disable. Otherwise enable.
                if (buf[0] == '0' || buf[0] == 'f' || buf[0] == 'F' || buf[0] == 'o' || buf[0] == 'O')
                    s_enabled = 0;
            }
        }
        return s_enabled;
#else
        return 0;
#endif
    }

    inline void WriteLine(const char *line)
    {
        if (!line)
            return;
        OutputDebugStringA(line);
        OutputDebugStringA("\n");
    }

    inline void QpcNow(LARGE_INTEGER *out)
    {
        if (!out)
            return;
        QueryPerformanceCounter(out);
    }

    inline double QpcToMicroseconds(const LARGE_INTEGER &start, const LARGE_INTEGER &end)
    {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        if (freq.QuadPart == 0)
            return 0.0;
        const double ticks = (double)(end.QuadPart - start.QuadPart);
        return (ticks * 1000000.0) / (double)freq.QuadPart;
    }

    class Scope
    {
    public:
        Scope(CK_PARAMETEROPERATION thunk, CKContext *context, CKParameterOut *res, CKParameterIn *p1, CKParameterIn *p2)
            : m_Thunk(thunk)
        {
            if (!IsEnabled())
                return;

            QpcNow(&m_Start);

            const OpFuncMeta *meta = FindMeta(thunk);

            char opBuf[64], resBuf[64], p1Buf[64], p2Buf[64];
            char r2Buf[64], a1Buf[64], a2Buf[64];

            CKGUID resGuid = res ? res->GetGUID() : CKGUID(0, 0);
            CKGUID p1Guid = p1 ? p1->GetGUID() : CKGUID(0, 0);
            CKGUID p2Guid = p2 ? p2->GetGUID() : CKGUID(0, 0);

            const DWORD tid = GetCurrentThreadId();

            char line[512];
            if (meta && meta->Name)
            {
                sprintf(
                    line,
                    "[ParamOpTrace] + %s tid=%lu op=%s expected(res=%s p1=%s p2=%s) actual(res=%s p1=%s p2=%s) ptr(res=%p p1=%p p2=%p)",
                    meta->Name,
                    (unsigned long)tid,
                    GuidToString(meta->OpGuid, opBuf, sizeof(opBuf)),
                    GuidToString(meta->ResTypeGuid, resBuf, sizeof(resBuf)),
                    GuidToString(meta->P1TypeGuid, p1Buf, sizeof(p1Buf)),
                    GuidToString(meta->P2TypeGuid, p2Buf, sizeof(p2Buf)),
                    GuidToString(resGuid, r2Buf, sizeof(r2Buf)),
                    GuidToString(p1Guid, a1Buf, sizeof(a1Buf)),
                    GuidToString(p2Guid, a2Buf, sizeof(a2Buf)),
                    (void *)res,
                    (void *)p1,
                    (void *)p2);
            }
            else
            {
                sprintf(
                    line,
                    "[ParamOpTrace] + <unregistered> tid=%lu ptr(res=%p p1=%p p2=%p)",
                    (unsigned long)tid,
                    (void *)res,
                    (void *)p1,
                    (void *)p2);
            }

            WriteLine(line);

            (void)context;
        }

        ~Scope()
        {
            if (!IsEnabled())
                return;

            LARGE_INTEGER end;
            QpcNow(&end);

            const OpFuncMeta *meta = FindMeta(m_Thunk);
            const DWORD tid = GetCurrentThreadId();
            const double us = QpcToMicroseconds(m_Start, end);

            char line[256];
            if (meta && meta->Name)
            {
                sprintf(line, "[ParamOpTrace] - %s tid=%lu dt=%.1fus", meta->Name, (unsigned long)tid, us);
            }
            else
            {
                sprintf(line, "[ParamOpTrace] - <unregistered> tid=%lu dt=%.1fus", (unsigned long)tid, us);
            }

            WriteLine(line);
        }

    private:
        CK_PARAMETEROPERATION m_Thunk;
        LARGE_INTEGER m_Start;
    };

    template <CK_PARAMETEROPERATION Fn>
    void Thunk(CKContext *context, CKParameterOut *res, CKParameterIn *p1, CKParameterIn *p2)
    {
        if (IsEnabled())
        {
            Scope scope((CK_PARAMETEROPERATION)&Thunk<Fn>, context, res, p1, p2);
            Fn(context, res, p1, p2);
        }
        else
        {
            Fn(context, res, p1, p2);
        }
    }
} // namespace ParamOpTrace

// Register wrapper thunks for every operation function.
// This is intentionally a macro so we can stringize `fn` as its human-readable name.
#if PARAMOP_TRACE_ENABLED
#define PARAMOP_REGISTER_OPERATION_FUNCTION(pm, opGuid, resGuid, p1Guid, p2Guid, fn)                                                     \
    do                                                                                                                                   \
    {                                                                                                                                    \
        if (ParamOpTrace::IsEnabled())                                                                                                   \
        {                                                                                                                                \
            ParamOpTrace::RegisterMeta((CK_PARAMETEROPERATION) & ParamOpTrace::Thunk<fn>,                                                \
                                       ParamOpTrace::OpFuncMeta(#fn, (opGuid), (resGuid), (p1Guid), (p2Guid)));                          \
            (pm)->RegisterOperationFunction((opGuid), (resGuid), (p1Guid), (p2Guid), (CK_PARAMETEROPERATION) & ParamOpTrace::Thunk<fn>); \
        }                                                                                                                                \
        else                                                                                                                             \
        {                                                                                                                                \
            (pm)->RegisterOperationFunction((opGuid), (resGuid), (p1Guid), (p2Guid), (fn));                                              \
        }                                                                                                                                \
    } while (0)
#else
#define PARAMOP_REGISTER_OPERATION_FUNCTION(pm, opGuid, resGuid, p1Guid, p2Guid, fn) \
    (pm)->RegisterOperationFunction((opGuid), (resGuid), (p1Guid), (p2Guid), (fn))
#endif

#endif // PARAMOP_FUNCTION_TRACER_H

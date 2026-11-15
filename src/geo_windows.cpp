// Precise device geolocation for Windows via WinRT
// Windows.Devices.Geolocation.Geolocator.
//
// Uses only the Windows SDK headers and WRL — no C++/WinRT dependency.
// Unpackaged desktop apps get the system location consent prompt on
// first use; if the user denies, location services are off, or no fix
// arrives in time, nullopt is returned and the caller falls back to
// IP-based geolocation.

#include "geo.h"

#if defined(_WIN32)

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <roapi.h>
#include <wrl.h>
#include <windows.devices.geolocation.h>
#include <windows.foundation.h>

#include <memory>
#include <optional>

using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Make;
using Microsoft::WRL::Wrappers::HStringReference;
using Windows::Devices::Geolocation::GeolocationAccessStatus;
using Windows::Devices::Geolocation::GeolocationAccuracy;
using Windows::Devices::Geolocation::Geoposition;
using Windows::Devices::Geolocation::IGeolocator;
using Windows::Devices::Geolocation::IGeolocatorStatics;
using Windows::Devices::Geolocation::IGeopoint;
using Windows::Foundation::AsyncStatus;
using Windows::Foundation::IAsyncOperation;
using Windows::Foundation::IAsyncOperationCompletedHandler;

namespace {

// Shared between the waiting thread and the completion handler. The
// handler holds a reference, so the event stays valid even if the
// caller times out and stops waiting.
struct AsyncDone {
    HANDLE event = nullptr;
    AsyncStatus status = AsyncStatus::Started;
};

template <typename TResult>
class AsyncHandler
    : public Microsoft::WRL::RuntimeClass<
          Microsoft::WRL::RuntimeClassFlags<
              Microsoft::WRL::RuntimeClassType::Delegate>,
          IAsyncOperationCompletedHandler<TResult>> {
public:
    explicit AsyncHandler(std::shared_ptr<AsyncDone> done)
        : done_(std::move(done)) {}

    IFACEMETHODIMP Invoke(IAsyncOperation<TResult>*,
                          AsyncStatus status) noexcept override {
        done_->status = status;
        SetEvent(done_->event);
        return S_OK;
    }

private:
    std::shared_ptr<AsyncDone> done_;
};

struct WaitResult {
    bool completed = false;
    AsyncStatus status = AsyncStatus::Started;
};

// Register a completion handler, start the operation and wait up to
// timeout_ms. On timeout the operation is cancelled; the handler keeps
// AsyncDone alive until it completes.
template <typename TResult>
WaitResult wait_async(IAsyncOperation<TResult>* op, DWORD timeout_ms) {
    auto done = std::make_shared<AsyncDone>();
    done->event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    WaitResult r;

    ComPtr<IAsyncOperationCompletedHandler<TResult>> handler =
        Make<AsyncHandler<TResult>>(done);
    if (FAILED(op->put_Completed(handler.Get()))) return r;
    if (FAILED(op->Start())) return r;

    if (WaitForSingleObject(done->event, timeout_ms) == WAIT_OBJECT_0) {
        r.completed = true;
        r.status = done->status;
    } else {
        op->Cancel();
    }
    return r;
}

}  // namespace

std::optional<GeoFix> platform_location() {
    HRESULT coinit = RoInitialize(RO_INIT_MULTITHREADED);
    if (FAILED(coinit)) {
        if (coinit != RPC_E_CHANGED_MODE) return std::nullopt;
    }
    // RPC_E_CHANGED_MODE: the thread is already in an apartment (STA);
    // WinRT calls still work there. S_OK means we must uninitialize.
    const bool uninit = SUCCEEDED(coinit);

    std::optional<GeoFix> result;
    do {
        ComPtr<Windows::Foundation::IInspectable> insp;
        HStringReference cls(L"Windows.Devices.Geolocation.Geolocator");
        if (FAILED(RoGetActivationFactory(cls.Get(), IID_PPV_ARGS(&insp))))
            break;
        ComPtr<IGeolocatorStatics> statics;
        if (FAILED(insp.As(&statics))) break;

        // Consent check first — may show the system prompt, so allow
        // the user up to a minute to respond.
        ComPtr<IAsyncOperation<GeolocationAccessStatus>> reqOp;
        if (FAILED(statics->RequestAccessAsync(&reqOp)) || !reqOp) break;
        WaitResult wr = wait_async(reqOp.Get(), 60000);
        if (!wr.completed || wr.status != AsyncStatus::Completed) break;
        GeolocationAccessStatus access = GeolocationAccessStatus_Unspecified;
        if (FAILED(reqOp->GetResults(&access)) ||
            access != GeolocationAccessStatus_Allowed)
            break;

        ComPtr<Windows::Foundation::IInspectable> locInsp;
        if (FAILED(statics->ActivateInstance(&locInsp))) break;
        ComPtr<IGeolocator> locator;
        if (FAILED(locInsp.As(&locator))) break;
        locator->put_DesiredAccuracy(GeolocationAccuracy_High);
        GeolocationAccessStatus locStatus = GeolocationAccessStatus_Unspecified;
        if (FAILED(locator->get_LocationStatus(&locStatus)) ||
            locStatus != GeolocationAccessStatus_Allowed)
            break;

        ComPtr<IAsyncOperation<Geoposition*>> posOp;
        if (FAILED(locator->GetGeopositionAsync(&posOp)) || !posOp) break;
        WaitResult pw = wait_async(posOp.Get(), 30000);
        if (!pw.completed || pw.status != AsyncStatus::Completed) {
            posOp->Cancel();
            break;
        }
        Geoposition* pos = nullptr;
        if (FAILED(posOp->GetResults(&pos)) || !pos) break;
        ComPtr<IGeopoint> point;
        if (SUCCEEDED(pos->get_Coordinate(&point)) && point) {
            double lat = 0, lon = 0, acc = -1;
            if (SUCCEEDED(point->get_Latitude(&lat)) &&
                SUCCEEDED(point->get_Longitude(&lon))) {
                point->get_Accuracy(&acc);
                result = GeoFix{lat, lon, acc};
            }
        }
        pos->Release();
    } while (false);

    if (uninit) RoUninitialize();
    return result;
}

#endif  // _WIN32

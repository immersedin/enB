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
#include <windows.foundation.collections.h>

#include <memory>
#include <optional>

using Microsoft::WRL::ComPtr;
using Microsoft::WRL::Make;
using Microsoft::WRL::Wrappers::HStringReference;
using ABI::Windows::Devices::Geolocation::BasicGeoposition;
using ABI::Windows::Devices::Geolocation::GeolocationAccessStatus;
using ABI::Windows::Devices::Geolocation::Geoposition;
using ABI::Windows::Devices::Geolocation::IGeocoordinate;
using ABI::Windows::Devices::Geolocation::IGeocoordinateWithPoint;
using ABI::Windows::Devices::Geolocation::IGeolocator;
using ABI::Windows::Devices::Geolocation::IGeolocatorStatics;
using ABI::Windows::Devices::Geolocation::IGeopoint;
using ABI::Windows::Devices::Geolocation::IGeoposition;
using ABI::Windows::Devices::Geolocation::PositionAccuracy;
using ABI::Windows::Devices::Geolocation::PositionStatus;
using ABI::Windows::Foundation::AsyncStatus;
using ABI::Windows::Foundation::IAsyncInfo;
using ABI::Windows::Foundation::IAsyncOperation;
using ABI::Windows::Foundation::IAsyncOperationCompletedHandler;

namespace {

// Shared between the waiting thread and the completion handler. The
// handler holds a reference, so the event stays valid even if the
// caller times out and stops waiting.
struct AsyncDone {
    HANDLE event = nullptr;
    AsyncStatus status = AsyncStatus::Started;
    ~AsyncDone() {
        if (event) CloseHandle(event);
    }
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

// Register a completion handler and wait up to timeout_ms. WinRT async
// operations start when created; IAsyncOperation has no Start(). On
// timeout the operation is cancelled through IAsyncInfo; the handler
// keeps AsyncDone alive until it completes.
template <typename TResult>
WaitResult wait_async(IAsyncOperation<TResult>* op, DWORD timeout_ms) {
    auto done = std::make_shared<AsyncDone>();
    done->event = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    WaitResult r;
    if (!done->event) return r;

    ComPtr<IAsyncOperationCompletedHandler<TResult>> handler =
        Make<AsyncHandler<TResult>>(done);
    if (FAILED(op->put_Completed(handler.Get()))) return r;

    if (WaitForSingleObject(done->event, timeout_ms) == WAIT_OBJECT_0) {
        r.completed = true;
        r.status = done->status;
    } else {
        ComPtr<IAsyncInfo> info;
        if (SUCCEEDED(op->QueryInterface(IID_PPV_ARGS(&info))) && info)
            info->Cancel();
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
        HStringReference cls(RuntimeClass_Windows_Devices_Geolocation_Geolocator);
        ComPtr<IGeolocatorStatics> statics;
        if (FAILED(RoGetActivationFactory(cls.Get(), IID_PPV_ARGS(&statics))) ||
            !statics)
            break;

        // Consent check first — may show the system prompt, so allow
        // the user up to a minute to respond.
        ComPtr<IAsyncOperation<GeolocationAccessStatus>> reqOp;
        if (FAILED(statics->RequestAccessAsync(&reqOp)) || !reqOp) break;
        WaitResult wr = wait_async(reqOp.Get(), 60000);
        if (!wr.completed || wr.status != AsyncStatus::Completed) break;
        GeolocationAccessStatus access =
            GeolocationAccessStatus::GeolocationAccessStatus_Unspecified;
        if (FAILED(reqOp->GetResults(&access)) ||
            access != GeolocationAccessStatus::GeolocationAccessStatus_Allowed)
            break;

        ComPtr<IInspectable> inspectable;
        if (FAILED(RoActivateInstance(cls.Get(), &inspectable)) || !inspectable)
            break;
        ComPtr<IGeolocator> locator;
        if (FAILED(inspectable.As(&locator)) || !locator) break;
        locator->put_DesiredAccuracy(PositionAccuracy::PositionAccuracy_High);

        PositionStatus locStatus = PositionStatus::PositionStatus_NotInitialized;
        if (FAILED(locator->get_LocationStatus(&locStatus)) ||
            locStatus == PositionStatus::PositionStatus_Disabled ||
            locStatus == PositionStatus::PositionStatus_NotAvailable)
            break;

        ComPtr<IAsyncOperation<Geoposition*>> posOp;
        if (FAILED(locator->GetGeopositionAsync(&posOp)) || !posOp) break;
        WaitResult pw = wait_async(posOp.Get(), 30000);
        if (!pw.completed || pw.status != AsyncStatus::Completed) break;

        ComPtr<IGeoposition> pos;
        if (FAILED(posOp->GetResults(&pos)) || !pos) break;
        ComPtr<IGeocoordinate> coord;
        if (FAILED(pos->get_Coordinate(&coord)) || !coord) break;
        ComPtr<IGeocoordinateWithPoint> coordWithPoint;
        if (FAILED(coord.As(&coordWithPoint)) || !coordWithPoint) break;
        ComPtr<IGeopoint> point;
        if (FAILED(coordWithPoint->get_Point(&point)) || !point) break;
        BasicGeoposition geopos{};
        if (FAILED(point->get_Position(&geopos))) break;
        double acc = -1;
        coord->get_Accuracy(&acc);
        result = GeoFix{geopos.Latitude, geopos.Longitude, acc};
    } while (false);

    if (uninit) RoUninitialize();
    return result;
}

#endif  // _WIN32

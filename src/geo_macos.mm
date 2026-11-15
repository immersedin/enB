// Precise device geolocation for macOS via CoreLocation.
//
// The location manager needs a run loop, so all work happens on a
// dedicated NSThread while the caller waits on a semaphore. The best
// fix wins; updates continue until the horizontal accuracy is <= 25 m
// or the 20 s timeout expires.
//
// Important: CLLocationManager raises an NSException when the process
// has no NSLocationWhenInUseUsageDescription in its Info.plist — which
// is always the case for the bare `p2p` binary. We therefore bail out
// early unless the key is present (i.e. we run inside p2p.app).

#include "geo.h"

#if defined(__APPLE__)

#import <CoreLocation/CoreLocation.h>
#import <Foundation/Foundation.h>

#include <atomic>
#include <mutex>
#include <optional>

namespace {

struct LocState {
    std::mutex mu;
    CLLocation* best = nil;  // retained; lowest horizontalAccuracy seen
    double best_acc = 1e30;
    std::atomic<bool> stop{false};
};
LocState& state() {
    static LocState s;
    return s;
}

#if TARGET_OS_OSX
// macOS has a single "authorized" state (no WhenInUse/Always split).
bool auth_granted(CLAuthorizationStatus s) {
    return s == kCLAuthorizationStatusAuthorized;
}
bool auth_denied(CLAuthorizationStatus s) {
    return s == kCLAuthorizationStatusDenied ||
           s == kCLAuthorizationStatusRestricted;
}
#else
bool auth_granted(CLAuthorizationStatus s) {
    return s == kCLAuthorizationStatusAuthorizedWhenInUse ||
           s == kCLAuthorizationStatusAuthorizedAlways;
}
bool auth_denied(CLAuthorizationStatus s) {
    return s == kCLAuthorizationStatusDenied ||
           s == kCLAuthorizationStatusRestricted;
}
#endif

}  // namespace

@interface P2PLocDelegate : NSObject <CLLocationManagerDelegate>
@end

@implementation P2PLocDelegate

- (void)locationManager:(CLLocationManager*)manager
     didUpdateLocations:(NSArray<CLLocation*>*)locations {
    if (locations.count == 0) return;
    CLLocation* l = locations.lastObject;
    if (l.horizontalAccuracy < 0) return;  // invalid fix
    LocState& st = state();
    {
        std::lock_guard<std::mutex> lk(st.mu);
        if (!st.best || l.horizontalAccuracy < st.best_acc) {
            [st.best release];
            st.best = [l retain];
            st.best_acc = l.horizontalAccuracy;
        }
    }
    if (l.horizontalAccuracy <= 25.0) st.stop = true;
}

- (void)locationManager:(CLLocationManager*)manager
       didFailWithError:(NSError*)error {
    if (error.code == kCLErrorDenied) state().stop = true;
}

- (void)locationManagerDidChangeAuthorization:(CLLocationManager*)manager {
    CLAuthorizationStatus s = manager.authorizationStatus;
    if (auth_granted(s)) {
        [manager startUpdatingLocation];
    } else if (auth_denied(s)) {
        state().stop = true;
    }
}

@end

namespace {

std::optional<GeoFix> precise_location_run() {
    @autoreleasepool {
        id usage = [[NSBundle mainBundle]
            objectForInfoDictionaryKey:@"NSLocationWhenInUseUsageDescription"];
        if (!usage) return std::nullopt;
    }

    LocState& st = state();
    __block std::optional<GeoFix> result;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSThread* thread = [[NSThread alloc] initWithBlock:^{
        @autoreleasepool {
            {
                std::lock_guard<std::mutex> lk(st.mu);
                [st.best release];
                st.best = nil;
                st.best_acc = 1e30;
            }
            st.stop = false;

            CLLocationManager* mgr = [[CLLocationManager alloc] init];
            P2PLocDelegate* del = [P2PLocDelegate new];
            mgr.delegate = del;
            mgr.desiredAccuracy = kCLLocationAccuracyBest;

            [mgr requestWhenInUseAuthorization];
            CLAuthorizationStatus auth = mgr.authorizationStatus;
            if (auth_granted(auth)) {
                [mgr startUpdatingLocation];
            } else if (auth_denied(auth)) {
                st.stop = true;
            }
            // kCLAuthorizationStatusNotDetermined: the system prompt is
            // up; didChangeAuthorization starts updates on approval.

            NSDate* deadline =
                [NSDate dateWithTimeIntervalSinceNow:20.0];
            while (!st.stop && [deadline timeIntervalSinceNow] > 0) {
                [[NSRunLoop currentRunLoop]
                    runMode:NSDefaultRunLoopMode
                    beforeDate:[NSDate dateWithTimeIntervalSinceNow:0.2]];
            }
            [mgr stopUpdatingLocation];

            {
                std::lock_guard<std::mutex> lk(st.mu);
                if (st.best) {
                    result = GeoFix{st.best.coordinate.latitude,
                                    st.best.coordinate.longitude,
                                    st.best.horizontalAccuracy};
                }
                [st.best release];
                st.best = nil;
            }
            [mgr release];
            [del release];
        }
        dispatch_semaphore_signal(sem);
    }];
    [thread start];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    [thread release];
    return result;
}

}  // namespace

std::optional<GeoFix> platform_location() { return precise_location_run(); }

#endif  // __APPLE__

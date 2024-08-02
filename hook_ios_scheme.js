function hook_openurl() {
    var UIApplication = ObjC.classes.UIApplication
    Interceptor.attach(UIApplication['- _applicationOpenURLAction:payload:origin:'].implementation, {
        onEnter: function (args) {
            console.log('URL Scheme: ' + new ObjC.Object(args[2]).url())
        },
        onLeave: function (retval) {

        }
    });
    
    Interceptor.attach(UIApplication['- activityContinuationManager:continueUserActivity:'].implementation, {
        onEnter: function (args) {
            console.log('Universal Link: ' + new ObjC.Object(args[3]).webpageURL())
        },
        onLeave: function (retval) {

        }
    });
    Interceptor.attach(UIApplication['- openURL:options:completionHandler:'].implementation, {
        onEnter: function (args) {
            console.log('Open URL: ' + new ObjC.Object(args[2]))
        },
        onLeave: function (retval) {

        }
    });
}

function main() {
    if (ObjC.available) {
        hook_openurl()
    }
}

setImmediate(main);
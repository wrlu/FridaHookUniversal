function hook_webview() {
    var WebView = Java.use('android.webkit.WebView')
    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {
        console.log('loadUrl: this = ' + this + ', url = ' + url);
        this.loadUrl(url);
    };
    WebView.loadUrl.overload('java.lang.String', 'java.util.Map').implementation = function (url, params) {
        console.log('loadUrl: this = ' + this + ', url = ' + url);
        this.loadUrl(url, params);
    };
}

function main() {
    if (Java.available) {
        Java.perform(function() {
            hook_webview();
        })
    }
}

setImmediate(main);
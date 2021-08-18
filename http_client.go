package centrify

import (
	"fmt"
	"net/http"
	"regexp"
	"time"

	"github.com/hashicorp/go-hclog"
)

var securityRegexp = regexp.MustCompile(`^(\/api\/v\d\.\d\/(privilegeddata\/)*secrets\/)|^(\/security\/)`)

// newLogClient returns a new http client object but using a different transport that logs messages.
func newLogClient(logger hclog.Logger) func() *http.Client {
	return func() *http.Client {
		return &http.Client{
			Transport: &logTransport{
				transport: http.DefaultTransport.(*http.Transport).Clone(),
				logger:    logger,
			},
		}
	}
}

// logTransport is a custom RoundTripper object that supports the http.RoundTripper interface.
// Its implementation of RoundTrip() logs the time that the REST API is sent and time received, as well as the REST
// call transaction ID.
type logTransport struct {
	transport http.RoundTripper
	logger    hclog.Logger
}

const (
	// start message: REST|starts|METHOD|URL.
	logStartMsg = "REST|starts|%s|%s"

	// end message: REST|ends|METHOD|URL|HTTP status code|xid|elapsed time.
	logEndMsg = "REST|ends|%s|%s|%d|%s|%v"

	// error message: REST|error|METHOD|URL|elapsed time|error.
	logErrMsg = "REST|error|%s|%s|%v|%v"
)

func securityCleanURL(u string) string {
	matches := securityRegexp.FindStringSubmatch(u)
	if len(matches) > 0 {
		u = matches[0] + "***"
	}
	return u
}

// RoundTrip logs starts/ends messages for the REST API call.
func (tr *logTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	securedURL := securityCleanURL(req.URL.Path)

	startTime := time.Now()
	tr.logger.Info(fmt.Sprintf(logStartMsg, req.Method, securedURL))

	resp, err := tr.transport.RoundTrip(req)
	if err != nil {
		tr.logger.Info(fmt.Sprintf(logErrMsg, req.Method, securedURL, time.Since(startTime), err))
		return resp, err //nolint: wrapcheck
	}

	xid := resp.Header.Get("X-CFY-TX-ID")
	tr.logger.Info(fmt.Sprintf(logEndMsg, req.Method, securedURL, resp.StatusCode, xid, time.Since(startTime)))

	return resp, nil
}

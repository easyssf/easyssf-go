// Package receiver is the SSF receiver without a web framework beyond net/http: it verifies
// Security Event Tokens (RFC 8417) a transmitter pushes (RFC 8935) or it polls (RFC 8936),
// de-duplicates them, manages its stream at the transmitter and hands the events to handlers.
//
// A port of easyssf-receiver of the Java library, with the options, the transmitter factory and
// the assembly of a receiver from its configuration of the .NET EasySsf.Receiver.Hosting project
// in config.go and receiver.go. The Java packages map to files of this package: set.go, push.go,
// event.go, transmitter.go, stream.go, poll.go, revocation.go, session.go, metrics.go.
//
// Reacting to an event is a function, see HandlerFunc and ForEvent; assembling a receiver by hand
// is a few lines, see Processor and PushHandler; assembling it from configuration is New.
//
// Because net/http is the standard library, the push endpoint (PushHandler) is an http.Handler
// and the revocation middleware is a func(http.Handler) http.Handler: they mount on net/http,
// chi, gorilla/mux and, through their adapters, on gin and echo without a package per framework.
package receiver

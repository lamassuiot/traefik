package gateway

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/tls"
	gatev1 "sigs.k8s.io/gateway-api/apis/v1"
)

func httpsListener(options map[gatev1.AnnotationKey]gatev1.AnnotationValue) gatewayListener {
	return gatewayListener{
		Protocol: gatev1.HTTPSProtocolType,
		EPName:   "websecure",
		Attached: true,
		TLS:      &gatev1.ListenerTLSConfig{Options: options},
	}
}

func Test_buildListenerRouters_tlsOptions(t *testing.T) {
	testCases := []struct {
		desc     string
		gateways [][]gatewayListener
		// wantOptions is the router TLS options; "" means the isolated per-listener options.
		wantOptions string
	}{
		{
			desc:     "no reference keeps the isolated default options",
			gateways: [][]gatewayListener{{httpsListener(nil)}},
		},
		{
			desc:        "default references the default TLS options",
			gateways:    [][]gatewayListener{{httpsListener(map[gatev1.AnnotationKey]gatev1.AnnotationValue{listenerTLSOptionsKey: "default"})}},
			wantOptions: "default",
		},
		{
			desc:        "qualified TLS options name",
			gateways:    [][]gatewayListener{{httpsListener(map[gatev1.AnnotationKey]gatev1.AnnotationValue{listenerTLSOptionsKey: "traefik-system-pqc@kubernetescrd"})}},
			wantOptions: "traefik-system-pqc@kubernetescrd",
		},
		{
			desc: "gateways sharing the parent router agree",
			gateways: [][]gatewayListener{
				{httpsListener(map[gatev1.AnnotationKey]gatev1.AnnotationValue{listenerTLSOptionsKey: "default"})},
				{httpsListener(map[gatev1.AnnotationKey]gatev1.AnnotationValue{listenerTLSOptionsKey: "default"})},
			},
			wantOptions: "default",
		},
		{
			desc: "gateways sharing the parent router disagree",
			gateways: [][]gatewayListener{
				{httpsListener(map[gatev1.AnnotationKey]gatev1.AnnotationValue{listenerTLSOptionsKey: "default"})},
				{httpsListener(nil)},
			},
		},
	}

	for _, test := range testCases {
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()

			var gateways []gatewayWithListeners
			for _, listeners := range test.gateways {
				gateways = append(gateways, gatewayWithListeners{gateway: &gatev1.Gateway{}, listeners: listeners})
			}
			conf := &dynamic.Configuration{
				HTTP: &dynamic.HTTPConfiguration{Routers: map[string]*dynamic.Router{}},
				TLS:  &dynamic.TLSConfiguration{Options: map[string]tls.Options{}},
			}

			names := (&Provider{}).buildListenerRouters(gateways, conf)
			require.Len(t, names, 1)

			router := conf.HTTP.Routers[names[0]]
			require.NotNil(t, router.TLS)
			if test.wantOptions == "" {
				assert.Equal(t, names[0], router.TLS.Options)
				assert.Contains(t, conf.TLS.Options, names[0])
				return
			}
			assert.Equal(t, test.wantOptions, router.TLS.Options)
			assert.NotContains(t, conf.TLS.Options, names[0])
		})
	}
}

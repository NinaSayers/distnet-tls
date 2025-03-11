## Pasos para utilizar desde el proyecto principal

### 1. Inicializar CA (una sola vez)

import "github.com/yourusername/tls-library/tlsgen"

func main() {
    // Generar CA raíz
    tlsgen.GenerateRootCA(
        "Kademlia Root CA",
        "tls/certs/ca/ca.crt",
        "tls/certs/ca/ca.key",
    )
}

### 2. Generar certificados para componentes

// Para el router
tlsgen.GenerateCert(
    "router.distribuidos.net",
    []string{"192.168.1.1"},
    []string{"router.distribuidos.net", "*.dns.distribuidos.net"},
    "tls/certs/ca/ca.crt",
    "tls/certs/ca/ca.key",
    "tls/certs/generated/router/",
)

// Para un nodo Kademlia
tlsgen.GenerateCert(
    "node1.kademlia.net",
    []string{"10.0.0.5"},
    []string{"node1.internal.kademlia"},
    "tls/certs/ca/ca.crt",
    "tls/certs/ca/ca.key",
    "tls/certs/generated/nodes/node1/",
)

### 3. Usar en componentes existentes

// En el router (HTTP Server)
config, _ := tlsconfig.loadServerTLS(
    "tls/certs/nenerated/router/server.crt",
    "tls/certs/generated/router/server.key",
    "tls/certs/ca/ca.crt",
)

server := &http.Server{
    Addr:      ":443",
    Handler:   router,
    TLSConfig: config,
}
server.ListenAndServeTLS("", "")

// En un nodo Kademlia (gRPC Server)
creds, _ := credentials.NewServerTLSFromFile(
    "tls/certs/generated/nodes/node1/server.crt",
    "tls/certs/generated/nodes/node1/server.key",
)
grpcServer := grpc.NewServer(grpc.Creds(creds))

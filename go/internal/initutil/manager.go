package initutil

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	datastore "github.com/ipfs/go-datastore"
	"github.com/ipfs/go-ipfs/core"
	pubsub "github.com/libp2p/go-libp2p-pubsub"
	"github.com/oklog/run"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/shibukawa/configdir"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"gorm.io/gorm"

	"berty.tech/berty/v2/go/internal/grpcutil"
	"berty.tech/berty/v2/go/internal/ipfsutil"
	"berty.tech/berty/v2/go/internal/lifecycle"
	"berty.tech/berty/v2/go/internal/notification"
	"berty.tech/berty/v2/go/internal/tinder"
	"berty.tech/berty/v2/go/pkg/bertymessenger"
	"berty.tech/berty/v2/go/pkg/bertyprotocol"
	"berty.tech/berty/v2/go/pkg/errcode"
)

type Manager struct {
	Logging struct {
		Format  string `json:"Format,omitempty"`
		Logfile string `json:"Logfile,omitempty"`
		Filters string `json:"Filters,omitempty"`
		Tracer  string `json:"Tracer,omitempty"`
		Service string `json:"Service,omitempty"`

		zapLogger *zap.Logger
		cleanup   func()
	} `json:"Logging,omitempty"`
	Metrics struct {
		Listener string `json:"Listener,omitempty"`
		Pedantic bool   `json:"Pedantic,omitempty"`

		registry *prometheus.Registry
	} `json:"Metrics,omitempty"`
	Datastore struct {
		Dir      string `json:"Dir,omitempty"`
		InMemory bool   `json:"InMemory,omitempty"`

		defaultDir string
		dir        string
		rootDS     datastore.Batching
	} `json:"Datastore,omitempty"`
	Node struct {
		Preset   Preset
		Protocol struct {
			// IPFS
			IPFSListeners      flagStringSlice `json:"IPFSListeners,omitempty"`
			IPFSAPIListeners   flagStringSlice `json:"IPFSAPIListeners,omitempty"`
			IPFSWebUIListener  string          `json:"IPFSWebUIListener,omitempty"`
			Announce           flagStringSlice `json:"Announce,omitempty"`
			NoAnnounce         flagStringSlice `json:"NoAnnounce,omitempty"`
			LocalDiscovery     bool            `json:"LocalDiscovery,omitempty"`
			MinBackoff         time.Duration   `json:"MinBackoff,omitempty"`
			MaxBackoff         time.Duration   `json:"MaxBackoff,omitempty"`
			DisableIPFSNetwork bool            `json:"DisableIPFSNetwork,omitempty"`
			RdvpMaddrs         flagStringSlice `json:"RdvpMaddrs,omitempty"`
			AuthSecret         string          `json:"AuthSecret,omitempty"`
			AuthPublicKey      string          `json:"AuthPublicKey,omitempty"`
			Tor                struct {
				Enabled    bool   `json:"Enabled,omitempty"`
				BinaryPath string `json:"BinaryPath,omitempty"`
			} `json:"Tor,omitempty"`

			// internal
			needAuth         bool
			ipfsNode         *core.IpfsNode
			ipfsAPI          ipfsutil.ExtendedCoreAPI
			pubsub           *pubsub.PubSub
			discovery        tinder.Driver
			server           bertyprotocol.Service
			client           bertyprotocol.ProtocolServiceClient
			requiredByClient bool
			ipfsWebUICleanup func()
			orbitDB          *bertyprotocol.BertyOrbitDB
		}
		Messenger struct {
			DisplayName          string `json:"DisplayName,omitempty"`
			DisableNotifications bool   `json:"DisableNotifications,omitempty"`
			RebuildSqlite        bool   `json:"RebuildSqlite,omitempty"`
			MessengerSqliteOpts  string `json:"MessengerSqliteOpts,omitempty"`

			// internal
			protocolClient      bertyprotocol.Client
			server              bertymessenger.Service
			lcmanager           *lifecycle.Manager
			notificationManager notification.Manager
			client              bertymessenger.MessengerServiceClient
			db                  *gorm.DB
			dbCleanup           func()
			requiredByClient    bool
		}
		GRPC struct {
			RemoteAddr string `json:"RemoteAddr,omitempty"`
			Listeners  string `json:"Listeners,omitempty"`

			// internal
			clientConn        *grpc.ClientConn
			server            *grpc.Server
			bufServer         *grpc.Server
			bufServerListener *grpcutil.BufListener
			gatewayMux        *runtime.ServeMux
			listeners         []grpcutil.Listener
		} `json:"GRPC,omitempty"`
	} `json:"Node,omitempty"`

	// internal
	ctx        context.Context
	ctxCancel  func()
	initLogger *zap.Logger
	workers    run.Group // replace by something more accurate
	mutex      sync.Mutex
}

func New(ctx context.Context) (*Manager, error) {
	m := Manager{}
	m.ctx, m.ctxCancel = context.WithCancel(ctx)

	// storage path
	{
		storagePath := configdir.New("berty-tech", "berty")
		storageDirs := storagePath.QueryFolders(configdir.Global)
		if len(storageDirs) == 0 {
			return nil, fmt.Errorf("no storage path found")
		}
		if err := storageDirs[0].CreateParentDir(""); err != nil {
			return nil, errcode.TODO.Wrap(err)
		}
		m.Datastore.defaultDir = storageDirs[0].Path
	}

	return &m, nil
}

func (m *Manager) applyDefaults() {
	if m.initLogger == nil {
		if m.Logging.zapLogger != nil {
			m.initLogger = m.Logging.zapLogger.Named("init")
		} else {
			m.initLogger = zap.NewNop()
		}
	}
}

func (m *Manager) GetContext() context.Context {
	if m.ctx == nil {
		m.ctx, m.ctxCancel = context.WithCancel(context.Background())
	}
	return m.ctx
}

func (m *Manager) RunWorkers() error {
	m.workers.Add(func() error {
		<-m.GetContext().Done()
		return m.GetContext().Err()
	}, func(error) {
		m.ctxCancel()
	})
	return m.workers.Run()
}

func (m *Manager) Close() error {
	m.mutex.Lock()
	defer m.mutex.Unlock()

	if m.ctxCancel != nil {
		m.ctxCancel()
	}

	if m.Node.GRPC.clientConn != nil {
		m.Node.GRPC.clientConn.Close()
	}

	if m.Node.GRPC.bufServer != nil {
		m.Node.GRPC.bufServer.Stop()
	}

	if m.Node.GRPC.bufServerListener != nil {
		m.Node.GRPC.bufServerListener.Close()
	}

	if m.Node.GRPC.server != nil {
		m.Node.GRPC.server.Stop()
	}

	if m.Node.Messenger.server != nil {
		m.Node.Messenger.server.Close()
	}
	if m.Node.Messenger.protocolClient != nil {
		m.Node.Messenger.protocolClient.Close()
	}
	if m.Node.Messenger.dbCleanup != nil {
		m.Node.Messenger.dbCleanup()
	}
	if m.Node.Protocol.server != nil {
		m.Node.Protocol.server.Close()
	}
	if m.Node.Protocol.ipfsWebUICleanup != nil {
		m.Node.Protocol.ipfsWebUICleanup()
	}
	if m.Node.Protocol.ipfsNode != nil {
		m.Node.Protocol.ipfsNode.Close()
	}
	if m.Datastore.rootDS != nil {
		m.Datastore.rootDS.Close()
	}
	if m.Logging.cleanup != nil {
		m.Logging.cleanup()
	}

	return nil
}

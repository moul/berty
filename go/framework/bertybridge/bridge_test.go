package bertybridge

/*
import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/textproto"
	"os"
	"testing"
	"time"

	"github.com/gogo/protobuf/proto"
	p2p_peer "github.com/libp2p/go-libp2p-core/peer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	"google.golang.org/grpc"

	"berty.tech/berty/v2/go/internal/ipfsutil"
	"berty.tech/berty/v2/go/internal/testutil"
	"berty.tech/berty/v2/go/pkg/bertyprotocol"
	"berty.tech/berty/v2/go/pkg/bertytypes"
)


func TestProtocolBridge(t *testing.T) {
	var (
		err          error
		bridge       *Bridge
		bridgeClient *client
		grpcClient   *grpc.ClientConn
		req, res     []byte
	)

	if os.Getenv("WITH_GOLEAK") == "1" {
		defer goleak.VerifyNone(t,
			goleak.IgnoreTopFunction("github.com/syndtr/goleveldb/leveldb.(*DB).mpoolDrain"),           // inherited from one of the imports (init)
			goleak.IgnoreTopFunction("github.com/ipfs/go-log/writer.(*MirrorWriter).logRoutine"),       // inherited from one of the imports (init)
			goleak.IgnoreTopFunction("github.com/libp2p/go-libp2p-connmgr.(*BasicConnMgr).background"), // inherited from github.com/ipfs/go-ipfs/core.NewNode
			goleak.IgnoreTopFunction("github.com/jbenet/goprocess/periodic.callOnTicker.func1"),        // inherited from github.com/ipfs/go-ipfs/core.NewNode
			goleak.IgnoreTopFunction("github.com/libp2p/go-libp2p-connmgr.(*decayer).process"),         // inherited from github.com/ipfs/go-ipfs/core.NewNode)
			goleak.IgnoreTopFunction("go.opencensus.io/stats/view.(*worker).start"),                    // inherited from github.com/ipfs/go-ipfs/core.NewNode)
			goleak.IgnoreTopFunction("github.com/desertbit/timer.timerRoutine"),                        // inherited from github.com/ipfs/go-ipfs/core.NewNode)
		)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mc, cleanup := ipfsutil.TestingCoreAPI(ctx, t)
	defer cleanup()

	logger, cleanup := testutil.Logger(t)
	defer cleanup()
	config := NewConfig()
	config.AddGRPCListener("/ip4/127.0.0.1/tcp/0/grpc")
	config.AddGRPCListener("/ip4/127.0.0.1/tcp/0/grpcweb")

	messengerBridge, err = newProtocolBridge(ctx, logger, config)
	require.NoError(t, err)

	defer func() {
		err = messengerBridge.Close()
		assert.NoErrorf(t, err, "messengerBridge.Close")
	}()

	logger.Info(
		"listeners",
		zap.String("gRPC", messengerBridge.GRPCListenerAddr()),
		zap.String("gRPC web", messengerBridge.GRPCWebListenerAddr()),
	)

	// clients

	bridgeClient, cleanup, err = messengerBridge.NewGRPCClient()
	require.NoError(t, err)
	assert.NotNil(t, bridgeClient)
	defer cleanup()

	grpcClient, err = grpc.Dial(messengerBridge.GRPCListenerAddr(), grpc.WithBlock(), grpc.WithInsecure())

	require.NoError(t, err)

	defer func() { _ = grpcClient.Close() }()

	// setup unary test
	msg := &bertytypes.InstanceGetConfiguration_Request{}

	req, err = proto.Marshal(msg)
	require.NoError(t, err)a

	// bridgeClient test
	res, err = bridgeClient.UnaryRequest(ctx, "/berty.protocol.v1.ProtocolService/InstanceGetConfiguration", req)
	require.NoError(t, err)

	out := &bertytypes.InstanceGetConfiguration_Reply{}
	err = proto.Unmarshal(res, out)
	require.NoError(t, err)

	// webclient test
	cc := bertyprotocol.NewProtocolServiceClient(grpcClient)
	_, err = cc.InstanceGetConfiguration(ctx, msg)
	require.NoError(t, err)

	//results, err = makeGrpcRequest(
	//	protocol.GRPCWebListenerAddr(),
	//	"/berty.protocol.v1.ProtocolService/ContactGet",
	//	[][]byte{req},
	//	false,
	//)
	//require.NoError(t, err)
	//
	//for _, res = range results {
	//	out := &bertyprotocol.InstanceGetConfiguration{}
	//	err = proto.Unmarshal(res, out)
	//	require.NoError(t, err)
	//}
}

func TestPersistenceProtocol(t *testing.T) {
	var err error

	const n_try = 4

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger, cleanup := testutil.Logger(t)
	defer cleanup()
	rootdir, err := ioutil.TempDir("", "ipfs")
	require.NoError(t, err)

	defer os.RemoveAll(rootdir)

	// coreAPI, cleanup := ipfsutil.TestingCoreAPI(ctx, t)
	// defer cleanup()

	config := NewConfig()
	config.RootDirectory(rootdir)

	var node_id_1 p2p_peer.ID
	var device_pk_1 []byte
	{
		protocol, err := newProtocolBridge(ctx, logger, config)
		require.NoError(t, err)

		// get grpc client
		client, cleanup, err := newServiceClient(protocol)
		if !assert.NoError(t, err) {
			protocol.Close()
			assert.FailNow(t, "unable to create client")
		}

		defer cleanup()

		// get node id
		node_id_1 = protocol.node.Identity
		assert.NotEmpty(t, node_id_1)

		res, err := client.InstanceGetConfiguration(ctx, &bertytypes.InstanceGetConfiguration_Request{})
		assert.NoError(t, err)

		device_pk_1 = res.DevicePK
		assert.NotEmpty(t, device_pk_1)

		err = protocol.Close()
		require.NoError(t, err)
	}

	var node_id_2 p2p_peer.ID
	var device_pk_2 []byte
	{

		protocol, err := newProtocolBridge(ctx, logger, config)
		require.NoError(t, err)

		// get grpc client
		client, cleanup, err := newServiceClient(protocol)
		if !assert.NoError(t, err) {
			protocol.Close()
			assert.FailNow(t, "unable to create client")
		}

		defer cleanup()

		// get node id
		node_id_2 = protocol.node.Identity
		assert.NotEmpty(t, node_id_2)

		res, err := client.InstanceGetConfiguration(ctx, &bertytypes.InstanceGetConfiguration_Request{})
		assert.NoError(t, err)

		device_pk_2 = res.DevicePK
		assert.NotEmpty(t, device_pk_2)

		err = protocol.Close()
		require.NoError(t, err)
	}

	assert.Equal(t, node_id_1, node_id_2, "IPFS node should have the same ID after reboot")
	assert.Equal(t, device_pk_1, device_pk_2, "Device should have the same PK after reboot")
}

func TestBridgeLifecycle(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	logger, cleanup := testutil.Logger(t)
	defer cleanup()

	mc, cleanup := ipfsutil.TestingCoreAPI(ctx, t)
	defer cleanup()

	config := NewConfig()

	protocol, err := newProtocolBridge(ctx, logger, config)
	require.NoError(t, err)

	// test state active
	protocol.HandleState(AppStateActive)
	assert.Equal(t, AppStateActive, protocol.currentAppState)

	// test state inactive
	protocol.HandleState(AppStateInactive)
	assert.Equal(t, AppStateInactive, protocol.currentAppState)

	// test state background
	protocol.HandleState(AppStateBackground)
	assert.Equal(t, AppStateBackground, protocol.currentAppState)

	// test backgroud task
	bg := protocol.HandleTask()

	done := make(chan struct{})
	go func() {
		// we dont care if the task succeed here
		_ = bg.Execute()
		close(done)
	}()

	// wait that background has been trigger
	time.After(time.Second)

	// cancel the task
	bg.Cancel()

	var success bool
	select {
	case <-done:
		success = true
	case <-time.After(time.Second * 5):
		success = false
	}

	assert.True(t, success)

	err = protocol.Close()
	assert.NoError(t, err)
}

func makeRequest(ctx context.Context, host string, method string, headers http.Header, body io.Reader, isText bool) (*http.Response, error) {
	contentType := "application/grpc-web"
	if isText {
		// base64 encode the body
		encodedBody := &bytes.Buffer{}
		encoder := base64.NewEncoder(base64.StdEncoding, encodedBody)
		_, err := io.Copy(encoder, body)
		if err != nil {
			return nil, err
		}
		err = encoder.Close()
		if err != nil {
			return nil, err
		}
		body = encodedBody
		contentType = "application/grpc-web-text"
	}

	url := fmt.Sprintf("http://%s%s", host, method)
	req, err := http.NewRequest("POST", url, body)
	req = req.WithContext(ctx)
	req.Header = headers

	req.Header.Set("Content-Type", contentType)
	bridgeClient := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}
	resp, err := bridgeClient.Do(req)
	return resp, err
}

func decodeMultipleBase64Chunks(b []byte) ([]byte, error) {
	// grpc-web allows multiple base64 chunks: the implementation may send base64-encoded
	// "chunks" with potential padding whenever the runtime needs to flush a byte buffer.
	// https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-WEB.md
	output := make([]byte, base64.StdEncoding.DecodedLen(len(b)))
	outputEnd := 0

	for inputEnd := 0; inputEnd < len(b); {
		chunk := b[inputEnd:]
		paddingIndex := bytes.IndexByte(chunk, '=')
		if paddingIndex != -1 {
			// find the consecutive =
			for {
				paddingIndex++
				if paddingIndex >= len(chunk) || chunk[paddingIndex] != '=' {
					break
				}
			}
			chunk = chunk[:paddingIndex]
		}
		inputEnd += len(chunk)

		n, err := base64.StdEncoding.Decode(output[outputEnd:], chunk)
		if err != nil {
			return nil, err
		}
		outputEnd += n
	}
	return output[:outputEnd], nil
}

func makeGrpcRequest(ctx context.Context, host string, method string, requestMessages [][]byte, isText bool) (responseMessages [][]byte, err error) {
	writer := new(bytes.Buffer)
	for _, msgBytes := range requestMessages {
		grpcPreamble := []byte{0, 0, 0, 0, 0}
		binary.BigEndian.PutUint32(grpcPreamble[1:], uint32(len(msgBytes)))
		writer.Write(grpcPreamble)
		writer.Write(msgBytes)
	}
	resp, err := makeRequest(ctx, host, method, http.Header{}, writer, isText)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	contents, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if isText {
		contents, err = decodeMultipleBase64Chunks(contents)
		if err != nil {
			return nil, err
		}
	}

	reader := bytes.NewReader(contents)
	for {
		grpcPreamble := []byte{0, 0, 0, 0, 0}
		readCount, err := reader.Read(grpcPreamble)
		if err == io.EOF {
			break
		}
		if readCount != 5 || err != nil {
			return nil, fmt.Errorf("Unexpected end of body in preamble: %v", err)
		}
		payloadLength := binary.BigEndian.Uint32(grpcPreamble[1:])
		payloadBytes := make([]byte, payloadLength)

		readCount, err = reader.Read(payloadBytes)
		if uint32(readCount) != payloadLength || err != nil {
			if err == io.EOF {
				return responseMessages, nil
			}

			return nil, fmt.Errorf("Unexpected end of msg: %v", err)
		}
		if grpcPreamble[0]&(1<<7) == (1 << 7) { // MSB signifies the trailer parser
			bufferReader := bytes.NewBuffer(payloadBytes)
			tp := textproto.NewReader(bufio.NewReader(bufferReader))

			// First, read bytes as MIME headers.
			// However, it normalizes header names by textproto.CanonicalMIMEHeaderKey.
			// In the next step, replace header names by raw one.
			_, err := tp.ReadMIMEHeader()
			if err != nil {
				bufferReader = bytes.NewBuffer(payloadBytes)
				_ = textproto.NewReader(bufio.NewReader(bufferReader))
			}

		} else {
			responseMessages = append(responseMessages, payloadBytes)
		}
	}

	return responseMessages, nil
}

func newServiceClient(p *MessengerBridge) (bertyprotocol.ProtocolServiceClient, func(), error) {
	cl, cleanup, err := p.Bridge.NewGRPCClient()
	if err != nil {
		return nil, nil, err
	}

	return bertyprotocol.NewProtocolServiceClient(cl.grpcClient), cleanup, nil
}

*/

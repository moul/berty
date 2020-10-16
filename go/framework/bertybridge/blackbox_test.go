package bertybridge_test

import (
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/gogo/protobuf/proto"

	"berty.tech/berty/v2/go/framework/bertybridge"
	"berty.tech/berty/v2/go/pkg/bertytypes"
)

func Example() {
	tmpdir, err := ioutil.TempDir("", "example")
	checkErr(err)
	defer os.RemoveAll(tmpdir)

	// create and start the bridge
	var bridge *bertybridge.Bridge
	{
		config := bertybridge.NewConfig()
		{
			if false { // disabled in example, but not commented to be sure that compiler performs various checks
				config.SetLifeCycleDriver(nil)
				config.SetLoggerDriver(nil)
				config.SetNotificationDriver(nil)
			}
			config.SetCLIArgs([]string{
				"--log.filters", "info+:bty*,-*.grpc warn+:*.grpc error+:*",
				"--log.format", "console",
				"--node.display-name", "",
				"--node.listeners", "/ip4/127.0.0.1/tcp/0/grpcws",
				"--p2p.ipfs-listeners", "/ip4/0.0.0.0/tcp/0,/ip6/0.0.0.0/tcp/0",
				"--p2p.local-discovery=false",
				"--p2p.webui-listener", ":3000",
				"--store.dir", tmpdir,
			})
		}

		bridge, err = bertybridge.NewBridge(config)
		checkErr(err)
		defer bridge.Close()
		fmt.Println("[+] initialized.")
	}

	fmt.Println(bridge.GRPCWebListenerAddr())
	fmt.Println(bridge.GRPCWebSocketListenerAddr())

	// client call
	{
		input := &bertytypes.InstanceGetConfiguration_Request{}
		b64Input, err := encodeProtoMessage(input)
		checkErr(err)
		ret, err := bridge.InvokeBridgeMethod("/berty.protocol.v1.ProtocolService/InstanceGetConfiguration", b64Input)
		checkErr(err)
		log.Println("RET", ret)
		fmt.Println(ret)
	}

	// Output: initialized.
}

func checkErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
		panic(err)
	}
}

func encodeProtoMessage(input proto.Message) (string, error) {
	data, err := proto.Marshal(input)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(data), nil
}

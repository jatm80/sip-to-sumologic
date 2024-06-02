package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/marv2097/siprocket"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/naoina/toml"
	sumo "github.com/ushios/sumoll"
)

var (
	snapshotLEN int32 = 1490
	promiscuous       = true
	err         error
	timeout     time.Duration = 200 * time.Millisecond
	handle      *pcap.Handle
)

//Config ...
type Config struct {
	Device           string
	Filter           string
	Sumocollectorurl string
	EnvPrefix        string
	Environment      string
	EnvLocation      string
	Debug            bool
}

//Response ...
type Response struct {
	DestIP     string
	DestPort   string
	SrcIP      string
	SrcPort    string
	Proto      string
	Sipmethod  string
	Sipversion string
	Rstatus    string
	Rcode      int
	Msgtype    string
	Sipheaders map[string]string
}

func main() {

	var conf Config
	var resp Response
	f, err := os.Open("/opt/sipsumo/config.toml")
	if err != nil {
		panic(err)
	}
	err = toml.NewDecoder(f).Decode(&conf)
	if err != nil {
		fmt.Printf("Wrong configuration %s\n", fmt.Sprint(err))

		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}

		// Print device information
		fmt.Println("Devices found:")
		for _, device := range devices {
			fmt.Println("\nName: ", device.Name)
			fmt.Println("Description: ", device.Description)
			fmt.Println("Devices addresses: ", device.Description)
			for _, address := range device.Addresses {
				fmt.Println("- IP address: ", address.IP)
				fmt.Println("- Subnet mask: ", address.Netmask)
			}
		}

		os.Exit(1)
	}

	dev := conf.Device
	collectorURL := conf.Sumocollectorurl

	// Open device
	handle, err = pcap.OpenLive(dev, snapshotLEN, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	err = handle.SetBPFFilter(conf.Filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing UDP port 5060 packets.")

	sumoURL, err := url.Parse(collectorURL)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	// Use the handle as a packet source to process all packets
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		headers := make(map[string]string)
		layer3 := packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4)
		resp.DestIP = layer3.DstIP.String()
		resp.SrcIP = layer3.SrcIP.String()
		resp.Proto = layer3.Protocol.String()

		layer4 := packet.Layer(layers.LayerTypeUDP).(*layers.UDP)
		resp.SrcPort = layer4.SrcPort.String()
		resp.DestPort = layer4.DstPort.String()

		msg := packet.Layer(layers.LayerTypeSIP).(*layers.SIP)
		resp.Sipmethod = fmt.Sprint(msg.Method)
		resp.Sipversion = fmt.Sprint(msg.Version)

		for hname, hcontent := range msg.GetAllHeaders() {
			headers[hname] = strings.Join(hcontent, " ")
		}

		if msg.GetContentLength() > 0 {
			sip := siprocket.Parse(packet.Data())
			headers["SDPMediaType"] = string(sip.Sdp.MediaDesc.MediaType)
			headers["SDPPort"] = string(sip.Sdp.MediaDesc.Port)
			headers["SDPMediaDesc"] = string(sip.Sdp.MediaDesc.Src)
			headers["SDPProto"] = string(sip.Sdp.MediaDesc.Proto)
		}

		resp.Sipheaders = headers

		resp.Rstatus = msg.ResponseStatus
		resp.Rcode = msg.ResponseCode

		if msg.Method != 5 {
			if msg.IsResponse {
				resp.Msgtype = "Response"

			} else {
				resp.Msgtype = "Request"

			}

			mresp, err := json.Marshal(resp)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			logsumo := string(mresp)

			if conf.Debug {
				fmt.Print("\n----DEBUG ----\n" + string(packet.Data()))
				fmt.Printf("\n----DEBUG ---- %s %s\n", dev, collectorURL)
				fmt.Print("\n----DEBUG ----\n" + logsumo + "\n\n")
			}

			hostname, err := os.Hostname()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			sumocategory := conf.EnvPrefix + "/" + conf.Environment + "/" + conf.EnvLocation + "/" + hostname

			client := sumo.NewHTTPSourceClient(sumoURL)
			client.SetHeaders("UA", conf.EnvPrefix, hostname, sumocategory)
			client.Send(strings.NewReader(logsumo))

		}
	}
}

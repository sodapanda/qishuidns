package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
	"github.com/yl2chen/cidranger"
)

var ranger cidranger.Ranger
var gfwListTrie *Trie
var records []Record

// Record Record
type Record struct {
	Name   string `json:"name"`
	IP     string `json:"ip"`
	Server string `json:"server"`
}

func readConf() {
	b, err := ioutil.ReadFile("config.json")
	if err != nil {
		fmt.Println("读取json文件出错:", err)
		return
	}
	// 解析json数据
	err = json.Unmarshal(b, &records)
	if err != nil {
		fmt.Println("解析json数据出错:", err)
		return
	}

	// 输出结果
	for _, r := range records {
		fmt.Printf("name: %s, ip: %s, server: %s\n", r.Name, r.IP, r.Server)
	}
}

func isSubdomain(inputDomain string, givenDomain string) bool {
	if inputDomain == givenDomain {
		return true
	}
	givenDomainParts := strings.Split(givenDomain, ".")
	inputDomainParts := strings.Split(inputDomain, ".")
	if len(inputDomainParts) < len(givenDomainParts)+1 {
		return false
	}
	for i := range givenDomainParts {
		if givenDomainParts[len(givenDomainParts)-1-i] != inputDomainParts[len(inputDomainParts)-1-i] {
			return false
		}
	}
	return true
}

// TrieNode TrieNode
type TrieNode struct {
	children map[rune]*TrieNode
	isEnd    bool
}

// NewTrieNode NewTrieNode
func NewTrieNode() *TrieNode {
	return &TrieNode{children: make(map[rune]*TrieNode)}
}

// Trie Trie
type Trie struct {
	root *TrieNode
}

// NewTrie NewTrie
func NewTrie() *Trie {
	return &Trie{root: NewTrieNode()}
}

// Insert Insert
func (t *Trie) Insert(domain string) {
	node := t.root
	for _, ch := range domain {
		child, ok := node.children[ch]
		if !ok {
			child = NewTrieNode()
			node.children[ch] = child
		}
		node = child
	}
	node.isEnd = true
}

// IsSubdomain IsSubdomain
func (t *Trie) IsSubdomain(domain string) bool {
	node := t.root
	for _, ch := range domain {
		child, ok := node.children[ch]
		if !ok {
			return false
		}
		if child.isEnd {
			return true
		}
		node = child
	}
	return false
}

func loadGFWList() error {
	fileBytes, err := ioutil.ReadFile("gfwlist_out.txt")
	if err != nil {
		return err
	}

	gfwList := strings.Split(string(fileBytes), "\n")

	gfwListTrie = NewTrie()

	for _, domain := range gfwList {
		gfwListTrie.Insert(reverseDomain(domain))
	}

	return nil
}

func reverseDomain(domain string) string {
	labels := strings.Split(domain, ".")
	for i := 0; i < len(labels)/2; i++ {
		labels[i], labels[len(labels)-i-1] = labels[len(labels)-i-1], labels[i]
	}
	return strings.Join(labels, ".")
}

func loadNetRange() error {
	fileBytes, err := ioutil.ReadFile("cidrlist")
	if err != nil {
		return err
	}
	ipSlice := strings.Split(string(fileBytes), "\n")

	ranger = cidranger.NewPCTrieRanger()

	for _, item := range ipSlice {
		_, network, _ := net.ParseCIDR(item)
		ranger.Insert(cidranger.NewBasicRangerEntry(*network))
	}
	return nil
}

func checkCIDRRange(address net.IP) bool {
	contains, err := ranger.Contains(address)
	if err != nil {
		fmt.Println("checkCIDRRange", address, err)
		return false
	}
	return contains
}

func handleRequest(w dns.ResponseWriter, req *dns.Msg) {
	// 创建响应消息
	res := &dns.Msg{}
	res.SetReply(req)
	isConfigBind := false
	forwardServer := "52.235.135.129"

	// 判断是不是配置文件里的
	if req.Question[0].Qtype == dns.TypeA {
		queryName := strings.TrimRight(req.Question[0].Name, ".")
		for _, record := range records {
			// 写配置的时候cdn.openai.com必须在openai.com前边
			if isSubdomain(queryName, record.Name) {
				if record.IP != "" {
					isConfigBind = true

					rr, err := dns.NewRR(req.Question[0].Name + " IN A " + record.IP)
					if err != nil {
						panic(err)
					}
					res.Answer = append(res.Answer, rr)
					fmt.Printf("config: %s %s\n", queryName, record.IP)
				} else if record.Server != "" {
					forwardServer = record.Server
					fmt.Printf("Config server %s %s\n", queryName, forwardServer)
				}
				break
			}
		}
	}

	if !isConfigBind {
		// 判断是否含有A记录的请求
		foundSupportedType := false
		isA := false
		isGFW := false
		isNotChina := false
		for _, q := range req.Question {
			// 判断查询是否为支持的
			if q.Qtype == dns.TypeA || q.Qtype == dns.TypeMX || q.Qtype == dns.TypeCNAME || q.Qtype == dns.TypeHTTPS || q.Qtype == dns.TypePTR {
				foundSupportedType = true
				if q.Qtype == dns.TypeA {
					isA = true
				}
				isGFW = gfwListTrie.IsSubdomain(reverseDomain(strings.TrimRight(q.Name, ".")))
			}

		}

		if foundSupportedType {
			if isA {
				if isGFW {
					c := new(dns.Client)
					var err error
					res, _, err = c.Exchange(req, forwardServer+":53")
					if err != nil {
						log.Printf("Error forwarding request to %s: %v", forwardServer, err)
						res = createErrorReply(req)
					}
				} else {
					c := new(dns.Client)
					var err error
					res, _, err = c.Exchange(req, "223.5.5.5:53")
					if err != nil {
						log.Printf("Error forwarding request to 223.5.5.5: %v", err)
						res = createErrorReply(req)
					}

					for _, r := range res.Answer {
						if a, ok := r.(*dns.A); ok {
							// fmt.Printf("%s A记录 IP地址: %s\n", " ", a.A)
							if !checkCIDRRange(a.A) {
								isNotChina = true
							}
						}
					}

					if isNotChina {
						c := new(dns.Client)
						var err error
						res, _, err = c.Exchange(req, forwardServer+":53")
						if err != nil {
							log.Printf("Error forwarding request to %s: %v", forwardServer, err)
							res = createErrorReply(req)
						}
					}
				}
			} else {
				c := new(dns.Client)
				var err error
				res, _, err = c.Exchange(req, forwardServer+":53")
				if err != nil {
					log.Printf("Error forwarding request to %s: %v", forwardServer, err)
					res = createErrorReply(req)
				}
			}
		} else {
			res = createErrorReply(req)
		}

		for _, question := range req.Question {
			fmt.Printf("Support=%t,Type=%s,is GFW=%t,isNotChina=%t %s\n", foundSupportedType, dns.TypeToString[question.Qtype], isGFW, isNotChina, question.Name)
		}
	}

	// 将响应发送回客户端
	err := w.WriteMsg(res)
	if err != nil {
		log.Printf("Error sending response to client: %v", err)
	}
}

func createErrorReply(req *dns.Msg) *dns.Msg {
	res := &dns.Msg{}
	res.SetReply(req)
	res.Rcode = dns.RcodeServerFailure
	return res
}

func main() {
	readConf()
	loadGFWList()
	loadNetRange()

	// 创建一个DNS服务器实例
	server := &dns.Server{
		Addr: ":53", // 监听53端口
		Net:  "udp",
	}

	// 设置处理请求的回调函数
	server.Handler = dns.HandlerFunc(handleRequest)

	// 开始监听
	log.Printf("Starting DNS server on %s", server.Addr)
	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
}
